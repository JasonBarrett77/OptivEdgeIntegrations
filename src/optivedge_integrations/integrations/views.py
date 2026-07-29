"""UI views for the current integration management surfaces.

This module owns Django views and view-level composition for the management-station
workflow. Keep vendor session, collection, and persistence logic out of this layer.
"""

import json
import logging
import threading
from dataclasses import dataclass

from django.contrib import messages
from django.core.paginator import Paginator
from django.db import connections
from django.db.models import Count, OuterRef, Subquery
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, DeleteView, UpdateView

from optivedge.views import RightOverlayMixin
from optivedge_integrations.integrations.forms import ManagementStationForm
from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    EnforcementPoint,
    IntegrationEvent,
    IntegrationRun,
    ManagementStation,
    SecurityRule,
    Snapshot,
)
from optivedge_integrations.integrations.presentation import (
    build_address_group_row,
    build_address_object_row,
)
from optivedge_integrations.integrations.platforms.pan_os import (
    PANOSDynamicContentRefreshResult,
    PANOSInScopeRefreshCollection,
    PANOSInScopeRenormalizationResult,
    collect_persist_and_normalize,
    refresh_in_scope_configuration_snapshots,
    refresh_in_scope_dynamic_content,
    renormalize_in_scope_configuration,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors import collect_show_managed_devices
from optivedge_integrations.integrations.search_vocabulary import rebuild_all_security_rule_search_vocabulary


logger = logging.getLogger(__name__)

TAB_DETAILS = "details"
TAB_APPLIANCE_GROUPS = "appliance-groups"
TAB_ENFORCEMENT_POINTS = "enforcement-points"
TAB_EVENTS = "events"
_VALID_TABS = {TAB_DETAILS, TAB_APPLIANCE_GROUPS, TAB_ENFORCEMENT_POINTS, TAB_EVENTS}


def get_management_station_list_queryset():
    latest_run_qs = IntegrationRun.objects.filter(management_station=OuterRef("pk")).order_by("-started_at")
    return ManagementStation.objects.annotate(
        appliance_group_count=Count("appliance_groups", distinct=True),
        appliance_count=Count("appliances", distinct=True),
        enforcement_point_count=Count("enforcement_points", distinct=True),
        latest_run_status=Subquery(latest_run_qs.values("status")[:1]),
        latest_run_completed_at=Subquery(latest_run_qs.values("completed_at")[:1]),
    ).order_by("hostname")


def build_management_station_detail_context(management_station, *, active_tab=TAB_DETAILS):
    if active_tab not in _VALID_TABS:
        active_tab = TAB_DETAILS

    context = {"active_tab": active_tab}

    if active_tab == TAB_APPLIANCE_GROUPS:
        context["appliance_groups"] = management_station.appliance_groups.select_related(
            "active_appliance"
        ).prefetch_related("appliances")

    elif active_tab == TAB_ENFORCEMENT_POINTS:
        enforcement_points = list(
            management_station.enforcement_points.select_related(
                "appliance_group",
                "appliance",
            ).prefetch_related("nodes__appliance")
        )
        enforcement_points.sort(
            key=lambda ep: (
                enforcement_point_appliance_sort_key(ep),
                ep.vsys_name,
                ep.pk,
            )
        )
        context["enforcement_points"] = enforcement_points

    elif active_tab == TAB_EVENTS:
        context["integration_events"] = (
            management_station.integration_events
            .select_related("run", "appliance", "appliance_group", "enforcement_point")
            .order_by("-occurred_at")[:1000]
        )

    return context


def enforcement_point_appliance_sort_key(enforcement_point):
    node_names = sorted(
        str(node.appliance)
        for node in enforcement_point.nodes.all()
        if node.appliance is not None
    )
    if node_names:
        return ", ".join(node_names).lower()
    if enforcement_point.appliance is not None:
        return str(enforcement_point.appliance).lower()
    return ""


def build_pretty_json(value):
    return json.dumps(value, indent=2, sort_keys=True)


def build_appliance_group_snapshot_context(appliance_group):
    latest_snapshots = []
    latest_merged_config = (
        Snapshot.objects.filter(
            appliance__appliance_group=appliance_group,
            source_type="show_merged_config",
        )
        .select_related("appliance")
        .order_by("-collected_at", "-pk")
        .first()
    )
    latest_shared_policy = (
        Snapshot.objects.filter(
            appliance_group=appliance_group,
            source_type="show_pushed_shared_policy",
        )
        .order_by("-collected_at", "-pk")
        .first()
    )
    latest_predefined_ip_block_lists = (
        Snapshot.objects.filter(
            appliance__appliance_group=appliance_group,
            source_type="show_predefined_ip_block_lists",
        )
        .select_related("appliance")
        .order_by("-collected_at", "-pk")
        .first()
    )
    latest_predefined_url_lists = (
        Snapshot.objects.filter(
            appliance__appliance_group=appliance_group,
            source_type="show_predefined_url_lists",
        )
        .select_related("appliance")
        .order_by("-collected_at", "-pk")
        .first()
    )

    for source_type, label, snapshot in [
        ("show_merged_config", "Merged Config", latest_merged_config),
        ("show_pushed_shared_policy", "Pushed Shared Policy", latest_shared_policy),
        ("show_predefined_ip_block_lists", "Predefined IP Block Lists", latest_predefined_ip_block_lists),
        ("show_predefined_url_lists", "Predefined URL Lists", latest_predefined_url_lists),
    ]:
        latest_snapshots.append(
            {
                "source_type": source_type,
                "label": label,
                "snapshot": snapshot,
                "pretty_payload": build_pretty_json(snapshot.payload) if snapshot is not None else "",
                "pretty_metadata": build_pretty_json(snapshot.metadata) if snapshot is not None else "",
            }
        )

    enforcement_points = appliance_group.enforcement_points.order_by("vsys_name", "pk")
    for enforcement_point in enforcement_points:
        latest_vsys_policy = (
            Snapshot.objects.filter(
                enforcement_point=enforcement_point,
                source_type="show_pushed_shared_policy_vsys",
            )
            .select_related("enforcement_point")
            .order_by("-collected_at", "-pk")
            .first()
        )
        label = f"VSYS Pushed Shared Policy / {enforcement_point.vsys_name}"
        if enforcement_point.vsys_display_name:
            label = f"{label} / {enforcement_point.vsys_display_name}"
        latest_snapshots.append(
            {
                "source_type": "show_pushed_shared_policy_vsys",
                "label": label,
                "snapshot": latest_vsys_policy,
                "pretty_payload": build_pretty_json(latest_vsys_policy.payload) if latest_vsys_policy is not None else "",
                "pretty_metadata": build_pretty_json(latest_vsys_policy.metadata) if latest_vsys_policy is not None else "",
            }
        )

    return {
        "latest_snapshots": latest_snapshots,
    }


_ADDRESS_PAGE_SIZE = 20
_ADDRESS_KIND_OBJECT = "object"
_ADDRESS_KIND_GROUP = "group"


def build_enforcement_point_address_context(enforcement_point, *, kind=_ADDRESS_KIND_OBJECT, q="", page=1):
    if kind not in (_ADDRESS_KIND_OBJECT, _ADDRESS_KIND_GROUP):
        kind = _ADDRESS_KIND_OBJECT

    if kind == _ADDRESS_KIND_GROUP:
        qs = (
            enforcement_point.address_groups
            .select_related("source_snapshot")
            .prefetch_related("tags", "members", "field_provenance")
            .order_by("name", "pk")
        )
        if q:
            qs = qs.filter(name__icontains=q)
        page_obj = Paginator(qs, _ADDRESS_PAGE_SIZE).get_page(page)
        rows = [build_address_group_row(ag) for ag in page_obj]
    else:
        qs = (
            enforcement_point.address_objects
            .select_related("source_snapshot")
            .prefetch_related("tags", "field_provenance", "resolved_entries")
            .order_by("name", "pk")
        )
        if q:
            qs = qs.filter(name__icontains=q)
        page_obj = Paginator(qs, _ADDRESS_PAGE_SIZE).get_page(page)
        rows = [build_address_object_row(ao) for ao in page_obj]

    return {
        "address_rows": rows,
        "page_obj": page_obj,
        "kind": kind,
        "q": q,
    }


class ManagementStationListView(ListView):
    model = ManagementStation
    context_object_name = "management_stations"
    template_name = "integrations/management_station_list.html"

    def get_queryset(self):
        return get_management_station_list_queryset()


class ManagementStationDetailView(DetailView):
    model = ManagementStation
    context_object_name = "management_station"
    pk_url_kwarg = "pk"
    template_name = "integrations/management_station_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        active_tab = self.request.GET.get("tab", TAB_DETAILS)
        context.update(build_management_station_detail_context(self.object, active_tab=active_tab))
        return context


class ManagementStationListBackgroundMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["management_stations"] = get_management_station_list_queryset()
        return context


class ManagementStationDetailBackgroundMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        management_station = context["management_station"]
        context.update(build_management_station_detail_context(management_station, active_tab=TAB_DETAILS))
        return context


class ApplianceGroupSnapshotView(RightOverlayMixin, ManagementStationDetailBackgroundMixin, TemplateView):
    template_name = "integrations/appliance_group_snapshots.html"
    overlay_panel_class = "w-[56rem] max-w-[calc(100vw-8rem)]"

    def get_context_data(self, **kwargs):
        management_station = get_object_or_404(ManagementStation, pk=self.kwargs["pk"])
        appliance_group = get_object_or_404(
            ApplianceGroup.objects.select_related("active_appliance").prefetch_related("appliances"),
            pk=self.kwargs["appliance_group_pk"],
            management_station=management_station,
        )
        context = super().get_context_data(
            management_station=management_station,
            appliance_group=appliance_group,
            **kwargs,
        )
        context.update(build_appliance_group_snapshot_context(appliance_group))
        return context

    def get_overlay_close_url(self):
        return reverse("management_station_detail", kwargs={"pk": self.kwargs["pk"]})


class EnforcementPointAddressListView(TemplateView):
    template_name = "integrations/enforcement_point_addresses.html"

    def get_context_data(self, **kwargs):
        management_station = get_object_or_404(ManagementStation, pk=self.kwargs["pk"])
        enforcement_point = get_object_or_404(
            EnforcementPoint.objects.select_related("appliance_group", "appliance").prefetch_related("nodes__appliance"),
            pk=self.kwargs["enforcement_point_pk"],
            management_station=management_station,
        )
        context = super().get_context_data(**kwargs)
        context["management_station"] = management_station
        context["enforcement_point"] = enforcement_point
        context.update(build_enforcement_point_address_context(
            enforcement_point,
            kind=self.request.GET.get("kind", _ADDRESS_KIND_OBJECT),
            q=self.request.GET.get("q", ""),
            page=self.request.GET.get("page", 1),
        ))
        return context


class ManagementStationCreateView(RightOverlayMixin, ManagementStationListBackgroundMixin, CreateView):
    form_class = ManagementStationForm
    model = ManagementStation
    template_name = "integrations/management_station_form.html"

    def get_overlay_close_url(self):
        return reverse("management_station_list")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form_mode"] = "create"
        return context

    def get_success_url(self):
        return reverse("management_station_detail", kwargs={"pk": self.object.pk})


class ManagementStationUpdateView(RightOverlayMixin, ManagementStationDetailBackgroundMixin, UpdateView):
    form_class = ManagementStationForm
    model = ManagementStation
    context_object_name = "management_station"
    pk_url_kwarg = "pk"
    template_name = "integrations/management_station_form.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form_mode"] = "update"
        return context

    def get_success_url(self):
        return reverse("management_station_detail", kwargs={"pk": self.object.pk})

    def get_overlay_close_url(self):
        return reverse("management_station_detail", kwargs={"pk": self.object.pk})


class ManagementStationDeleteView(RightOverlayMixin, ManagementStationDetailBackgroundMixin, DeleteView):
    model = ManagementStation
    context_object_name = "management_station"
    pk_url_kwarg = "pk"
    template_name = "integrations/management_station_confirm_delete.html"
    success_url = reverse_lazy("management_station_list")

    def get_overlay_close_url(self):
        return reverse("management_station_detail", kwargs={"pk": self.object.pk})


class ManagementStationSyncView(View):
    def post(self, request, pk):
        management_station = get_object_or_404(ManagementStation, pk=pk)
        detail_url = reverse("management_station_detail", kwargs={"pk": management_station.pk})

        if management_station.station_type != ManagementStation.StationType.PAN_PANORAMA:
            messages.error(request, "Sync is currently only supported for Panorama management stations.")
            return HttpResponseRedirect(detail_url)

        run = IntegrationRun.objects.create(
            management_station=management_station,
            run_scope=IntegrationRun.SCOPE_STATION,
            status=IntegrationRun.STATUS_FAILED,
        )
        IntegrationEvent.objects.create(
            management_station=management_station,
            run=run,
            level=IntegrationEvent.LEVEL_INFO,
            stage="",
            reason="InventorySyncStarted",
            message="Managed devices inventory sync started.",
        )
        try:
            collect_persist_and_normalize(
                management_station,
                collector=collect_show_managed_devices,
            )
        except Exception as exc:
            IntegrationEvent.objects.create(
                management_station=management_station,
                run=run,
                level=IntegrationEvent.LEVEL_ERROR,
                stage="",
                reason="InventoryCollectionFailed",
                message=str(exc),
            )
            run.completed_at = timezone.now()
            run.save(update_fields=["completed_at"])
            messages.error(request, f"Sync failed: {exc}")
            return HttpResponseRedirect(detail_url)

        run.status = IntegrationRun.STATUS_SUCCEEDED
        run.completed_at = timezone.now()
        run.save(update_fields=["status", "completed_at"])
        IntegrationEvent.objects.create(
            management_station=management_station,
            run=run,
            level=IntegrationEvent.LEVEL_INFO,
            stage="",
            reason="InventorySyncCompleted",
            message="Managed devices collected, persisted, and normalized.",
        )
        messages.success(request, "Managed devices collected, persisted, and normalized.")
        return HttpResponseRedirect(detail_url)


@dataclass(slots=True)
class InScopeRefreshTrackingResult:
    run: IntegrationRun
    succeeded: bool
    refresh: PANOSInScopeRefreshCollection | None
    error: Exception | None
    failure_count: int


def _refresh_station_in_scope_with_tracking(management_station: ManagementStation) -> InScopeRefreshTrackingResult:
    """Run the in-scope configuration refresh for one station, recording an IntegrationRun
    and any per-item IntegrationEvents. Shared by the single-station and bulk in-scope
    refresh views so both stay consistent in what they track."""
    run = IntegrationRun.objects.create(
        management_station=management_station,
        run_scope=IntegrationRun.SCOPE_APPLIANCE,
        status=IntegrationRun.STATUS_RUNNING,
    )
    IntegrationEvent.objects.create(
        management_station=management_station,
        run=run,
        level=IntegrationEvent.LEVEL_INFO,
        stage="",
        reason="InScopeRefreshStarted",
        message="In-scope configuration refresh started.",
    )
    try:
        refresh = refresh_in_scope_configuration_snapshots(management_station)
    except Exception as exc:
        IntegrationEvent.objects.create(
            management_station=management_station,
            run=run,
            level=IntegrationEvent.LEVEL_ERROR,
            stage="",
            reason="ApplianceSyncFailed",
            message=str(exc),
        )
        run.status = IntegrationRun.STATUS_FAILED
        run.completed_at = timezone.now()
        run.save(update_fields=["status", "completed_at"])
        return InScopeRefreshTrackingResult(
            run=run, succeeded=False, refresh=None, error=exc, failure_count=1,
        )

    batch = refresh.configuration_snapshots
    events = []
    for f in batch.merged_config_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_COLLECT,
            reason="MergedConfigCollectionFailed", message=f.error_text,
            appliance=f.appliance,
        ))
    for item in batch.merged_config_collections:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_COLLECT,
            reason="MergedConfigCollected", message="Collected merged config snapshot.",
            appliance=item.appliance,
        ))
    for f in batch.predefined_lists_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_COLLECT,
            reason="PredefinedListsCollectionFailed", message=f.error_text,
            appliance=f.appliance,
        ))
    for item in batch.predefined_lists_collections:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_COLLECT,
            reason="PredefinedListsCollected",
            message="Collected predefined address/URL list catalog snapshot.",
            appliance=item.appliance,
        ))
    for f in batch.shared_policy_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_COLLECT,
            reason="SharedPolicyCollectionFailed", message=f.error_text,
            appliance_group=f.appliance_group,
        ))
    for item in batch.shared_policy_collections:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_COLLECT,
            reason="SharedPolicyCollected", message="Collected pushed shared policy snapshot.",
            appliance_group=item.appliance_group,
        ))
    for f in batch.vsys_policy_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_COLLECT,
            reason="VsysPolicyCollectionFailed", message=f.error_text,
            enforcement_point=f.enforcement_point,
        ))
    for item in batch.vsys_policy_collections:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_COLLECT,
            reason="VsysPolicyCollected", message="Collected pushed VSYS policy snapshot.",
            enforcement_point=item.enforcement_point,
        ))
    for f in batch.device_configuration_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="DeviceConfigurationNormalizationFailed", message=f.error_text,
            appliance=f.appliance,
        ))
    for item in batch.device_configuration_normalizations:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="DeviceConfigurationNormalized",
            message=f"Normalized {len(item.device_configuration_profiles)} device configuration profile(s).",
            appliance=item.appliance,
        ))
    for f in batch.address_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="AddressNormalizationFailed", message=f.error_text,
            enforcement_point=f.enforcement_point,
        ))
    for item in batch.address_normalizations:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="AddressNormalized",
            message=(
                f"Normalized {len(item.address_objects)} address object(s) and "
                f"{len(item.address_groups)} address group(s)."
            ),
            enforcement_point=item.enforcement_point,
        ))
    for f in batch.security_rule_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="SecurityRuleNormalizationFailed", message=f.error_text,
            enforcement_point=f.enforcement_point,
        ))
    for item in batch.security_rule_normalizations:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="SecurityRuleNormalized",
            message=f"Normalized {len(item.security_rules)} security rule(s).",
            enforcement_point=item.enforcement_point,
        ))
    for f in batch.security_rule_item_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="SecurityRuleItemNormalizationFailed",
            message=(
                f"rule={f.name!r} config_source={f.config_source!r} "
                f"position={f.rule_position}: {f.error_text}"
            ),
            enforcement_point=f.enforcement_point,
        ))
    failure_count = sum(1 for e in events if e.level == IntegrationEvent.LEVEL_ERROR)
    events.append(IntegrationEvent(
        management_station=management_station, run=run,
        level=IntegrationEvent.LEVEL_INFO, stage="",
        reason="InScopeRefreshCompleted",
        message=f"In-scope configuration refresh completed with {failure_count} failure(s).",
    ))
    IntegrationEvent.objects.bulk_create(events)
    run.status = IntegrationRun.STATUS_PARTIAL if failure_count else IntegrationRun.STATUS_SUCCEEDED
    run.completed_at = timezone.now()
    run.save(update_fields=["status", "completed_at"])

    return InScopeRefreshTrackingResult(
        run=run, succeeded=True, refresh=refresh, error=None, failure_count=failure_count,
    )


class ManagementStationInScopeSyncView(View):
    def post(self, request, pk):
        management_station = get_object_or_404(ManagementStation, pk=pk)
        detail_url = reverse("management_station_detail", kwargs={"pk": management_station.pk})

        if management_station.station_type != ManagementStation.StationType.PAN_PANORAMA:
            messages.error(
                request,
                "In-scope configuration refresh is currently only supported for Panorama management stations.",
            )
            return HttpResponseRedirect(detail_url)

        outcome = _refresh_station_in_scope_with_tracking(management_station)

        if not outcome.succeeded:
            messages.error(request, f"In-scope configuration refresh failed: {outcome.error}")
            return HttpResponseRedirect(detail_url)

        batch = outcome.refresh.configuration_snapshots
        messages.success(
            request,
            "In-scope configuration refresh completed for "
            f"{len(batch.merged_config_collections)} appliance config snapshot(s), "
            f"{len(batch.shared_policy_collections)} shared policy snapshot(s), and "
            f"{len(batch.vsys_policy_collections)} VSYS policy snapshot(s). "
            f"Normalized {sum(len(item.address_objects) for item in batch.address_normalizations)} address object(s) "
            f"and {sum(len(item.address_groups) for item in batch.address_normalizations)} address group(s). "
            f"Normalized {sum(len(item.security_rules) for item in batch.security_rule_normalizations)} security rule(s).",
        )
        if outcome.failure_count:
            messages.error(
                request,
                f"{outcome.failure_count} in-scope collection task(s) failed. Review the Events tab for details.",
            )
        return HttpResponseRedirect(detail_url)


def _run_bulk_in_scope_refresh_in_background() -> None:
    """Entry point for the background thread spawned by ManagementStationBulkInScopeSyncView.

    Runs outside the request/response cycle, so exceptions here would otherwise vanish
    silently — log them instead. Each new thread gets its own thread-local DB connection
    via the ORM; explicitly closing it when done avoids leaking an idle connection for the
    lifetime of the process.

    Refreshes each Panorama station independently (rather than delegating to a single
    all-or-nothing helper) so one station's failure doesn't abort the rest, and so each
    station gets its own IntegrationRun visible on the management-stations list page.
    """
    stations = ManagementStation.objects.filter(
        station_type=ManagementStation.StationType.PAN_PANORAMA,
    ).order_by("hostname", "pk")

    try:
        for management_station in stations:
            try:
                _refresh_station_in_scope_with_tracking(management_station)
            except Exception:
                # _refresh_station_in_scope_with_tracking already records routine sync
                # failures as a failed IntegrationRun/Event; this only catches something
                # unexpected in that bookkeeping itself, so one station's bug can't abort
                # the rest of the bulk run.
                logger.exception(
                    "Unexpected error refreshing management station %s during bulk in-scope refresh",
                    management_station.pk,
                )

        rebuild_all_security_rule_search_vocabulary()
    except Exception:
        logger.exception("Background bulk in-scope configuration refresh failed")
    finally:
        connections.close_all()


class ManagementStationBulkInScopeSyncView(View):
    def post(self, request):
        list_url = reverse("management_station_list")

        threading.Thread(
            target=_run_bulk_in_scope_refresh_in_background,
            name="bulk-in-scope-refresh",
            daemon=True,
        ).start()

        messages.success(
            request,
            "Bulk in-scope configuration refresh started in the background for all Panorama "
            "stations. Watch this page's Last Refresh column, or each station's Events tab, "
            "for results.",
        )
        return HttpResponseRedirect(list_url)


@dataclass(slots=True)
class RenormalizationTrackingResult:
    run: IntegrationRun
    renormalized: PANOSInScopeRenormalizationResult
    failure_count: int


def _renormalize_station_with_tracking(management_station: ManagementStation) -> RenormalizationTrackingResult:
    """Re-run normalization for a station's in-scope appliances/enforcement points against
    already-collected snapshots (no device connection), recording an IntegrationRun and any
    per-item IntegrationEvents the same way the in-scope refresh views do."""
    run = IntegrationRun.objects.create(
        management_station=management_station,
        run_scope=IntegrationRun.SCOPE_APPLIANCE,
        status=IntegrationRun.STATUS_RUNNING,
    )
    IntegrationEvent.objects.create(
        management_station=management_station,
        run=run,
        level=IntegrationEvent.LEVEL_INFO,
        stage="",
        reason="RenormalizationStarted",
        message="Renormalization started (using already-collected data).",
    )
    renormalized = renormalize_in_scope_configuration(management_station)

    events = []
    for f in renormalized.device_configuration_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="DeviceConfigurationNormalizationFailed", message=f.error_text,
            appliance=f.appliance,
        ))
    for item in renormalized.device_configuration_normalizations:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="DeviceConfigurationNormalized",
            message=f"Normalized {len(item.device_configuration_profiles)} device configuration profile(s).",
            appliance=item.appliance,
        ))
    for f in renormalized.address_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="AddressNormalizationFailed", message=f.error_text,
            enforcement_point=f.enforcement_point,
        ))
    for item in renormalized.address_normalizations:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="AddressNormalized",
            message=(
                f"Normalized {len(item.address_objects)} address object(s) and "
                f"{len(item.address_groups)} address group(s)."
            ),
            enforcement_point=item.enforcement_point,
        ))
    for f in renormalized.security_rule_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="SecurityRuleNormalizationFailed", message=f.error_text,
            enforcement_point=f.enforcement_point,
        ))
    for item in renormalized.security_rule_normalizations:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="SecurityRuleNormalized",
            message=f"Normalized {len(item.security_rules)} security rule(s).",
            enforcement_point=item.enforcement_point,
        ))
    for f in renormalized.security_rule_item_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="SecurityRuleItemNormalizationFailed",
            message=(
                f"rule={f.name!r} config_source={f.config_source!r} "
                f"position={f.rule_position}: {f.error_text}"
            ),
            enforcement_point=f.enforcement_point,
        ))
    failure_count = sum(1 for e in events if e.level == IntegrationEvent.LEVEL_ERROR)
    events.append(IntegrationEvent(
        management_station=management_station, run=run,
        level=IntegrationEvent.LEVEL_INFO, stage="",
        reason="RenormalizationCompleted",
        message=f"Renormalization completed with {failure_count} failure(s).",
    ))
    IntegrationEvent.objects.bulk_create(events)

    run.status = IntegrationRun.STATUS_PARTIAL if failure_count else IntegrationRun.STATUS_SUCCEEDED
    run.completed_at = timezone.now()
    run.save(update_fields=["status", "completed_at"])

    return RenormalizationTrackingResult(run=run, renormalized=renormalized, failure_count=failure_count)


class ManagementStationRenormalizeView(View):
    def post(self, request, pk):
        management_station = get_object_or_404(ManagementStation, pk=pk)
        list_url = reverse("management_station_list")

        outcome = _renormalize_station_with_tracking(management_station)

        messages.success(
            request,
            "Renormalization completed for "
            f"{len(outcome.renormalized.appliances)} appliance(s) and "
            f"{len(outcome.renormalized.enforcement_points)} enforcement point(s), "
            "using already-collected data (no device connection made).",
        )
        if outcome.failure_count:
            messages.error(
                request,
                f"{outcome.failure_count} normalization task(s) failed. Review the Events tab for details.",
            )
        return HttpResponseRedirect(list_url)


@dataclass(slots=True)
class DynamicContentRefreshTrackingResult:
    run: IntegrationRun
    refresh: PANOSDynamicContentRefreshResult
    failure_count: int


def _refresh_station_dynamic_content_with_tracking(
    management_station: ManagementStation,
) -> DynamicContentRefreshTrackingResult:
    """Collect and normalize runtime EDL/FQDN content for a station's in-scope
    appliances/enforcement points, recording an IntegrationRun and any per-item
    IntegrationEvents the same way the config sync/renormalize views do.

    A distinct, explicitly-triggered action rather than part of the regular sync - EDL
    collection is one API call per referenced EDL name (each potentially paginated), a
    fundamentally different cost profile than the fixed handful of calls the regular sync
    makes, so it stays opt-in rather than automatic."""
    run = IntegrationRun.objects.create(
        management_station=management_station,
        run_scope=IntegrationRun.SCOPE_APPLIANCE,
        status=IntegrationRun.STATUS_RUNNING,
    )
    IntegrationEvent.objects.create(
        management_station=management_station,
        run=run,
        level=IntegrationEvent.LEVEL_INFO,
        stage="",
        reason="DynamicContentRefreshStarted",
        message="EDL/FQDN cache refresh started.",
    )
    refresh = refresh_in_scope_dynamic_content(management_station)

    events = []
    for f in refresh.fqdn_cache_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_COLLECT,
            reason="FqdnCacheCollectionFailed", message=f.error_text,
            appliance=f.appliance,
        ))
    for item in refresh.fqdn_cache_collections:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_COLLECT,
            reason="FqdnCacheCollected", message="Collected FQDN resolution cache.",
            appliance=item.appliance,
        ))
    for f in refresh.external_list_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_COLLECT,
            reason="ExternalListCollectionFailed", message=f.error_text,
            enforcement_point=f.enforcement_point,
        ))
    for item in refresh.external_list_collections:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_COLLECT,
            reason="ExternalListCollected", message="Collected external dynamic list.",
            enforcement_point=item.enforcement_point,
        ))
    for f in refresh.dynamic_content_failures:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_ERROR, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="DynamicAddressContentNormalizationFailed", message=f.error_text,
            enforcement_point=f.enforcement_point,
        ))
    for item in refresh.dynamic_content_normalizations:
        events.append(IntegrationEvent(
            management_station=management_station, run=run,
            level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
            reason="DynamicAddressContentNormalized",
            message=(
                f"Normalized {len(item.updated_address_objects)} address object(s), "
                f"{item.total_resolved_entries} resolved entr{'y' if item.total_resolved_entries == 1 else 'ies'}."
            ),
            enforcement_point=item.enforcement_point,
        ))
    failure_count = sum(1 for e in events if e.level == IntegrationEvent.LEVEL_ERROR)
    events.append(IntegrationEvent(
        management_station=management_station, run=run,
        level=IntegrationEvent.LEVEL_INFO, stage="",
        reason="DynamicContentRefreshCompleted",
        message=f"EDL/FQDN cache refresh completed with {failure_count} failure(s).",
    ))
    IntegrationEvent.objects.bulk_create(events)

    run.status = IntegrationRun.STATUS_PARTIAL if failure_count else IntegrationRun.STATUS_SUCCEEDED
    run.completed_at = timezone.now()
    run.save(update_fields=["status", "completed_at"])

    return DynamicContentRefreshTrackingResult(run=run, refresh=refresh, failure_count=failure_count)


class ManagementStationRefreshDynamicContentView(View):
    def post(self, request, pk):
        management_station = get_object_or_404(ManagementStation, pk=pk)
        list_url = reverse("management_station_list")

        outcome = _refresh_station_dynamic_content_with_tracking(management_station)
        refresh = outcome.refresh

        total_resolved_entries = sum(
            item.total_resolved_entries for item in refresh.dynamic_content_normalizations
        )
        updated_object_count = sum(
            len(item.updated_address_objects) for item in refresh.dynamic_content_normalizations
        )
        messages.success(
            request,
            "EDL/FQDN cache refresh completed: "
            f"{len(refresh.fqdn_cache_collections)} appliance FQDN cache snapshot(s) collected, "
            f"{updated_object_count} address object(s) resolved to {total_resolved_entries} "
            "IP range(s).",
        )
        if outcome.failure_count:
            messages.error(
                request,
                f"{outcome.failure_count} EDL/FQDN refresh task(s) failed. Review the Events tab for details.",
            )
        return HttpResponseRedirect(list_url)


class EnforcementPointScopeToggleView(View):
    def post(self, request, pk, enforcement_point_pk):
        management_station = get_object_or_404(ManagementStation, pk=pk)
        enforcement_point = get_object_or_404(
            EnforcementPoint,
            pk=enforcement_point_pk,
            management_station=management_station,
        )
        detail_url = f"{reverse('management_station_detail', kwargs={'pk': management_station.pk})}?tab={TAB_ENFORCEMENT_POINTS}"
        enforcement_point.in_scope = not enforcement_point.in_scope
        enforcement_point.save(update_fields=["in_scope"])
        if enforcement_point.in_scope:
            messages.success(request, "Enforcement point marked in scope.")
        else:
            messages.success(request, "Enforcement point marked out of scope.")
        return HttpResponseRedirect(detail_url)
