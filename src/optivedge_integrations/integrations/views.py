"""UI views for the current integration management surfaces.

This module owns Django views and view-level composition for the management-station
workflow. Keep vendor session, collection, and persistence logic out of this layer.
"""

import json
import logging
import threading
from dataclasses import dataclass
from datetime import timedelta

from django.contrib import messages
from django.core.paginator import Paginator
from django.db import connections
from django.db.models import Count, OuterRef, Q, Subquery
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, DeleteView, UpdateView

from django.contrib.contenttypes.models import ContentType
from optivedge.models import ApplicationEnvironment
from optivedge.views import RightOverlayMixin
from optivedge_integrations.integrations.forms import ManagementStationForm, NoteForm
from optivedge_integrations.integrations.scripted_collection.generator import (
    build_collection_package,
)
from optivedge_integrations.integrations.diagnostics import (
    capture_census,
    diagnose_collisions,
    normalization_health,
    explain_address_reference,
    compare_censuses,
    list_censuses,
    load_census,
    write_census,
)
from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    EnforcementPoint,
    IntegrationEvent,
    IntegrationRun,
    ManagementStation,
    NormalizationIssue,
    Note,
    SecurityRule,
    Snapshot,
    Zone,
)
from optivedge_integrations.integrations.presentation import (
    build_address_group_row,
    build_address_object_row,
)
from optivedge_integrations.integrations.platforms.pan_os import (
    PANOSDynamicContentRefreshResult,
    PANOSInScopeRefreshCollection,
    PANOSInScopeRenormalizationResult,
    collect_and_normalize_device_groups,
    collect_persist_and_normalize,
    refresh_in_scope_configuration_snapshots,
    refresh_in_scope_dynamic_content,
    renormalize_in_scope_configuration,
)
from optivedge_integrations.integrations.platforms.pan_os.collectors import collect_show_managed_devices
from optivedge_integrations.integrations.platforms.pan_os.collectors.managed_devices import (
    MANAGED_DEVICES_SOURCE_TYPE,
)
from optivedge_integrations.integrations.device_group_bindings import rebuild_device_group_bindings
from optivedge_integrations.integrations.search_vocabulary import (
    rebuild_all_security_rule_search_vocabulary,
    rebuild_security_rule_search_vocabulary,
)


logger = logging.getLogger(__name__)

TAB_DETAILS = "details"
TAB_ENFORCEMENT_POINTS = "enforcement-points"
TAB_EVENTS = "events"
# No appliance-groups tab: it was removed as adding no operator value. An old
# ?tab=appliance-groups link falls back to Details like any unknown tab.
_VALID_TABS = {TAB_DETAILS, TAB_ENFORCEMENT_POINTS, TAB_EVENTS}

TAB_APPLIANCES = "appliances"
TAB_ZONES = "zones"
_VALID_ENFORCEMENT_POINT_TABS = {TAB_DETAILS, TAB_APPLIANCES, TAB_ZONES}

SCOPE_FILTER_IN = "in"
SCOPE_FILTER_OUT = "out"
SCOPE_FILTER_ALL = "all"
_VALID_SCOPE_FILTERS = {SCOPE_FILTER_IN, SCOPE_FILTER_OUT, SCOPE_FILTER_ALL}


def _latest_inventory_snapshot_qs(management_station_ref):
    """The station's `show devices all` snapshots, newest first. The newest one's
    collected_at is how current the station's inventory is."""
    return Snapshot.objects.filter(
        management_station=management_station_ref,
        source_type=MANAGED_DEVICES_SOURCE_TYPE,
    ).order_by("-collected_at")


def get_management_station_list_queryset():
    latest_run_qs = IntegrationRun.objects.filter(management_station=OuterRef("pk")).order_by("-started_at")
    return ManagementStation.objects.annotate(
        appliance_group_count=Count("appliance_groups", distinct=True),
        appliance_count=Count("appliances", distinct=True),
        enforcement_point_count=Count("enforcement_points", distinct=True),
        in_scope_enforcement_point_count=Count(
            "enforcement_points",
            filter=Q(enforcement_points__in_scope=True),
            distinct=True,
        ),
        latest_run_status=Subquery(latest_run_qs.values("status")[:1]),
        latest_run_completed_at=Subquery(latest_run_qs.values("completed_at")[:1]),
        inventory_as_of=Subquery(
            _latest_inventory_snapshot_qs(OuterRef("pk")).values("collected_at")[:1]
        ),
    ).order_by("hostname")


def build_management_station_detail_context(
    management_station, *, active_tab=TAB_DETAILS, scope=SCOPE_FILTER_ALL,
):
    if active_tab not in _VALID_TABS:
        active_tab = TAB_DETAILS

    context = {"active_tab": active_tab}

    if active_tab == TAB_DETAILS:
        context["workflow"] = build_management_station_workflow(management_station)

    elif active_tab == TAB_ENFORCEMENT_POINTS:
        scope = normalize_scope_filter(scope)
        context["scope_filter"] = scope
        enforcement_points = list(
            filter_enforcement_points_by_scope(
                management_station.enforcement_points.select_related(
                    "appliance",
                ).prefetch_related("nodes__appliance"),
                scope,
            )
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


#: The event each tracked action opens its run with. A run records no kind of its own, so
#: this is how the workflow tells an inventory sync from a collection.
_INVENTORY_RUN_REASON = "InventorySyncStarted"
_COLLECTION_RUN_REASON = "InScopeRefreshStarted"
_DYNAMIC_CONTENT_RUN_REASON = "DynamicContentRefreshStarted"

WORKFLOW_STEP_INVENTORY = "inventory"
WORKFLOW_STEP_SCOPE = "scope"
WORKFLOW_STEP_COLLECT = "collect"


def _latest_run_opened_by(management_station, reason):
    return (
        IntegrationRun.objects.filter(management_station=management_station, events__reason=reason)
        .order_by("-started_at")
        .first()
    )


def build_management_station_workflow(management_station):
    """State of the three operator steps on the station details tab - sync inventory, choose
    scope, collect and normalize - and which one is the next thing to do.

    `next_step` is the first step whose work is missing or out of date, or None when all
    three are current. A collection that finished before the latest inventory is out of
    date: the inventory may have found devices the collection never reached.
    """
    is_panorama = management_station.station_type == ManagementStation.StationType.PAN_PANORAMA
    inventory_snapshot = _latest_inventory_snapshot_qs(management_station).only("collected_at").first()
    inventory_as_of = inventory_snapshot.collected_at if inventory_snapshot else None
    inventory_run = _latest_run_opened_by(management_station, _INVENTORY_RUN_REASON)

    enforcement_points = management_station.enforcement_points
    ep_total = enforcement_points.count()
    ep_in_scope = enforcement_points.filter(in_scope=True).count()
    appliance_count = management_station.appliances.count()

    collection_run = _latest_run_opened_by(management_station, _COLLECTION_RUN_REASON)
    dynamic_content_run = _latest_run_opened_by(management_station, _DYNAMIC_CONTENT_RUN_REASON)
    # Against completion, not start: the collection re-reads `show devices all` itself, so
    # every collection writes an inventory snapshot newer than the moment it began.
    collection_is_stale = bool(
        collection_run
        and collection_run.completed_at
        and inventory_as_of
        and collection_run.completed_at < inventory_as_of
    )

    in_progress = collection_in_progress(management_station)

    if not is_panorama or in_progress:
        next_step = None
    elif inventory_as_of is None:
        next_step = WORKFLOW_STEP_INVENTORY
    elif ep_in_scope == 0:
        next_step = WORKFLOW_STEP_SCOPE
    elif (
        collection_run is None
        or collection_run.status == IntegrationRun.STATUS_FAILED
        or collection_is_stale
    ):
        next_step = WORKFLOW_STEP_COLLECT
    else:
        next_step = None

    if ep_total == 0:
        scope_summary = "No enforcement points discovered yet."
    else:
        scope_summary = (
            f"{ep_in_scope} of {ep_total} enforcement point{'s' if ep_total != 1 else ''} in scope."
        )

    return {
        "is_panorama": is_panorama,
        "next_step": next_step,
        "inventory_as_of": inventory_as_of,
        "inventory_run": inventory_run,
        "inventory_summary": (
            f"{appliance_count} appliance{'s' if appliance_count != 1 else ''}, "
            f"{ep_total} enforcement point{'s' if ep_total != 1 else ''} discovered."
        ),
        "ep_total": ep_total,
        "ep_in_scope": ep_in_scope,
        "scope_summary": scope_summary,
        # Emphasised only once there is something to choose from: before the first inventory
        # sync an empty scope is expected, and step 1 is what needs doing.
        "scope_needs_attention": ep_total > 0 and ep_in_scope == 0,
        "collection_run": collection_run,
        "collection_is_stale": collection_is_stale,
        "dynamic_content_run": dynamic_content_run,
        "collection_in_progress": in_progress,
    }


def normalize_scope_filter(scope):
    """All by default, unlike the standalone list this tab replaced: the tab is where scope
    is CHOSEN (step 2 of the station workflow links here), and hiding out-of-scope points
    by default would hide the very rows an operator came to put in scope."""
    return scope if scope in _VALID_SCOPE_FILTERS else SCOPE_FILTER_ALL


def filter_enforcement_points_by_scope(queryset, scope):
    if scope == SCOPE_FILTER_IN:
        return queryset.filter(in_scope=True)
    if scope == SCOPE_FILTER_OUT:
        return queryset.filter(in_scope=False)
    return queryset


def build_enforcement_point_detail_context(enforcement_point, *, active_tab=TAB_DETAILS):
    if active_tab not in _VALID_ENFORCEMENT_POINT_TABS:
        active_tab = TAB_DETAILS

    context = {"active_tab": active_tab}

    if active_tab == TAB_APPLIANCES:
        context["appliances"] = get_enforcement_point_appliances(enforcement_point)

    elif active_tab == TAB_ZONES:
        context["zones"] = list(
            enforcement_point.zones.prefetch_related("interfaces").order_by("name", "pk")
        )

    return context


def get_enforcement_point_appliances(enforcement_point):
    """The appliances enforcing this point, in a single shape for the template.

    Production points are group-scoped and reach their appliances through
    `EnforcementNode`; the appliance-scoped shape is only built by tests, but the
    management-station detail template already renders both, so this does too.
    """
    appliances = [
        node.appliance
        for node in enforcement_point.nodes.select_related("appliance").order_by(
            "appliance__hostname",
            "appliance__serial_number",
            "pk",
        )
        if node.appliance is not None
    ]
    if not appliances and enforcement_point.appliance is not None:
        appliances = [enforcement_point.appliance]
    return appliances


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
        context.update(build_management_station_detail_context(
            self.object,
            active_tab=active_tab,
            scope=self.request.GET.get("scope", SCOPE_FILTER_ALL),
        ))
        return context


class EnforcementPointDetailView(DetailView):
    model = EnforcementPoint
    context_object_name = "enforcement_point"
    pk_url_kwarg = "pk"
    template_name = "integrations/enforcement_point_detail.html"

    def get_queryset(self):
        return EnforcementPoint.objects.select_related(
            "management_station",
            "appliance_group",
            "appliance",
            "appliance_group__active_appliance",
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        active_tab = self.request.GET.get("tab", TAB_DETAILS)
        context.update(build_enforcement_point_detail_context(self.object, active_tab=active_tab))
        return context


class EnforcementPointZoneDetailView(DetailView):
    model = Zone
    context_object_name = "zone"
    pk_url_kwarg = "zone_pk"
    template_name = "integrations/zone_detail.html"

    def get_queryset(self):
        return Zone.objects.filter(
            enforcement_point=self.kwargs["pk"],
        ).select_related(
            "enforcement_point",
            "enforcement_point__management_station",
            "source_snapshot",
        ).prefetch_related("interfaces")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["enforcement_point"] = self.object.enforcement_point
        context["raw_entry_json"] = build_pretty_json(self.object.raw_entry)
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
            # The device-group tree is station inventory too, and one op call: an operator
            # who syncs a station gets the containers as well as the devices.
            collect_and_normalize_device_groups(management_station)
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
            message="Managed devices and device groups collected, persisted, and normalized.",
        )
        messages.success(request, "Managed devices and device groups collected, persisted, and normalized.")
        return HttpResponseRedirect(detail_url)


@dataclass(slots=True)
class InScopeRefreshTrackingResult:
    run: IntegrationRun
    succeeded: bool
    refresh: PANOSInScopeRefreshCollection | None
    error: Exception | None
    failure_count: int


def _open_in_scope_refresh_run(management_station: ManagementStation) -> IntegrationRun:
    """Create the RUNNING run and its opening event. Split out so the background collection
    can open it inside the request, before the redirect: the page the operator lands on then
    already shows the run, rather than the previous one until the thread gets going."""
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
        reason=_COLLECTION_RUN_REASON,
        message="In-scope configuration refresh started.",
    )
    return run


def _refresh_station_in_scope_with_tracking(
    management_station: ManagementStation,
    run: IntegrationRun | None = None,
) -> InScopeRefreshTrackingResult:
    """Run the in-scope configuration refresh for one station, recording an IntegrationRun
    and any per-item IntegrationEvents. Shared by the single-station and bulk in-scope
    refresh views so both stay consistent in what they track.

    A RUN IS ALWAYS FINISHED, whatever happens inside it. Only the collection call used to be
    guarded, so anything that went wrong afterwards - normalization bookkeeping, the binding
    rebuild - left the run RUNNING for ever. The station then showed "Refreshing..."
    indefinitely with nothing to explain it, because the per-item events are gathered in
    memory and written in one go at the end, so the failure discarded the entire account of
    the run and left only InScopeRefreshStarted behind.

    That is why the events list is owned HERE and passed down: on failure, whatever was
    gathered before the exception is still written, and an explicit failure event is added
    beside it. A refresh that dies half way is a thing that has to be readable afterwards.

    Pass `run` when it was already opened by _open_in_scope_refresh_run().
    """
    if run is None:
        run = _open_in_scope_refresh_run(management_station)
    events: list[IntegrationEvent] = []
    try:
        return _refresh_station_in_scope_tracked(management_station, run, events)
    except Exception as exc:  # noqa: BLE001 - the run must be closed whatever this was
        logger.exception(
            "In-scope configuration refresh failed for management station %s", management_station.pk,
        )
        if events:
            IntegrationEvent.objects.bulk_create(events)
        IntegrationEvent.objects.create(
            management_station=management_station,
            run=run,
            level=IntegrationEvent.LEVEL_ERROR,
            stage="",
            reason="InScopeRefreshFailed",
            message=f"{type(exc).__name__}: {exc}",
        )
        run.status = IntegrationRun.STATUS_FAILED
        run.completed_at = timezone.now()
        run.save(update_fields=["status", "completed_at"])
        return InScopeRefreshTrackingResult(
            run=run, succeeded=False, refresh=None, error=exc,
            failure_count=sum(1 for e in events if e.level == IntegrationEvent.LEVEL_ERROR) + 1,
        )


def _refresh_station_in_scope_tracked(
    management_station: ManagementStation,
    run: IntegrationRun,
    events: list[IntegrationEvent],
) -> InScopeRefreshTrackingResult:
    """The body of one tracked refresh. Appends to `events` as it goes so the caller can still
    write them if this raises - see _refresh_station_in_scope_with_tracking."""
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
    # Here rather than in `orchestration.refresh_panorama_in_scope_data`, which no view calls:
    # both refresh paths - one station and the bulk sweep - come through this helper, and
    # bindings must be rebuilt AFTER the refresh, from the provenance rows it just rewrote.
    bindings = rebuild_device_group_bindings(management_station)
    events.append(IntegrationEvent(
        management_station=management_station, run=run,
        level=IntegrationEvent.LEVEL_INFO, stage=IntegrationEvent.STAGE_NORMALIZE,
        reason="DeviceGroupBindingsRebuilt",
        message=(
            f"{bindings.binding_count} device-group binding(s) across "
            f"{bindings.device_group_count} group(s); "
            f"{bindings.unresolved_row_count} provenance row(s) resolved to no vsys."
        ),
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


#: A RUNNING collection younger than this blocks starting another. Older ones are taken to
#: be orphans - the thread is a daemon, so a server restart mid-collection kills it and
#: leaves its run RUNNING for ever, and without an age limit that would lock the button
#: permanently. Collections take minutes; this is far outside any real one.
COLLECTION_LOCK_MAX_AGE = timedelta(hours=2)


def collection_in_progress(management_station: ManagementStation) -> bool:
    """Whether step 3 is running for this station: either half of it, configuration or
    EDL/FQDN, holds a RUNNING run recent enough not to be an orphan."""
    return IntegrationRun.objects.filter(
        management_station=management_station,
        status=IntegrationRun.STATUS_RUNNING,
        started_at__gte=timezone.now() - COLLECTION_LOCK_MAX_AGE,
        events__reason__in=(_COLLECTION_RUN_REASON, _DYNAMIC_CONTENT_RUN_REASON),
    ).exists()


def _collect_and_normalize_station(management_station: ManagementStation, run: IntegrationRun) -> None:
    """Step 3 of the station workflow: the in-scope configuration refresh, then EDL/FQDN
    content, then the search vocabulary. Runs on a background thread - there is no request
    to report to, so each part's outcome is its run and events, which the details tab and
    the Events tab show.
    """
    outcome = _refresh_station_in_scope_with_tracking(management_station, run)

    # EDL/FQDN content hangs off the address objects in-scope rules reference, so it can
    # only follow a configuration refresh that ran, rather than resolving against stale
    # rules. Its run and events record the outcome.
    if outcome.succeeded:
        _refresh_station_dynamic_content_with_tracking(management_station)

    # The bulk sweep used to be the only caller of this, so a station collected on its own
    # left the assessment search grounding stale.
    rebuild_security_rule_search_vocabulary(management_station)


def _run_station_collection_in_background(management_station_pk: int, run_pk: int) -> None:
    """Thread entry point for ManagementStationInScopeSyncView.

    Takes primary keys rather than instances: the thread has its own database connection
    and reads its own rows. Nothing it raises reaches a user, so it is logged, and a run
    that the failure left open is closed - the details tab would otherwise show "Running"
    until COLLECTION_LOCK_MAX_AGE passed.
    """
    run = None
    try:
        management_station = ManagementStation.objects.get(pk=management_station_pk)
        run = IntegrationRun.objects.get(pk=run_pk)
        _collect_and_normalize_station(management_station, run)
    except Exception:
        logger.exception(
            "Background collection failed for management station %s", management_station_pk,
        )
        if run is not None:
            # Only this collection's own runs - its configuration run and any EDL/FQDN run
            # it went on to open - never, say, a renormalize running beside it.
            IntegrationRun.objects.filter(
                management_station_id=management_station_pk,
                status=IntegrationRun.STATUS_RUNNING,
                started_at__gte=run.started_at,
                events__reason__in=(_COLLECTION_RUN_REASON, _DYNAMIC_CONTENT_RUN_REASON),
            ).update(status=IntegrationRun.STATUS_FAILED, completed_at=timezone.now())
    finally:
        connections.close_all()


class ManagementStationInScopeSyncView(View):
    """Starts step 3 on a background thread and returns at once. A collection contacts every
    in-scope device and takes minutes; held in the request, it kept the browser waiting for
    all of it and ran into any proxy or server timeout on the way."""

    def post(self, request, pk):
        management_station = get_object_or_404(ManagementStation, pk=pk)
        detail_url = reverse("management_station_detail", kwargs={"pk": management_station.pk})

        if management_station.station_type != ManagementStation.StationType.PAN_PANORAMA:
            messages.error(
                request,
                "In-scope configuration refresh is currently only supported for Panorama management stations.",
            )
            return HttpResponseRedirect(detail_url)

        # Two collections at once would interleave their delete-and-recreate writes on the
        # same enforcement points.
        if collection_in_progress(management_station):
            messages.error(request, "A collection is already running for this station.")
            return HttpResponseRedirect(detail_url)

        run = _open_in_scope_refresh_run(management_station)
        threading.Thread(
            target=_run_station_collection_in_background,
            args=(management_station.pk, run.pk),
            name=f"station-collection-{management_station.pk}",
            daemon=True,
        ).start()

        messages.success(
            request,
            "Collection started in the background. This page refreshes itself until it "
            "finishes; the Events tab has the detail.",
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
    """No longer linked from any page - the button was removed from the station list. Kept
    routable by decision; see CLAUDE.md "Views"."""

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
        detail_url = reverse("management_station_detail", kwargs={"pk": management_station.pk})

        outcome = _renormalize_station_with_tracking(management_station)
        # Rules were just rewritten, so the grounding built from them is stale.
        rebuild_security_rule_search_vocabulary(management_station)

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
        return HttpResponseRedirect(detail_url)


@dataclass(slots=True)
class DynamicContentRefreshTrackingResult:
    run: IntegrationRun
    refresh: PANOSDynamicContentRefreshResult | None
    failure_count: int
    error: Exception | None = None


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
    # Closed whatever happens, as the in-scope refresh is: an exception here used to leave
    # the run RUNNING for ever, and it now follows every configuration refresh.
    try:
        refresh = refresh_in_scope_dynamic_content(management_station)
    except Exception as exc:  # noqa: BLE001 - the run must be closed whatever this was
        logger.exception(
            "EDL/FQDN cache refresh failed for management station %s", management_station.pk,
        )
        IntegrationEvent.objects.create(
            management_station=management_station,
            run=run,
            level=IntegrationEvent.LEVEL_ERROR,
            stage="",
            reason="DynamicContentRefreshFailed",
            message=f"{type(exc).__name__}: {exc}",
        )
        run.status = IntegrationRun.STATUS_FAILED
        run.completed_at = timezone.now()
        run.save(update_fields=["status", "completed_at"])
        return DynamicContentRefreshTrackingResult(run=run, refresh=None, failure_count=1, error=exc)

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


def _dynamic_content_summary(refresh: PANOSDynamicContentRefreshResult) -> str:
    total_resolved_entries = sum(
        item.total_resolved_entries for item in refresh.dynamic_content_normalizations
    )
    updated_object_count = sum(
        len(item.updated_address_objects) for item in refresh.dynamic_content_normalizations
    )
    return (
        "EDL/FQDN cache refresh completed: "
        f"{len(refresh.fqdn_cache_collections)} appliance FQDN cache snapshot(s) collected, "
        f"{updated_object_count} address object(s) resolved to {total_resolved_entries} "
        "IP range(s)."
    )


class ManagementStationRefreshDynamicContentView(View):
    """No longer linked from any page - step 3 on the station details tab runs this after
    the configuration refresh. Kept routable by decision; see CLAUDE.md "Views"."""

    def post(self, request, pk):
        management_station = get_object_or_404(ManagementStation, pk=pk)
        list_url = reverse("management_station_list")

        outcome = _refresh_station_dynamic_content_with_tracking(management_station)
        if outcome.refresh is None:
            messages.error(request, f"EDL/FQDN cache refresh failed: {outcome.error}")
            return HttpResponseRedirect(list_url)

        messages.success(request, _dynamic_content_summary(outcome.refresh))
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
        # Back to the filter the toggle was pressed under, so the list the operator was
        # working through does not reset to All after every click.
        scope = normalize_scope_filter(request.POST.get("scope", SCOPE_FILTER_ALL))
        detail_url = (
            f"{reverse('management_station_detail', kwargs={'pk': management_station.pk})}"
            f"?tab={TAB_ENFORCEMENT_POINTS}&scope={scope}"
        )
        enforcement_point.in_scope = not enforcement_point.in_scope
        enforcement_point.save(update_fields=["in_scope"])
        if enforcement_point.in_scope:
            messages.success(request, "Enforcement point marked in scope.")
        else:
            messages.success(request, "Enforcement point marked out of scope.")
        return HttpResponseRedirect(detail_url)


def build_note_rows(notes):
    """Resolve each note's target to the appliance name(s) shown in the Notes area.

    Currently every note targets an ApplianceGroup; the presentation leads with that
    group's member appliance names. Written generically so new target types can be added
    to the resolution map without reshaping callers.
    """
    appliance_group_ct = ContentType.objects.get_for_model(ApplianceGroup)
    group_ids = [
        note.object_id for note in notes if note.content_type_id == appliance_group_ct.id
    ]
    groups_by_id = {
        group.pk: group
        for group in (
            ApplianceGroup.objects.filter(pk__in=group_ids)
            .select_related("management_station")
            .prefetch_related("appliances")
        )
    }

    rows = []
    for note in notes:
        group = None
        if note.content_type_id == appliance_group_ct.id:
            group = groups_by_id.get(note.object_id)
        appliance_names = (
            [appliance.hostname or appliance.serial_number for appliance in group.appliances.all()]
            if group is not None
            else []
        )
        rows.append(
            {
                "note": note,
                "appliance_group": group,
                "appliance_names": appliance_names,
            }
        )
    return rows


def get_note_rows():
    return build_note_rows(list(Note.objects.select_related("content_type")))


class CollectionScriptView(TemplateView):
    """Build the collection package for a customer to run.

    For an estate this deployment cannot reach: the customer runs the script on their own
    machine and sends back what it collects. The page hands out three files in one .zip -
    the script, the launcher and the instructions - with the client's name substituted in,
    so whoever opens it can see who asked for it.

    The files come from `scripted_collection/`, which is the same copy the test suite checks
    against the collector command set. Nothing is generated from scratch here.
    """

    template_name = "integrations/collection_script.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        environment = ApplicationEnvironment.objects.order_by("pk").first()
        context["client_name"] = self.request.POST.get("client_name") or (
            environment.client_name if environment else ""
        )
        context["has_environment"] = environment is not None
        return context

    def post(self, request, *args, **kwargs):
        client_name = (request.POST.get("client_name") or "").strip()
        if not client_name:
            messages.error(request, "Enter the client name to put on the script.")
            return HttpResponseRedirect(reverse("collection_script"))

        package = build_collection_package(client_name)
        response = HttpResponse(package.content, content_type="application/zip")
        response["Content-Disposition"] = f'attachment; filename="{package.file_name}"'
        return response


class NoteListView(TemplateView):
    template_name = "integrations/note_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["note_rows"] = get_note_rows()
        return context


class NoteListBackgroundMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["note_rows"] = get_note_rows()
        return context


class NoteCreateView(RightOverlayMixin, NoteListBackgroundMixin, CreateView):
    form_class = NoteForm
    model = Note
    template_name = "integrations/note_form.html"

    def get_overlay_close_url(self):
        return reverse("note_list")

    def get_success_url(self):
        return reverse("note_list")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form_mode"] = "create"
        return context

    def form_valid(self, form):
        appliance_group = form.cleaned_data["appliance_group"]
        form.instance.content_type = ContentType.objects.get_for_model(ApplianceGroup)
        form.instance.object_id = appliance_group.pk
        return super().form_valid(form)


class NoteUpdateView(RightOverlayMixin, NoteListBackgroundMixin, UpdateView):
    form_class = NoteForm
    model = Note
    pk_url_kwarg = "pk"
    template_name = "integrations/note_form.html"

    def get_overlay_close_url(self):
        return reverse("note_list")

    def get_success_url(self):
        return reverse("note_list")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["form_mode"] = "update"
        return context

    def get_initial(self):
        initial = super().get_initial()
        if isinstance(self.object.target, ApplianceGroup):
            initial["appliance_group"] = self.object.target
        return initial

    def form_valid(self, form):
        appliance_group = form.cleaned_data["appliance_group"]
        form.instance.content_type = ContentType.objects.get_for_model(ApplianceGroup)
        form.instance.object_id = appliance_group.pk
        return super().form_valid(form)


class DeveloperView(TemplateView):
    """Hidden operations page. Deliberately absent from the sidebar (`app_meta.py`).

    Reachable only by typing /developer/. It is not access-controlled by this package —
    a downstream project that exposes it publicly should gate it in its own middleware or
    URL conf, since this repo has no auth model of its own.
    """

    template_name = "integrations/developer.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["censuses"] = list_censuses()
        context["live_census"] = capture_census(label="(live, unsaved)")
        context["live_collisions"] = diagnose_collisions(context["live_census"])

        comparison = None
        before_path = self.request.GET.get("before")
        after_path = self.request.GET.get("after")
        if before_path and after_path:
            try:
                comparison = compare_censuses(load_census(before_path), load_census(after_path))
            except (OSError, ValueError) as exc:
                comparison = {"error": f"Could not compare: {exc}"}
        context["comparison"] = comparison

        # Address-reference explainer: why did "unresolved address reference: X" happen?
        context["reference_points"] = EnforcementPoint.objects.select_related(
            "management_station", "appliance_group"
        ).order_by("appliance_group__name", "vsys_name", "pk")
        context["reference_name"] = (self.request.GET.get("reference_name") or "").strip()
        context["reference_point_id"] = self.request.GET.get("reference_point") or ""
        context["reference_explanation"] = None
        if context["reference_name"] and context["reference_point_id"]:
            point = EnforcementPoint.objects.filter(pk=context["reference_point_id"]).first()
            if point is None:
                context["reference_explanation"] = {"error": "That enforcement point no longer exists."}
            else:
                try:
                    context["reference_explanation"] = explain_address_reference(
                        point, context["reference_name"])
                except Exception as exc:  # noqa: BLE001 - a diagnostic must not 500
                    context["reference_explanation"] = {"error": f"{type(exc).__name__}: {exc}"}
        context["selected_before"] = before_path or ""
        context["selected_after"] = after_path or ""
        return context


class PolicyObjectCensusCaptureView(View):
    """Capture a census and write it to disk.

    Two labels matter for the shared-scope migration: capture `before` while the old
    schema is still in place, then `after` once migration 0015 and a renormalize have
    run. Any label is accepted — the page compares whichever two files you pick.
    """

    def post(self, request):
        label = (request.POST.get("label") or "").strip() or "census"
        try:
            path = write_census(capture_census(label=label))
        except OSError as exc:
            messages.error(request, f"Could not write the census file: {exc}")
            return HttpResponseRedirect(reverse("developer"))

        census = load_census(path)
        rows = sum(m.get("total_rows", 0) for m in census.get("models", {}).values())
        messages.success(
            request,
            f'Captured "{label}": {rows:,} scoped policy object row(s) written to {path}.',
        )
        if not census.get("schema_has_appliance_group_owner"):
            messages.warning(
                request,
                "This database predates migration 0015 — scoped objects have no appliance-group "
                "owner yet, so this is a pre-migration baseline.",
            )
        return HttpResponseRedirect(reverse("developer"))


class NormalizationIssueListView(TemplateView):
    """What is currently unnormalized, root causes first.

    The shell indicator says only *whether* something is wrong. This says what, and it
    leads with root causes: one object that fails to normalize makes every rule
    referencing it fail, and listing those together buries the cause among its own
    symptoms. Consequences are shown, but after, and grouped under what caused them.
    """

    template_name = "integrations/normalization_issue_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        issues = NormalizationIssue.objects.select_related(
            "management_station", "enforcement_point", "appliance_group"
        )

        station_id = self.request.GET.get("management_station")
        station = ManagementStation.objects.filter(pk=station_id).first() if station_id else None
        if station is not None:
            issues = issues.filter(management_station=station)

        context["stations"] = ManagementStation.objects.order_by("hostname", "pk")
        context["selected_station"] = station
        context["health"] = normalization_health(station)

        roots = [i for i in issues if not i.is_consequent]
        consequents = [i for i in issues if i.is_consequent]

        # Group consequences under the root they point at, so the page reads as
        # "this failed, and here is everything it took with it".
        by_cause: dict[str, list] = {}
        for issue in consequents:
            by_cause.setdefault(issue.related_object_name or "(unknown)", []).append(issue)

        context["root_issues"] = sorted(
            roots, key=lambda i: (i.severity != "error", i.kind, i.name)
        )
        context["consequences_by_cause"] = sorted(
            by_cause.items(), key=lambda pair: (-len(pair[1]), pair[0])
        )
        context["orphan_consequences"] = [
            issue for issue in consequents
            if issue.related_object_name and not any(
                r.name == issue.related_object_name for r in roots
            )
        ]
        return context
