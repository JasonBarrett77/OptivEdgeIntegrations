from django.urls import path

from optivedge.app_registry import optional_app_urlpatterns
from optivedge.integrations.views import (
    ApplicationEnvironmentSettingsView,
    ApplianceGroupSnapshotView,
    EnforcementPointAddressListView,
    EnforcementPointSecurityRuleListView,
    EnforcementPointScopeToggleView,
    HomeView,
    ManagementStationBulkInScopeSyncView,
    ManagementStationCreateView,
    ManagementStationDeleteView,
    ManagementStationDetailView,
    ManagementStationInScopeSyncView,
    ManagementStationListView,
    ManagementStationSyncView,
    ManagementStationUpdateView,
)

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path(
        "environment/settings/",
        ApplicationEnvironmentSettingsView.as_view(),
        name="application_environment_settings",
    ),
    path(
        "management-stations/",
        ManagementStationListView.as_view(),
        name="management_station_list",
    ),
    path(
        "management-stations/sync-in-scope-all/",
        ManagementStationBulkInScopeSyncView.as_view(),
        name="management_station_bulk_in_scope_sync",
    ),
    path(
        "management-stations/create/",
        ManagementStationCreateView.as_view(),
        name="management_station_create",
    ),
    path(
        "management-stations/<int:pk>/",
        ManagementStationDetailView.as_view(),
        name="management_station_detail",
    ),
    path(
        "management-stations/<int:pk>/edit/",
        ManagementStationUpdateView.as_view(),
        name="management_station_update",
    ),
    path(
        "management-stations/<int:pk>/delete/",
        ManagementStationDeleteView.as_view(),
        name="management_station_delete",
    ),
    path(
        "management-stations/<int:pk>/sync/",
        ManagementStationSyncView.as_view(),
        name="management_station_sync",
    ),
    path(
        "management-stations/<int:pk>/sync-in-scope/",
        ManagementStationInScopeSyncView.as_view(),
        name="management_station_in_scope_sync",
    ),
    path(
        "management-stations/<int:pk>/appliance-groups/<int:appliance_group_pk>/snapshots/",
        ApplianceGroupSnapshotView.as_view(),
        name="appliance_group_snapshots",
    ),
    path(
        "management-stations/<int:pk>/enforcement-points/<int:enforcement_point_pk>/scope/",
        EnforcementPointScopeToggleView.as_view(),
        name="enforcement_point_scope_toggle",
    ),
    path(
        "management-stations/<int:pk>/enforcement-points/<int:enforcement_point_pk>/security-rules/",
        EnforcementPointSecurityRuleListView.as_view(),
        name="enforcement_point_security_rules",
    ),
    path(
        "management-stations/<int:pk>/enforcement-points/<int:enforcement_point_pk>/addresses/",
        EnforcementPointAddressListView.as_view(),
        name="enforcement_point_addresses",
    ),
]

urlpatterns += optional_app_urlpatterns()
