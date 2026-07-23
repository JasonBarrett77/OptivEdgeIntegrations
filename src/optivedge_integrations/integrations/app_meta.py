"""Plugin registration for the shared OptivEdge shell.

See `optivedge.app_registry` for how `URL_MOUNT`/`SIDEBAR_SECTION` are consumed.
"""

URL_MOUNT = {
    "prefix": "integrations/",
    "module": "optivedge_integrations.integrations.urls",
}

SIDEBAR_SECTION = {
    "label": "Firewall Integrations",
    "items": [
        {
            "href": "/integrations/management-stations/",
            "icon": "server",
            "label": "Management Stations",
            "active_names": {
                "management_station_list",
                "management_station_create",
                "management_station_detail",
                "management_station_update",
                "management_station_delete",
                "management_station_sync",
                "management_station_in_scope_sync",
                "management_station_bulk_in_scope_sync",
                "appliance_group_snapshots",
                "enforcement_point_scope_toggle",
                "enforcement_point_addresses",
            },
        },
    ],
}
