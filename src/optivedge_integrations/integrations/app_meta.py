"""Plugin registration for the shared OptivEdge shell.

See `optivedge.app_registry` for how `URL_MOUNT`/`SIDEBAR_SECTION` are consumed.
"""

URL_MOUNT = {
    "prefix": "integrations/",
    "module": "optivedge_integrations.integrations.urls",
}

#: The shell renders this on every page when it returns something. Deliberately binary
#: and icon-only - see optivedge.app_registry.health_indicators().
HEALTH_INDICATOR = {
    "check": "optivedge_integrations.integrations.diagnostics.health:normalization_indicator",
}

SIDEBAR_SECTION = [
    {
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
                    "management_station_refresh_dynamic_content",
                    "appliance_group_snapshots",
                    "enforcement_point_scope_toggle",
                    "enforcement_point_addresses",
                },
            },
            {
                "href": "/integrations/enforcement-points/",
                "icon": "shield",
                "label": "Enforcement Points",
                "active_names": {
                    "enforcement_point_list",
                    "enforcement_point_detail",
                    "enforcement_point_zone_detail",
                },
            },
            {
                "href": "/integrations/collection-script/",
                "icon": "wand-sparkles",
                "label": "Collection Script",
                "active_names": {"collection_script"},
            },
        ],
    },
    {
        "label": "Notes",
        "items": [
            {
                "href": "/integrations/notes/",
                "icon": "book-marked",
                "label": "Notes",
                "active_names": {
                    "note_list",
                    "note_create",
                    "note_update",
                },
            },
        ],
    },
]
