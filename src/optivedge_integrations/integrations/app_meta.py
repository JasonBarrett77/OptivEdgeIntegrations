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
                    # Enforcement points are browsed from their station's tab, so their
                    # pages light up the station's item - there is no list of their own.
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
        # Notes sits under Experimental, a heading Assessments also contributes to: the shell
        # merges sections sharing a label, so each app still declares only its own items and
        # its own URL names. `collapsible` and `order` are repeated rather than left to the
        # other app because this package has to stand alone in a deployment without it.
        "label": "Experimental",
        "collapsible": True,
        "order": 100,
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
