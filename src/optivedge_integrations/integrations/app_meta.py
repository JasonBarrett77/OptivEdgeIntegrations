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
            "active_names": {"management_station_list", "management_station_detail"},
        },
    ],
}
