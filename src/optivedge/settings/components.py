OPTIVEDGE_APPS = [
    "optivedge.apps.OptivEdgeConfig",
    "optivedge.integrations.apps.IntegrationsConfig",
]

OPTIVEDGE_MIDDLEWARE = []

OPTIVEDGE_CONTEXT_PROCESSORS = [
    "optivedge.context_processors.optional_app_navigation",
]

OPTIVEDGE_TEMPLATE_LIBRARIES = {
    "lucide": "optivedge.templatetags.lucide",
}
