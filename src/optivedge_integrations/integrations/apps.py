from django.apps import AppConfig


class IntegrationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "optivedge_integrations.integrations"
    label = "integrations"

    def ready(self):
        # `server_started` receiver: closes the runs a restart killed.
        from . import lifecycle  # noqa: F401
