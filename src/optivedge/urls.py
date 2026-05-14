from django.urls import include, path

from optivedge.app_registry import optional_app_urlpatterns

urlpatterns = [
    path("", include("optivedge.integrations.urls")),
]

urlpatterns += optional_app_urlpatterns()
