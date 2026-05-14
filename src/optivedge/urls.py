from django.urls import path

from optivedge.app_registry import optional_app_urlpatterns
from optivedge.integrations.views import HomeView

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
]

urlpatterns += optional_app_urlpatterns()
