"""Forms for integration-facing CRUD surfaces.

This module owns shared form definitions and widget styling for the current
integration UI. Keep vendor-specific transport or persistence orchestration out
of this layer.
"""

from django import forms

from optivedge.forms import MONO_TEXT_INPUT_CLASS, TEXT_INPUT_CLASS, TEXTAREA_CLASS
from optivedge_integrations.integrations.models import ManagementStation


SELECT_CLASS = (
    "h-8 rounded-md border border-slate-200 bg-white px-3 text-sm text-slate-800 "
    "focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
)


class ManagementStationForm(forms.ModelForm):
    class Meta:
        model = ManagementStation
        fields = [
            "station_type",
            "name",
            "hostname",
            "port",
            "username",
            "password",
            "api_key",
            "verify_tls",
            "ca_bundle_path",
            "notes",
        ]
        widgets = {
            "station_type": forms.Select(
                attrs={
                    "class": SELECT_CLASS,
                }
            ),
            "name": forms.TextInput(
                attrs={
                    "class": TEXT_INPUT_CLASS,
                }
            ),
            "hostname": forms.TextInput(
                attrs={
                    "class": MONO_TEXT_INPUT_CLASS,
                }
            ),
            "port": forms.NumberInput(
                attrs={
                    "class": SELECT_CLASS,
                }
            ),
            "username": forms.TextInput(
                attrs={
                    "class": TEXT_INPUT_CLASS,
                }
            ),
            "password": forms.PasswordInput(
                render_value=True,
                attrs={
                    "class": TEXT_INPUT_CLASS,
                },
            ),
            "api_key": forms.TextInput(
                attrs={
                    "class": TEXT_INPUT_CLASS,
                }
            ),
            "ca_bundle_path": forms.TextInput(
                attrs={
                    "class": MONO_TEXT_INPUT_CLASS,
                }
            ),
            "notes": forms.Textarea(
                attrs={
                    "class": TEXTAREA_CLASS,
                }
            ),
        }
