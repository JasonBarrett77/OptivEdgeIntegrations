"""Forms for integration-facing CRUD surfaces.

This module owns shared form definitions and widget styling for the current
integration UI. Keep vendor-specific transport or persistence orchestration out
of this layer.
"""

from django import forms

from optivedge.integrations.models import ApplicationEnvironment, ManagementStation


TEXT_INPUT_CLASS = (
    "h-8 rounded-md border border-slate-200 bg-white px-3 text-sm text-slate-800 "
    "placeholder:text-slate-400 focus:border-blue-300 focus:outline-none "
    "focus:ring-2 focus:ring-blue-500/20"
)
MONO_TEXT_INPUT_CLASS = f"{TEXT_INPUT_CLASS} font-mono"
TEXTAREA_CLASS = (
    "min-h-24 rounded-md border border-slate-200 bg-white px-3 py-2 text-sm "
    "text-slate-800 placeholder:text-slate-400 focus:border-blue-300 "
    "focus:outline-none focus:ring-2 focus:ring-blue-500/20"
)
SELECT_CLASS = (
    "h-8 rounded-md border border-slate-200 bg-white px-3 text-sm text-slate-800 "
    "focus:border-blue-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
)


class ApplicationEnvironmentForm(forms.ModelForm):
    class Meta:
        model = ApplicationEnvironment
        fields = [
            "client_name",
            "client_short_name",
            "opportunity_number",
            "notes",
        ]
        widgets = {
            "client_name": forms.TextInput(
                attrs={
                    "class": TEXT_INPUT_CLASS,
                }
            ),
            "client_short_name": forms.TextInput(
                attrs={
                    "class": MONO_TEXT_INPUT_CLASS,
                }
            ),
            "opportunity_number": forms.TextInput(
                attrs={
                    "class": MONO_TEXT_INPUT_CLASS,
                    "placeholder": "OP-1234567",
                }
            ),
            "notes": forms.Textarea(
                attrs={
                    "class": TEXTAREA_CLASS,
                }
            ),
        }


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
