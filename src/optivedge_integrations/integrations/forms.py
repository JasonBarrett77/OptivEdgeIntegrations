"""Forms for integration-facing CRUD surfaces.

This module owns shared form definitions and widget styling for the current
integration UI. Keep vendor-specific transport or persistence orchestration out
of this layer.
"""

from django import forms
from django.db.models import Exists, F, OuterRef, Value
from django.db.models.functions import Coalesce, NullIf

from optivedge.forms import MONO_TEXT_INPUT_CLASS, TEXT_INPUT_CLASS, TEXTAREA_CLASS
from optivedge_integrations.integrations.models import (
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    Note,
)


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


class ApplianceGroupChoiceField(forms.ModelChoiceField):
    """Renders each appliance group by its member appliance name(s) - the presentation
    the Notes feature keys on - with the station/group for disambiguation."""

    def label_from_instance(self, obj):
        appliances = ", ".join(
            appliance.hostname or appliance.serial_number for appliance in obj.appliances.all()
        ) or "no appliances"
        return f"{appliances} — {obj.management_station} / {obj.name}"


def appliance_group_note_choice_queryset():
    """Appliance groups ordered for the note picker: in-scope groups first (a group is
    in scope if any of its enforcement points is), then by active appliance name.

    Active appliance name is COALESCE(hostname or NULL, serial_number); groups without an
    active appliance sort last within their scope bucket.
    """
    in_scope = EnforcementPoint.objects.filter(appliance_group=OuterRef("pk"), in_scope=True)
    active_name = Coalesce(
        NullIf("active_appliance__hostname", Value("")),
        "active_appliance__serial_number",
    )
    return (
        ApplianceGroup.objects.select_related("management_station", "active_appliance")
        .prefetch_related("appliances")
        .annotate(_in_scope=Exists(in_scope), _active_name=active_name)
        .order_by("-_in_scope", F("_active_name").asc(nulls_last=True), "name")
    )


class NoteForm(forms.ModelForm):
    appliance_group = ApplianceGroupChoiceField(
        queryset=appliance_group_note_choice_queryset(),
        widget=forms.Select(attrs={"class": SELECT_CLASS}),
        label="Appliance group",
    )

    field_order = ["appliance_group", "body"]

    class Meta:
        model = Note
        fields = ["body"]
        labels = {"body": "Note"}
        widgets = {
            "body": forms.Textarea(attrs={"class": TEXTAREA_CLASS, "rows": 8}),
        }
