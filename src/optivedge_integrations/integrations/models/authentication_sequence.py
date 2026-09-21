"""Authentication sequences - PAN-AAA-012's subject.

An ordered list of authentication profiles the firewall tries top to bottom until one succeeds.
Definable in `shared` and under a vsys - measured 2026-09-11, the same four children in both -
so it carries the scope column the authentication profiles do.
"""

from __future__ import annotations

from django.db import models

from .base import ApplianceScopedObject


class AuthenticationSequence(ApplianceScopedObject):
    """One authentication sequence, in the scope it was defined in.

    A sequence is offered at EVERY administrative binding - per-account and both device-wide
    leaves - and at captive portal, measured 2026-09-11 by eligibility-filtered completion. The
    device-wide bindings refuse a local-database PROFILE but accept a sequence CONTAINING one, so a
    sequence is how a device-wide binding can end in a local check.

    The Help (p.843) recommends exactly the shape PAN-AAA-012 reports: "Make the local
    authentication profile the last profile in the sequence so it's only used if all external
    authentication methods fail." The corpus excepts documented break-glass; that is the
    consultant's call, and this model only records whether a local path exists.
    """

    #: Computed here: methods resolved through the member profiles, and filtered subsets - `member_names` is the payload's own list and is deliberately not here. See ProvenancedMixin.DERIVED_FIELDS.
    DERIVED_FIELDS = (
        "is_missing",
        "member_count",
        "member_methods",
        "local_member_names",
        "has_local_member",
        "unresolved_member_count",
        "all_members_external",
        "referrer_paths",
        "referrer_count",
        "is_administrative",
    )

    #: Profile names, in the order the firewall tries them. Order is the meaning: the same two
    #: members the other way round put the local check FIRST.
    member_names = models.JSONField(default=list, blank=True)
    member_count = models.PositiveIntegerField(default=0)
    #: Each member's resolved `method`, parallel to `member_names`; "" where the name resolves to
    #: no profile on this appliance. Display only - the columns below are what controls read.
    member_methods = models.JSONField(default=list, blank=True)
    #: Members whose method is `local-database` or `none` - the firewall itself, not an
    #: authority off the box. Display only.
    local_member_names = models.JSONField(default=list, blank=True)
    #: PAN-AAA-012's first half. A column rather than a JSON lookup, for the reason every
    #: finding rests on one: a JSON lookup matches nothing the day a key is renamed.
    has_local_member = models.BooleanField(default=False)
    #: Members naming no profile on this appliance. Not assumed external - an unresolvable
    #: member proves nothing about where the credential is checked.
    unresolved_member_count = models.PositiveIntegerField(default=0)
    #: Every member resolved and every method external. What an administrator bound to this
    #: sequence needs for PAN-AUTH-019's first half; false for an empty sequence.
    all_members_external = models.BooleanField(default=False)

    #: Implicit NO - measured 2026-09-11: the device stores none of these three flags unless the
    #: form sets them, and the committed sequence and the empty Add form render the same.
    exit_sequence_on_failure = models.BooleanField(default=False)
    #: Implicit YES. The Help's "enabled by default" (p.844) agrees with the rendered form.
    use_domain_find_profile = models.BooleanField(default=True)
    #: Implicit NO.
    use_userid_domain = models.BooleanField(default=False)

    #: Every place on this appliance that names this sequence, from the same whole-payload walk
    #: the authentication profiles use - an unused claim is only as good as its hiding places.
    referrer_paths = models.JSONField(default=list, blank=True)
    referrer_count = models.PositiveIntegerField(default=0)
    #: PAN-AAA-012's scoping clause: something under `mgt-config/users` or `deviceconfig/system`
    #: names it. The same derivation, and the same ruling, as `AuthenticationProfile`'s.
    is_administrative = models.BooleanField(default=False)

    class Meta:
        ordering = ["management_station__hostname", "appliance__hostname", "scope",
                    "vsys_name", "name"]
        indexes = [
            models.Index(fields=["appliance", "scope"]),
            models.Index(fields=["name"]),
            models.Index(fields=["is_administrative"]),
            models.Index(fields=["has_local_member"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["appliance", "scope", "vsys_name", "name"],
                name="unique_authentication_sequence_per_scope"),
        ]
