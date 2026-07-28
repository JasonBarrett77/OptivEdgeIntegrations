"""THROWAWAY diagnostic command - delete once the security-rules address-column bug is fully understood.

For each matched SecurityRule, prints:
  - the exact raw_rule["source"]/["destination"] this specific row was normalized from
    (raw_rule is the per-row snapshot of the config dict passed into normalize_rule() -
    comparing against it avoids any ambiguity from a rule name appearing more than once
    across config_source variants, e.g. local vs. pushed-pre vs. pushed-post vs. default)
  - the persisted SecurityRuleSourceAddressRef/SecurityRuleDestinationAddressRef rows for that row

The goal: find a rule where raw_rule shows real source/destination members but the persisted ref
rows are still empty, to prove/disprove a bug beyond the "element entirely absent" case already
fixed (which only explains rows where raw_rule.get("source")/("destination") is itself None/empty).
"""

import json

from django.core.management.base import BaseCommand

from optivedge_integrations.integrations.models import SecurityRule


class Command(BaseCommand):
    help = "THROWAWAY: compare raw_rule source/destination against persisted address refs."

    def add_arguments(self, parser):
        parser.add_argument("--pk", type=int, action="append", default=None, help="Specific rule pk(s).")
        parser.add_argument("--name", type=str, default=None, help="Filter by rule name (icontains).")
        parser.add_argument("--limit", type=int, default=25)
        parser.add_argument(
            "--mismatches-only",
            action="store_true",
            help="Only print rules where raw_rule has real source/destination members "
            "but zero persisted refs exist on that side.",
        )

    def handle(self, *args, **options):
        queryset = SecurityRule.objects.select_related("source_snapshot").prefetch_related(
            "source_address_refs", "destination_address_refs"
        ).order_by("pk")

        if options["pk"]:
            queryset = queryset.filter(pk__in=options["pk"])
        elif options["name"]:
            queryset = queryset.filter(name__icontains=options["name"])
        else:
            queryset = queryset[: options["limit"]]

        count = 0
        for rule in queryset:
            source_refs = list(rule.source_address_refs.all())
            destination_refs = list(rule.destination_address_refs.all())
            raw_source = rule.raw_rule.get("source") if isinstance(rule.raw_rule, dict) else None
            raw_destination = rule.raw_rule.get("destination") if isinstance(rule.raw_rule, dict) else None

            source_mismatch = bool(raw_source) and not source_refs
            destination_mismatch = bool(raw_destination) and not destination_refs

            if options["mismatches_only"] and not (source_mismatch or destination_mismatch):
                continue

            count += 1
            self.stdout.write(
                f"--- {rule.name!r} (pk={rule.pk}, config_source={rule.config_source!r}, "
                f"rule_position={rule.rule_position}, enforcement_point_id={rule.enforcement_point_id}, "
                f"last_synced_at={rule.last_synced_at.isoformat() if rule.last_synced_at else None}, "
                f"source_snapshot_collected_at="
                f"{rule.source_snapshot.collected_at.isoformat() if rule.source_snapshot_id else None}) ---"
            )
            self.stdout.write(f"  raw_rule['source']      = {json.dumps(raw_source)}")
            self.stdout.write(f"  raw_rule['destination'] = {json.dumps(raw_destination)}")
            self.stdout.write(
                f"  source_ref_count={len(source_refs)} destination_ref_count={len(destination_refs)}"
            )
            for ref in source_refs:
                self.stdout.write(f"    SRC ref_type={ref.ref_type!r} raw_value={ref.raw_value!r}")
            for ref in destination_refs:
                self.stdout.write(f"    DST ref_type={ref.ref_type!r} raw_value={ref.raw_value!r}")
            if source_mismatch:
                self.stdout.write(self.style.ERROR("  MISMATCH: real source members but zero source refs"))
            if destination_mismatch:
                self.stdout.write(
                    self.style.ERROR("  MISMATCH: real destination members but zero destination refs")
                )

        if count == 0:
            self.stdout.write(self.style.WARNING("No matching security rules found."))
