"""THROWAWAY diagnostic command - delete once the security-rules address-column bug is found.

Samples SecurityRuleSourceAddressRef/SecurityRuleDestinationAddressRef rows for rules whose
source/destination address columns render "-" in the /security-rules/ list, to compare against
the ref_type/raw_value/FK shape expected by listed_address_ref_values() in presentation.py.
"""

from django.core.management.base import BaseCommand

from optivedge_integrations.integrations.models import SecurityRule


class Command(BaseCommand):
    help = "THROWAWAY: dump source/destination address ref data for a sample of security rules."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=10,
            help="Number of rules to sample (default: 10).",
        )
        parser.add_argument(
            "--non-region-only",
            action="store_true",
            help="Only sample rules that have at least one non-region source address ref "
            "(i.e. the ref types reported as showing '-').",
        )

    def handle(self, *args, **options):
        limit = options["limit"]
        non_region_only = options["non_region_only"]

        queryset = SecurityRule.objects.prefetch_related(
            "source_address_refs",
            "destination_address_refs",
        )
        if non_region_only:
            queryset = queryset.exclude(source_address_refs__ref_type="region")

        rules = queryset.order_by("pk")[:limit]

        count = 0
        for rule in rules:
            count += 1
            self.stdout.write(f"--- {rule.name} (pk={rule.pk}) ---")
            for ref in rule.source_address_refs.all():
                self.stdout.write(
                    f"  SOURCE ref_type={ref.ref_type!r} raw_value={ref.raw_value!r} "
                    f"position={ref.position} address_object_id={ref.address_object_id} "
                    f"address_group_id={ref.address_group_id} region_id={ref.region_id}"
                )
            for ref in rule.destination_address_refs.all():
                self.stdout.write(
                    f"  DEST   ref_type={ref.ref_type!r} raw_value={ref.raw_value!r} "
                    f"position={ref.position} address_object_id={ref.address_object_id} "
                    f"address_group_id={ref.address_group_id} region_id={ref.region_id}"
                )

        if count == 0:
            self.stdout.write(self.style.WARNING("No matching security rules found."))
