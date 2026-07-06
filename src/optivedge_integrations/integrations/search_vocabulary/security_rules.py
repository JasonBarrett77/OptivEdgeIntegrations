"""Rebuild helpers for security-rule search-grounding vocabulary."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    ManagementStation,
    SecurityRuleApplication,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSearchVocabularyEntry,
    SecurityRuleService,
    SecurityRuleSourceAddressRef,
)


@dataclass(slots=True)
class _VocabularyAccumulator:
    rule_ids: set[int]
    usage_count: int = 0

    def add(self, security_rule_id: int) -> None:
        self.rule_ids.add(security_rule_id)
        self.usage_count += 1


@dataclass(slots=True)
class SecurityRuleSearchVocabularyRebuildResult:
    management_station: ManagementStation
    deleted_entry_count: int
    created_entry_count: int
    source_address_name_count: int
    destination_address_name_count: int
    application_count: int
    service_count: int


def rebuild_all_security_rule_search_vocabulary() -> list[SecurityRuleSearchVocabularyRebuildResult]:
    """Rebuild security-rule vocabulary entries for every management station."""

    results: list[SecurityRuleSearchVocabularyRebuildResult] = []
    for management_station in ManagementStation.objects.order_by("hostname", "pk"):
        results.append(rebuild_security_rule_search_vocabulary(management_station))
    return results


def rebuild_security_rule_search_vocabulary(
    management_station: ManagementStation,
) -> SecurityRuleSearchVocabularyRebuildResult:
    """Rebuild security-rule vocabulary entries for one management station."""

    field_accumulators = _build_field_accumulators(management_station)
    created_entries = _build_vocabulary_entries(management_station, field_accumulators)
    current_time = timezone.now()
    for entry in created_entries:
        entry.last_synced_at = current_time

    with transaction.atomic():
        deleted_entry_count, _ = SecurityRuleSearchVocabularyEntry.objects.filter(
            management_station=management_station,
        ).delete()
        SecurityRuleSearchVocabularyEntry.objects.bulk_create(created_entries)

    return SecurityRuleSearchVocabularyRebuildResult(
        management_station=management_station,
        deleted_entry_count=deleted_entry_count,
        created_entry_count=len(created_entries),
        source_address_name_count=len(
            field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.SOURCE_ADDRESS_NAME]
        ),
        destination_address_name_count=len(
            field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.DESTINATION_ADDRESS_NAME]
        ),
        application_count=len(
            field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION]
        ),
        service_count=len(
            field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.SERVICE]
        ),
    )


def _build_field_accumulators(
    management_station: ManagementStation,
) -> dict[str, dict[str, _VocabularyAccumulator]]:
    field_accumulators: dict[str, dict[str, _VocabularyAccumulator]] = {
        field_family: defaultdict(lambda: _VocabularyAccumulator(rule_ids=set()))
        for field_family in SecurityRuleSearchVocabularyEntry.FieldFamily.values
    }

    _accumulate_address_ref_values(
        field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.SOURCE_ADDRESS_NAME],
        SecurityRuleSourceAddressRef.objects.filter(
            security_rule__management_station=management_station,
        ).select_related("address_object", "address_group"),
    )
    _accumulate_address_ref_values(
        field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.DESTINATION_ADDRESS_NAME],
        SecurityRuleDestinationAddressRef.objects.filter(
            security_rule__management_station=management_station,
        ).select_related("address_object", "address_group"),
    )
    _accumulate_repeated_values(
        field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION],
        SecurityRuleApplication.objects.filter(
            security_rule__management_station=management_station,
        ),
    )
    _accumulate_repeated_values(
        field_accumulators[SecurityRuleSearchVocabularyEntry.FieldFamily.SERVICE],
        SecurityRuleService.objects.filter(
            security_rule__management_station=management_station,
        ),
    )
    return field_accumulators


def _accumulate_address_ref_values(
    accumulator_by_value: dict[str, _VocabularyAccumulator],
    queryset,
) -> None:
    for address_ref in queryset.iterator():
        for candidate_value in (
            address_ref.raw_value,
            getattr(address_ref.address_object, "name", ""),
            getattr(address_ref.address_group, "name", ""),
        ):
            _add_vocabulary_value(
                accumulator_by_value,
                candidate_value,
                security_rule_id=address_ref.security_rule_id,
            )


def _accumulate_repeated_values(
    accumulator_by_value: dict[str, _VocabularyAccumulator],
    queryset,
) -> None:
    for repeated_value in queryset.iterator():
        _add_vocabulary_value(
            accumulator_by_value,
            repeated_value.value,
            security_rule_id=repeated_value.security_rule_id,
        )


def _add_vocabulary_value(
    accumulator_by_value: dict[str, _VocabularyAccumulator],
    candidate_value: str,
    *,
    security_rule_id: int,
) -> None:
    trimmed_value = candidate_value.strip()
    if not trimmed_value:
        return
    accumulator_by_value[trimmed_value].add(security_rule_id)


def _build_vocabulary_entries(
    management_station: ManagementStation,
    field_accumulators: dict[str, dict[str, _VocabularyAccumulator]],
) -> list[SecurityRuleSearchVocabularyEntry]:
    entries: list[SecurityRuleSearchVocabularyEntry] = []
    for field_family, accumulator_by_value in field_accumulators.items():
        ordered_values = sorted(
            accumulator_by_value.items(),
            key=lambda item: (-len(item[1].rule_ids), -item[1].usage_count, item[0]),
        )
        for canonical_value, accumulator in ordered_values:
            entries.append(
                SecurityRuleSearchVocabularyEntry(
                    management_station=management_station,
                    field_family=field_family,
                    canonical_value=canonical_value,
                    normalized_value=SecurityRuleSearchVocabularyEntry.normalize_lookup_value(canonical_value),
                    compact_value=SecurityRuleSearchVocabularyEntry.compact_lookup_value(canonical_value),
                    rule_count=len(accumulator.rule_ids),
                    usage_count=accumulator.usage_count,
                )
            )
    return entries
