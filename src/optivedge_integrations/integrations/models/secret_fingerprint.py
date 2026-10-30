"""The per-station key an equality-group id is computed with - the only key material this
package generates, rather than collects from a device.

WHY IT EXISTS. A shared secret's VALUE is never stored - Jason's standing ruling, and the shipped
precedents are `models/ike.py::IkeGateway` ("THE PRE-SHARED KEY'S VALUE IS NEVER STORED... No
column holds the ciphertext") and `models/device_services.py::SnmpSettings` ("THE COMMUNITY STRING
IS NOT STORED"). The one question PAN-AAA-005 asks of a RADIUS secret is whether two server
entries hold the SAME one, and an equality-group id answers that exactly as well as the value
does: equal secrets map to equal ids and the id is not the secret.

WHY A KEY AND NOT A BARE HASH. PAN-OS's stored form is `-AQ==` + base64(unsalted SHA-1 of the
plaintext) + base64(ciphertext), so the first 33 characters are derivable from a GUESSED plaintext
with no device key at all. A plain digest of that form is therefore brute-forceable from a word
list. The digest needs a secret the secret itself does not supply - and it has to be the SAME one
across the estate, or two appliances holding one secret stop comparing equal, which is the whole
reading the column exists for. One random value per management station satisfies both.

WHAT THIS DOES AND DOES NOT PROTECT, stated because a key in the same database as the digests is
easy to over-read. It protects the digest everywhere the digest TRAVELS WITHOUT IT - a finding, a
workbook, a report, a log line, a support bundle, a copied table. It does NOT protect against
somebody holding this whole database, who has both halves and can run the same word list. The
stronger arrangement is a key the HOST project supplies and this package never stores; that is a
deployment decision rather than a normalisation one, and this model is where a reference to such a
key would go.
"""

from __future__ import annotations

import secrets

from django.db import models


class SecretFingerprintKey(models.Model):
    """One key per management station, generated once and never rotated by this package.

    ROTATION IS A RE-NORMALISATION, not a migration: every equality-group id already stored was
    computed with the old key, so a new key makes an old row and a new row compare unequal when
    the secrets are identical. Nothing here rotates it for that reason; a rotation has to be
    followed by a collection pass over every appliance of the station.
    """

    #: 32 bytes from `secrets.token_bytes`, stored as hex so it is inspectable and so no backend
    #: returns it as a memoryview. It is key material: do not render it, log it or export it.
    KEY_BYTES = 32

    management_station = models.OneToOneField(
        "integrations.ManagementStation", on_delete=models.CASCADE,
        related_name="secret_fingerprint_key")
    key_hex = models.CharField(max_length=2 * KEY_BYTES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "secret fingerprint key"
        verbose_name_plural = "secret fingerprint keys"

    @classmethod
    def key_for(cls, management_station) -> bytes:
        """The station's key, generated on first use. Same bytes for every appliance it owns.

        `get_or_create` rather than a check-then-create, because two appliances of one station
        are normalised in one pass and a second key would silently split the estate's equality
        groups in two.
        """
        row, _ = cls.objects.get_or_create(
            management_station=management_station,
            defaults={"key_hex": secrets.token_bytes(cls.KEY_BYTES).hex()})
        return bytes.fromhex(row.key_hex)

    def __str__(self) -> str:
        return f"{self.management_station} secret fingerprint key"
