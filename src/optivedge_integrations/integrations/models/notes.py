"""User-authored notes attachable to tracked objects via a generic relation."""

from __future__ import annotations

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models


class Note(models.Model):
    """A free-text note attached to a target object (currently appliance groups).

    Uses a generic relation so additional object types can be annotated later with no
    schema change. Deliberately not a SyncTrackedModel: notes are user-authored and must
    persist across syncs. That is safe because notes target objects whose PKs are stable
    across re-sync (appliance groups are upserted via get_or_create, not deleted and
    recreated); a target that is genuinely removed cascades its notes away via the
    GenericRelation on that model.
    """

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    target = GenericForeignKey("content_type", "object_id")

    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-id"]
        indexes = [
            models.Index(fields=["content_type", "object_id"]),
        ]

    def __str__(self) -> str:
        return f"Note #{self.pk} on {self.content_type} #{self.object_id}"
