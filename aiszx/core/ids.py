"""Identifier helpers."""

import uuid


def new_id() -> str:
    """Random, collision-resistant identifier for database rows."""
    return uuid.uuid4().hex
