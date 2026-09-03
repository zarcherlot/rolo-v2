"""Controlled-vault boundary for HMAC secrets.

The RKB package never persists secret bytes. Deployments provide a resolver
backed by their secret manager and receive an ephemeral :class:`HMACKeyring`.
"""

from __future__ import annotations

from collections.abc import Callable

from .keyring import HMACKeyring


def keyring_from_vault(resolve: Callable[[str], bytes], key_ids: list[str]) -> HMACKeyring:
    ring = HMACKeyring()
    for key_id in key_ids:
        ring.rotate(key_id, resolve(key_id))
    return ring
