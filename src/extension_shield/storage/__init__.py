"""
Storage adapters for ExtensionShield.

Provides a ScanStore interface with two implementations:
  - SQLiteStore  (OSS default, zero-config)
  - SupabaseStore (Cloud mode, production)

Use get_store() to get the correct backend based on EXTSHIELD_MODE / DB_BACKEND.
"""

from extension_shield.storage.base import ScanStore

__all__ = ["ScanStore"]
