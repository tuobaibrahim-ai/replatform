"""طبقة التكامل الخارجي: كتالوج، عميل HTTP آمن، وموصلات قراءة فقط."""

from __future__ import annotations

from .catalog import (
    CONNECTORS,
    RESOURCES,
    Connector,
    Resource,
    get_connector,
    list_connectors,
    list_resources,
)
from .http import DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT, IntegrationError, SafeHTTPClient

__all__ = [
    "CONNECTORS",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_TIMEOUT",
    "RESOURCES",
    "Connector",
    "IntegrationError",
    "Resource",
    "SafeHTTPClient",
    "get_connector",
    "list_connectors",
    "list_resources",
]
