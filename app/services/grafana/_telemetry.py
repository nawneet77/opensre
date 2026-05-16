"""Shared Sentry capture helper for the Grafana service stack.

Used at boundaries where each Grafana mixin swallows an upstream failure
into a degraded return value (empty list, ``{"success": False, ...}`` dict).
The helper keeps the Sentry tag shape identical across all files so
dashboards can pivot on (surface, integration, component, method).
"""

from __future__ import annotations

import logging
from typing import Any

from app.utils.errors import report_exception


def report_grafana_failure(
    exc: BaseException,
    *,
    logger: logging.Logger,
    component: str,
    method: str,
    severity: str = "warning",
    datasource_uid: str | None = None,
    extras: dict[str, Any] | None = None,
) -> None:
    """Capture a swallowed Grafana stack failure to Sentry + logs.

    Args:
        exc: The exception being swallowed.
        logger: The caller module's logger.
        component: Dotted module path, e.g. ``app.services.grafana.loki``.
        method: Name of the method that failed, e.g. ``query_loki``.
        severity: ``warning`` (default) for expected vendor failures,
            ``error`` for unexpected ones.
        datasource_uid: The Grafana datasource UID involved, when relevant.
            Only set when present to keep tag cardinality bounded.
        extras: Additional Sentry ``extra`` payload (e.g. query parameters).
    """
    tags = {
        "surface": "service_client",
        "integration": "grafana",
        "component": component,
        "method": method,
    }
    if datasource_uid is not None:
        tags["datasource_uid"] = datasource_uid

    report_exception(
        exc,
        logger=logger,
        message=f"[grafana] {method} failed",
        severity=severity,
        tags=tags,
        extras=extras,
    )
