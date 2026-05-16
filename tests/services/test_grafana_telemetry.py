"""Unit tests for app.services.grafana._telemetry.report_grafana_failure.

Covers the standard tag shape, optional datasource_uid omission to keep tag
cardinality bounded, severity override, and the logger + Sentry side-effects
forwarded to app.utils.errors.report_exception.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

from app.services.grafana._telemetry import report_grafana_failure


def _call(exc: Exception, **kwargs: object) -> object:
    """Invoke report_grafana_failure with report_exception patched."""
    with patch("app.services.grafana._telemetry.report_exception") as mock_report:
        report_grafana_failure(exc, **kwargs)  # type: ignore[arg-type]
    return mock_report


class TestReportGrafanaFailureTags:
    """Standard tag shape across all callers."""

    def test_minimum_tags_when_datasource_uid_absent(self) -> None:
        logger = logging.getLogger("test")
        exc = RuntimeError("boom")

        mock_report = _call(
            exc,
            logger=logger,
            component="app.services.grafana.loki",
            method="query_loki",
        )

        mock_report.assert_called_once()  # type: ignore[attr-defined]
        kwargs = mock_report.call_args.kwargs  # type: ignore[attr-defined]
        assert kwargs["tags"] == {
            "surface": "service_client",
            "integration": "grafana",
            "component": "app.services.grafana.loki",
            "method": "query_loki",
        }

    def test_datasource_uid_added_only_when_present(self) -> None:
        logger = logging.getLogger("test")
        exc = RuntimeError("boom")

        mock_report = _call(
            exc,
            logger=logger,
            component="app.services.grafana.mimir",
            method="query_mimir",
            datasource_uid="mimir-uid-1",
        )

        tags = mock_report.call_args.kwargs["tags"]  # type: ignore[attr-defined]
        assert tags["datasource_uid"] == "mimir-uid-1"

    def test_extras_forwarded(self) -> None:
        logger = logging.getLogger("test")
        exc = RuntimeError("boom")

        mock_report = _call(
            exc,
            logger=logger,
            component="app.services.grafana.base",
            method="query_loki_label_values",
            extras={"label": "service_name"},
        )

        assert mock_report.call_args.kwargs["extras"] == {"label": "service_name"}  # type: ignore[attr-defined]


class TestReportGrafanaFailureSeverity:
    """Severity defaults to warning; callers can promote to error."""

    def test_default_severity_is_warning(self) -> None:
        logger = logging.getLogger("test")
        exc = RuntimeError("boom")

        mock_report = _call(
            exc,
            logger=logger,
            component="app.services.grafana.tempo",
            method="query_tempo",
        )

        assert mock_report.call_args.kwargs["severity"] == "warning"  # type: ignore[attr-defined]

    def test_severity_override_propagates(self) -> None:
        logger = logging.getLogger("test")
        exc = RuntimeError("boom")

        mock_report = _call(
            exc,
            logger=logger,
            component="app.services.grafana.tempo",
            method="query_tempo",
            severity="error",
        )

        assert mock_report.call_args.kwargs["severity"] == "error"  # type: ignore[attr-defined]


class TestReportGrafanaFailureForwarding:
    """The helper forwards exc + logger + a method-derived message."""

    def test_message_includes_method_name(self) -> None:
        logger = logging.getLogger("test")
        exc = RuntimeError("boom")

        mock_report = _call(
            exc,
            logger=logger,
            component="app.services.grafana.base",
            method="discover_datasource_uids",
        )

        message = mock_report.call_args.kwargs["message"]  # type: ignore[attr-defined]
        assert "discover_datasource_uids" in message
        assert "grafana" in message.lower()

    def test_exception_passed_positionally(self) -> None:
        logger = logging.getLogger("test")
        exc = RuntimeError("boom")

        mock_report = _call(
            exc,
            logger=logger,
            component="app.services.grafana.loki",
            method="query_loki",
        )

        assert mock_report.call_args.args[0] is exc  # type: ignore[attr-defined]
        assert mock_report.call_args.kwargs["logger"] is logger  # type: ignore[attr-defined]
