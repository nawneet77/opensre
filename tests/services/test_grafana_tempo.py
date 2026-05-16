"""Unit tests for the Grafana Tempo mixin."""

from __future__ import annotations

from unittest.mock import Mock, patch

from app.services.grafana.tempo import TempoMixin


class FakeGrafanaClient(TempoMixin):
    """Fake Grafana client to test the TempoMixin."""

    def __init__(self, is_configured: bool = True):
        self.is_configured = is_configured
        self.account_id = "test-account-123"
        self.tempo_datasource_uid = "tempo-uid-abc"

    def _build_datasource_url(self, uid: str, path: str) -> str:
        return f"https://grafana.fake/api/datasources/uid/{uid}{path}"

    def _make_request(self, url: str, params: dict | None = None) -> dict:
        del url, params
        # To be mocked in tests
        return {}

    def _get_auth_headers(self) -> dict:
        return {"Authorization": "Bearer fake-token"}


class TestTempoMixin:
    """Tests for the Tempo trace query capabilities."""

    def test_query_tempo_not_configured(self):
        """Test behavior when the client is not configured."""
        client = FakeGrafanaClient(is_configured=False)
        result = client.query_tempo(service_name="auth-service")

        assert result["success"] is False
        assert "not configured for account" in result["error"]
        assert result["traces"] == []

    def test_query_tempo_general_exception(self):
        """Test general exception handling during a query."""
        client = FakeGrafanaClient()
        client._make_request = Mock(side_effect=Exception("Connection timeout"))

        with patch("app.services.grafana.tempo.report_grafana_failure") as mock_report:
            result = client.query_tempo(service_name="auth-service")

        assert result["success"] is False
        assert result["error"] == "Connection timeout"
        assert result["response"] == ""
        assert result["traces"] == []
        mock_report.assert_called_once()
        kwargs = mock_report.call_args.kwargs
        assert kwargs["component"] == "app.services.grafana.tempo"
        assert kwargs["method"] == "query_tempo"
        assert kwargs["datasource_uid"] == "tempo-uid-abc"

    def test_query_tempo_http_exception_with_response(self):
        """Test exception handling when the exception contains a response object."""
        client = FakeGrafanaClient()

        class MockResponse:
            status_code = 403
            text = "Permission denied for this datasource"

        class MockException(Exception):
            response = MockResponse()

        client._make_request = Mock(side_effect=MockException("HTTP Error"))

        with patch("app.services.grafana.tempo.report_grafana_failure") as mock_report:
            result = client.query_tempo(service_name="auth-service")

        assert result["success"] is False
        assert result["error"] == "Tempo query failed: 403"
        assert "Permission denied" in result["response"]
        mock_report.assert_called_once()

    @patch("app.services.grafana.tempo.requests.get")
    def test_query_tempo_successful_trace_parsing(self, mock_requests_get):
        """Test a successful trace query and the subsequent span parsing."""
        client = FakeGrafanaClient()

        # Mock the search response (from self._make_request)
        client._make_request = Mock(
            return_value={
                "traces": [
                    {
                        "traceID": "trace-123",
                        "rootServiceName": "auth-service",
                        "durationMs": 150,
                        "spanCount": 2,
                    }
                ]
            }
        )

        # Mock the trace details response (from requests.get in _get_trace_details)
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "batches": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": "DB Query",
                                    "attributes": [
                                        {
                                            "key": "db.system",
                                            "value": {"stringValue": "postgresql"},
                                        },
                                        {"key": "http.status_code", "value": {"intValue": 200}},
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        mock_requests_get.return_value = mock_response

        # Execute
        result = client.query_tempo(service_name="auth-service")

        # Assert Search result parsing
        assert result["success"] is True
        assert result["total_traces"] == 1
        assert result["service_name"] == "auth-service"
        assert len(result["traces"]) == 1

        # Assert enriched trace structure
        enriched_trace = result["traces"][0]
        assert enriched_trace["trace_id"] == "trace-123"
        assert enriched_trace["root_service"] == "auth-service"
        assert enriched_trace["duration_ms"] == 150
        assert enriched_trace["span_count"] == 2

        # Assert span parsing and attribute extraction
        assert len(enriched_trace["spans"]) == 1
        span = enriched_trace["spans"][0]
        assert span["name"] == "DB Query"
        assert span["attributes"]["db.system"] == "postgresql"
        assert span["attributes"]["http.status_code"] == 200

    @patch("app.services.grafana.tempo.report_grafana_failure")
    @patch("app.services.grafana.tempo.requests.get")
    def test_get_trace_details_network_failure(self, mock_requests_get, mock_report):
        """Test _get_trace_details graceful degradation on network error."""
        client = FakeGrafanaClient()
        mock_requests_get.side_effect = Exception("Requests connection error")

        result = client._get_trace_details(trace_id="trace-123")

        # Should catch the error and return empty spans gracefully + capture to Sentry
        assert result == {"spans": []}
        mock_report.assert_called_once()
        kwargs = mock_report.call_args.kwargs
        assert kwargs["component"] == "app.services.grafana.tempo"
        assert kwargs["method"] == "_get_trace_details"
        assert kwargs["extras"] == {"trace_id": "trace-123"}

    def test_extract_span_attributes_edge_cases(self):
        """Test extraction of various attribute types."""
        client = FakeGrafanaClient()

        mock_span = {
            "attributes": [
                {"key": "valid_string", "value": {"stringValue": "test"}},
                {"key": "valid_int", "value": {"intValue": 42}},
                {"key": "unsupported_type", "value": {"boolValue": True}},
                {"key": "empty_value", "value": {}},
                {"value": {"stringValue": "missing_key"}},  # Should be skipped!
            ]
        }

        attributes = client._extract_span_attributes(mock_span)

        assert attributes.get("valid_string") == "test"
        assert attributes.get("valid_int") == 42
        assert "unsupported_type" not in attributes
        assert "empty_value" not in attributes
        assert "" not in attributes

    @patch("app.services.grafana.tempo.report_grafana_failure")
    @patch("app.services.grafana.tempo.requests.get")
    def test_get_trace_details_non_200_status(self, mock_requests_get, mock_report):
        """Test _get_trace_details when the API returns a non-200 status.

        After issue #1461 the non-200 path is routed through raise_for_status,
        so it now reports to Sentry instead of failing silently.
        """
        import requests as requests_module

        client = FakeGrafanaClient()

        # Setup mock to raise HTTPError on raise_for_status (real requests behavior on non-200)
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests_module.HTTPError(
            "404 Not Found",
            response=mock_response,
        )
        mock_requests_get.return_value = mock_response

        result = client._get_trace_details(trace_id="trace-123")

        # Assert it safely falls back to empty spans AND captured the non-200 to Sentry
        assert result == {"spans": []}
        mock_report.assert_called_once()
        kwargs = mock_report.call_args.kwargs
        assert kwargs["component"] == "app.services.grafana.tempo"
        assert kwargs["method"] == "_get_trace_details"

    @patch("app.services.grafana.tempo.report_grafana_failure")
    @patch("app.services.grafana.tempo.requests.get")
    def test_get_trace_details_with_failures_out_defers_capture(
        self, mock_requests_get, mock_report
    ):
        """When failures_out is provided, the per-call Sentry capture is
        skipped and the trace_id is appended for batch-level reporting."""
        client = FakeGrafanaClient()
        mock_requests_get.side_effect = Exception("Connection refused")

        collected: list[str] = []
        result = client._get_trace_details(trace_id="trace-zzz", failures_out=collected)

        assert result == {"spans": []}
        assert collected == ["trace-zzz"]
        mock_report.assert_not_called()

    @patch("app.services.grafana.tempo.report_grafana_failure")
    def test_query_tempo_aggregates_per_trace_failures_into_one_event(
        self, mock_report
    ):
        """Multiple failed _get_trace_details lookups inside one query_tempo
        call must coalesce into a single Sentry event so a degraded Tempo
        endpoint doesn't fan out into N events per query."""
        client = FakeGrafanaClient()
        client._make_request = Mock(
            return_value={
                "traces": [
                    {"traceID": "trace-a", "rootServiceName": "auth", "durationMs": 1},
                    {"traceID": "trace-b", "rootServiceName": "auth", "durationMs": 2},
                    {"traceID": "trace-c", "rootServiceName": "auth", "durationMs": 3},
                ]
            }
        )

        with patch(
            "app.services.grafana.tempo.requests.get",
            side_effect=Exception("Tempo degraded"),
        ):
            result = client.query_tempo(service_name="auth-service")

        # Search succeeded, but every detail lookup failed
        assert result["success"] is True
        assert result["total_traces"] == 3
        for enriched in result["traces"]:
            assert enriched["spans"] == []

        # Exactly one aggregated Sentry event for all three failures
        mock_report.assert_called_once()
        kwargs = mock_report.call_args.kwargs
        assert kwargs["component"] == "app.services.grafana.tempo"
        assert kwargs["method"] == "_get_trace_details_batch"
        assert kwargs["extras"]["failed_count"] == 3
        assert kwargs["extras"]["total_count"] == 3
        assert kwargs["extras"]["first_failed_trace_id"] == "trace-a"
