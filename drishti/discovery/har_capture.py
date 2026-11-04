"""HAR trace exporter and observation converter for browser crawler observations.

Transforms raw, role-attributed BrowserObservation objects into sanitized HAR 1.2
archives and EndpointObservation instances for seamless ingestion into EndpointNormalizer.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from drishti.discovery.crawler_models import BrowserObservation
from drishti.discovery.models import EndpointObservation


class HarCaptureExporter:
    """Exports and transforms browser crawl observations into sanitized HAR 1.2 format."""

    def __init__(self, creator_name: str = "Drishti-AI-Crawler", creator_version: str = "1.0"):
        self.creator_name = creator_name
        self.creator_version = creator_version

    def observations_to_har_dict(
        self,
        observations: List[BrowserObservation],
        title: str = "Drishti Crawl Capture",
    ) -> Dict[str, Any]:
        """Converts a list of BrowserObservations into a valid, sanitized HAR 1.2 dictionary."""
        entries = []
        for obs in observations:
            parsed = urlparse(obs.url)
            query_params = [
                {"name": k, "value": v}
                for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            ]

            req_headers = [
                {"name": k, "value": v}
                for k, v in obs.request_headers.items()
            ]

            resp_headers = [
                {"name": k, "value": v}
                for k, v in obs.response_headers.items()
            ]

            post_data = None
            if obs.request_body:
                post_data = {
                    "mimeType": obs.request_headers.get("content-type", "application/json"),
                    "text": obs.request_body,
                }

            resp_content = {
                "size": len(obs.response_body.encode("utf-8")) if obs.response_body else 0,
                "mimeType": obs.response_headers.get("content-type", "application/json"),
                "text": obs.response_body or "",
            }

            entry = {
                "startedDateTime": obs.timestamp,
                "time": obs.latency_ms,
                "request": {
                    "method": obs.method,
                    "url": obs.url,
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": req_headers,
                    "queryString": query_params,
                    "postData": post_data,
                    "headersSize": -1,
                    "bodySize": len(obs.request_body.encode("utf-8")) if obs.request_body else 0,
                    "comment": f"role={obs.role_name};tenant={obs.tenant_id}",
                },
                "response": {
                    "status": obs.status_code,
                    "statusText": "OK" if obs.status_code < 400 else "Error",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": resp_headers,
                    "content": resp_content,
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": resp_content["size"],
                },
                "cache": {},
                "timings": {
                    "send": 1,
                    "wait": max(obs.latency_ms - 2, 1),
                    "receive": 1,
                },
                "_role": obs.role_name,
                "_tenant_id": obs.tenant_id,
                "_journey_step": obs.journey_step_id,
            }
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": self.creator_name,
                    "version": self.creator_version,
                },
                "pages": [
                    {
                        "startedDateTime": datetime.now(timezone.utc).isoformat(),
                        "id": "page_0",
                        "title": title,
                        "pageTimings": {"onContentLoad": -1, "onLoad": -1},
                    }
                ],
                "entries": entries,
            }
        }

    def export_to_har_string(
        self,
        observations: List[BrowserObservation],
        title: str = "Drishti Crawl Capture",
    ) -> str:
        """Serializes observations to a formatted HAR 1.2 JSON string."""
        har_dict = self.observations_to_har_dict(observations, title=title)
        return json.dumps(har_dict, indent=2)

    @staticmethod
    def to_endpoint_observations(
        observations: List[BrowserObservation],
        default_asset_id: str = "primary-api",
    ) -> List[EndpointObservation]:
        """Converts BrowserObservations directly into EndpointObservations for normalization."""
        results = []
        for obs in observations:
            parsed_body = None
            if obs.request_body:
                try:
                    parsed_body = json.loads(obs.request_body)
                except Exception:
                    pass

            endpoint_obs = EndpointObservation(
                method=obs.method,
                raw_url=obs.url,
                response_status=obs.status_code,
                role=obs.role_name,
                asset_id=default_asset_id,
            )
            results.append(endpoint_obs)
        return results
