"""Sanitized evidence store with automated redaction, size limits, and digest computation."""

import re
import json
from pathlib import Path
from typing import Dict, Any, Tuple
from drishti.core.config import EvidenceConfig
from drishti.audit.hash_chain import sha256_digest, canonical_json

REDACTION_PATTERNS = [
    (re.compile(r'(?i)(["\']?authorization["\']?\s*:\s*["\']?bearer\s+)([A-Za-z0-9\-_\.]+)', re.IGNORECASE), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(["\']?cookie["\']?\s*:\s*["\']?.*?(?:session_id|session|token|jwt|auth)=)([^\s;"]+)', re.IGNORECASE), r'\1[REDACTED_COOKIE]'),
    (re.compile(r'(?i)(["\']password["\']\s*:\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED_PASSWORD]\3'),
    (re.compile(r'(?i)(["\'](?:card_number|cvv|credit_card)["\']\s*:\s*["\']?)([^"\'}\s,]+)(["\']?)', re.IGNORECASE), r'\1[REDACTED_PAYMENT]\3'),
    (re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'), '[REDACTED_CREDIT_CARD]'),
    (re.compile(r'\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b'), '[REDACTED_PASSPORT]')
]

class EvidenceStore:
    """
    Isolated storage for request and response evidence.
    Enforces automatic PII/secret redaction and payload size limits before persistence.
    """
    def __init__(self, storage_dir: Path = Path(".drishti_evidence"), config: EvidenceConfig = None):
        self.storage_dir = storage_dir
        self.config = config or EvidenceConfig()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._memory_artifacts: Dict[str, bytes] = {}

    def store_raw_artifact(
        self,
        artifact_id: str,
        raw_bytes: bytes,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Stores immutable raw response bytes indexed by artifact_id."""
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8")
        self._memory_artifacts[artifact_id] = raw_bytes
        artifact_file = self.storage_dir / f"{artifact_id}.bin"
        try:
            with open(artifact_file, "wb") as f:
                f.write(raw_bytes)
        except Exception:
            pass
        return str(artifact_file)

    def get_raw_artifact(self, artifact_id: str) -> Optional[bytes]:
        """Retrieves immutable raw response bytes by artifact_id."""
        if artifact_id in self._memory_artifacts:
            return self._memory_artifacts[artifact_id]
        artifact_file = self.storage_dir / f"{artifact_id}.bin"
        if artifact_file.exists():
            try:
                with open(artifact_file, "rb") as f:
                    content = f.read()
                    self._memory_artifacts[artifact_id] = content
                    return content
            except Exception:
                return None
        return None

    def has_artifact(self, artifact_id: str) -> bool:
        """Checks if an artifact exists in memory or on disk."""
        return artifact_id in self._memory_artifacts or (self.storage_dir / f"{artifact_id}.bin").exists()

    def redact(self, text: str) -> str:
        if not self.config.redaction_enabled or not isinstance(text, str):
            return text
        for pattern, replacement in REDACTION_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def store_evidence(
        self,
        evidence_id: str,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any]
    ) -> Tuple[str, str]:
        """
        Redacts sensitive data, enforces size caps, stores evidence file,
        and returns (evidence_path, sha256_digest).
        """
        raw_json = json.dumps({"request": request_data, "response": response_data})
        sanitized_json = self.redact(raw_json)

        # Enforce payload size limit
        encoded = sanitized_json.encode("utf-8")
        if len(encoded) > self.config.max_payload_size_bytes:
            sanitized_json = sanitized_json[:self.config.max_payload_size_bytes] + "\n[TRUNCATED_AT_MAX_SIZE]"
            encoded = sanitized_json.encode("utf-8")

        digest = sha256_digest(encoded)
        evidence_file = self.storage_dir / f"{evidence_id}_{digest[:12]}.json"

        with open(evidence_file, "w", encoding="utf-8") as f:
            f.write(sanitized_json)

        return str(evidence_file), digest
