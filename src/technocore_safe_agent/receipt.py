"""Portable receipts for bounded, read-only public GitHub PR observations."""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent import __version__
from technocore_safe_agent.crypto import (
    ProtocolValueError,
    did_from_private_key,
    sign_detached,
    validate_did,
    verify_detached_signature,
)
from technocore_safe_agent.protocol import verified_tls_context

GITHUB_API_HOST = "api.github.com"
GITHUB_API_VERSION = "2026-03-10"
MAX_GITHUB_RESPONSE_BYTES = 2 * 1024 * 1024
RECEIPT_SCHEMA = "technocore-github-pr-receipt-v1"
RECEIPT_SOURCE = "github-public-rest"

OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
AUTHOR_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?(?:\[bot\])?\Z"
)
SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

CHECK_STATUSES = frozenset(
    {"queued", "in_progress", "requested", "waiting", "pending", "completed"}
)
CHECK_FAILURES = frozenset(
    {
        "action_required",
        "cancelled",
        "failure",
        "stale",
        "startup_failure",
        "timed_out",
    }
)
CHECK_NON_FAILURES = frozenset({"neutral", "skipped", "success"})
COMBINED_STATUS_STATES = frozenset({"error", "failure", "pending", "success"})
CI_STATES = frozenset({"failure", "no_signals", "partial", "pending", "success"})

RECEIPT_PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "issuer",
        "source",
        "api_version",
        "repository",
        "pull_number",
        "url",
        "author",
        "state",
        "merged",
        "draft",
        "head_sha",
        "base_sha",
        "merge_commit_sha",
        "ci",
        "ci_data_complete",
        "checks_observed",
        "checks_total",
        "statuses_observed",
        "statuses_total",
        "source_updated_at",
        "observed_at",
    }
)


class GitHubReceiptError(RuntimeError):
    """A receipt cannot be issued without overstating the available evidence."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.retry_after = retry_after


@dataclass(frozen=True)
class GitHubPullRequestRef:
    owner: str
    repository: str
    number: int

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repository}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self.full_name}/pull/{self.number}"


@dataclass(frozen=True)
class RawGitHubResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class GitHubTransport(Protocol):
    def request(
        self, path: str, *, headers: Mapping[str, str], timeout: float
    ) -> RawGitHubResponse: ...


class ReceiptIssuer(Protocol):
    def issue(self, url: str) -> str: ...


@dataclass
class HttpsGitHubTransport:
    """HTTPS transport pinned to api.github.com with no redirect handling."""

    def request(
        self, path: str, *, headers: Mapping[str, str], timeout: float
    ) -> RawGitHubResponse:
        connection = http.client.HTTPSConnection(
            GITHUB_API_HOST,
            timeout=timeout,
            context=verified_tls_context(),
        )
        try:
            connection.request("GET", path, headers=dict(headers))
            response = connection.getresponse()
            body = response.read(MAX_GITHUB_RESPONSE_BYTES + 1)
            response_headers = {
                name.lower(): value for name, value in response.getheaders()
            }
        except (OSError, http.client.HTTPException) as error:
            raise GitHubReceiptError(
                f"GitHub request failed: {error}", code="github_transport_error"
            ) from error
        finally:
            connection.close()
        return RawGitHubResponse(response.status, response_headers, body)


@dataclass(frozen=True)
class PullRequestEvidence:
    repository: str
    number: int
    url: str
    author: str
    state: str
    merged: bool
    draft: bool
    head_sha: str
    base_sha: str
    merge_commit_sha: str | None
    ci: str
    ci_data_complete: bool
    checks_observed: int
    checks_total: int
    statuses_observed: int
    statuses_total: int
    source_updated_at: str


@dataclass(frozen=True)
class _PullDetails:
    repository: str
    number: int
    url: str
    author: str
    state: str
    merged: bool
    draft: bool
    head_sha: str
    base_sha: str
    merge_commit_sha: str | None
    source_updated_at: str


@dataclass(frozen=True)
class _CheckSummary:
    observed: int
    total: int
    complete: bool
    has_failure: bool
    has_pending: bool


@dataclass(frozen=True)
class _StatusSummary:
    observed: int
    total: int
    complete: bool
    state: str


def parse_github_pull_request_url(url: str) -> GitHubPullRequestRef:
    """Accept only an exact public github.com pull-request URL."""

    if not isinstance(url, str) or url != url.strip():
        raise GitHubReceiptError(
            "pull request URL must not contain surrounding whitespace",
            code="invalid_pull_request_url",
        )
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubReceiptError(
            "only canonical https://github.com/OWNER/REPO/pull/NUMBER URLs are allowed",
            code="invalid_pull_request_url",
        )
    match = re.fullmatch(r"/([^/]+)/([^/]+)/pull/([1-9][0-9]*)", parsed.path)
    if match is None:
        raise GitHubReceiptError(
            "pull request URL must end exactly with /pull/NUMBER",
            code="invalid_pull_request_url",
        )
    owner, repository, number_text = match.groups()
    if OWNER_PATTERN.fullmatch(owner) is None or not _valid_repository(repository):
        raise GitHubReceiptError(
            "pull request URL contains an invalid owner or repository",
            code="invalid_pull_request_url",
        )
    number = int(number_text)
    if number > 2_147_483_647:
        raise GitHubReceiptError(
            "pull request number is outside the supported range",
            code="invalid_pull_request_url",
        )
    return GitHubPullRequestRef(owner, repository, number)


def _valid_repository(value: str) -> bool:
    return (
        REPOSITORY_PATTERN.fullmatch(value) is not None
        and value not in {".", ".."}
        and not value.endswith(".git")
    )


def _parse_repository(value: Any) -> str:
    if not isinstance(value, str) or value.count("/") != 1:
        raise GitHubReceiptError(
            "GitHub returned an invalid repository name", code="invalid_github_response"
        )
    owner, repository = value.split("/", 1)
    if OWNER_PATTERN.fullmatch(owner) is None or not _valid_repository(repository):
        raise GitHubReceiptError(
            "GitHub returned an unsafe repository name", code="invalid_github_response"
        )
    return value


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_PATTERN.fullmatch(value) is None:
        raise GitHubReceiptError(
            f"GitHub returned an invalid {label}", code="invalid_github_response"
        )
    return value


def _require_count(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GitHubReceiptError(
            f"GitHub returned an invalid {label}", code="invalid_github_response"
        )
    return value


def _require_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise GitHubReceiptError(
            f"GitHub returned an invalid {label}", code="invalid_github_response"
        )
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise GitHubReceiptError(
            f"GitHub returned an invalid {label}", code="invalid_github_response"
        ) from error
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise GitHubReceiptError(
            f"GitHub returned an invalid {label}", code="invalid_github_response"
        )
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GitHubReceiptError(
            f"GitHub returned an invalid {label}", code="invalid_github_response"
        )
    return value


def _retry_after(headers: Mapping[str, str]) -> float | None:
    value = headers.get("retry-after")
    if value is None:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


@dataclass
class GitHubPublicClient:
    transport: GitHubTransport = field(default_factory=HttpsGitHubTransport)
    timeout: float = 15.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or not 0.1 <= float(self.timeout) <= 60.0
        ):
            raise ProtocolValueError(
                "GitHub timeout must be between 0.1 and 60 seconds"
            )
        self.timeout = float(self.timeout)

    def inspect(self, reference: GitHubPullRequestRef) -> PullRequestEvidence:
        base_path = f"/repos/{reference.owner}/{reference.repository}"
        pull = self._request_object(f"{base_path}/pulls/{reference.number}")
        details = self._parse_pull(pull, reference)
        checks = self._parse_checks(
            self._request_object(
                f"{base_path}/commits/{details.head_sha}/check-runs?per_page=100&filter=latest"
            ),
            details.head_sha,
        )
        statuses = self._parse_statuses(
            self._request_object(
                f"{base_path}/commits/{details.head_sha}/status?per_page=100"
            ),
            details.head_sha,
        )
        complete = checks.complete and statuses.complete
        if checks.has_failure or statuses.state in {"error", "failure"}:
            ci = "failure"
        elif not complete:
            ci = "partial"
        elif checks.total + statuses.total == 0:
            ci = "no_signals"
        elif checks.has_pending or statuses.state == "pending":
            ci = "pending"
        else:
            ci = "success"
        return PullRequestEvidence(
            repository=details.repository,
            number=details.number,
            url=details.url,
            author=details.author,
            state=details.state,
            merged=details.merged,
            draft=details.draft,
            head_sha=details.head_sha,
            base_sha=details.base_sha,
            merge_commit_sha=details.merge_commit_sha,
            ci=ci,
            ci_data_complete=complete,
            checks_observed=checks.observed,
            checks_total=checks.total,
            statuses_observed=statuses.observed,
            statuses_total=statuses.total,
            source_updated_at=details.source_updated_at,
        )

    def _request_object(self, path: str) -> Mapping[str, Any]:
        if not path.startswith("/repos/") or "//" in path:
            raise GitHubReceiptError(
                "refusing an unsafe GitHub API path", code="unsafe_github_path"
            )
        response = self.transport.request(
            path,
            timeout=self.timeout,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"technocore-safe-agent/{__version__}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        if len(response.body) > MAX_GITHUB_RESPONSE_BYTES:
            raise GitHubReceiptError(
                "GitHub response exceeded the 2 MiB safety limit",
                code="github_response_too_large",
            )
        if response.status != 200:
            rate_limited = response.status == 429 or (
                response.status == 403
                and response.headers.get("x-ratelimit-remaining") == "0"
            )
            code = (
                "github_rate_limited"
                if rate_limited
                else f"github_http_{response.status}"
            )
            raise GitHubReceiptError(
                f"GitHub returned HTTP {response.status}",
                code=code,
                status=response.status,
                retry_after=_retry_after(response.headers),
            )
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise GitHubReceiptError(
                "GitHub returned invalid JSON", code="invalid_github_response"
            ) from error
        if not isinstance(payload, dict):
            raise GitHubReceiptError(
                "GitHub response must be a JSON object",
                code="invalid_github_response",
            )
        return payload

    @staticmethod
    def _parse_pull(
        payload: Mapping[str, Any], reference: GitHubPullRequestRef
    ) -> _PullDetails:
        number = _require_count(payload.get("number"), "pull request number")
        if number != reference.number or number == 0:
            raise GitHubReceiptError(
                "GitHub returned a different pull request number",
                code="invalid_github_response",
            )
        base = _mapping(payload.get("base"), "pull request base")
        base_repo = _mapping(base.get("repo"), "base repository")
        if base_repo.get("private") is not False:
            raise GitHubReceiptError(
                "only public base repositories can receive receipts",
                code="private_repository_rejected",
            )
        repository = _parse_repository(base_repo.get("full_name"))
        if repository.casefold() != reference.full_name.casefold():
            raise GitHubReceiptError(
                "GitHub returned a different base repository",
                code="invalid_github_response",
            )
        canonical_reference = parse_github_pull_request_url(
            f"https://github.com/{repository}/pull/{number}"
        )
        html_reference = parse_github_pull_request_url(payload.get("html_url"))
        if (
            html_reference.full_name.casefold()
            != canonical_reference.full_name.casefold()
            or html_reference.number != number
        ):
            raise GitHubReceiptError(
                "GitHub returned an inconsistent pull request URL",
                code="invalid_github_response",
            )

        user = _mapping(payload.get("user"), "pull request author")
        author = user.get("login")
        if not isinstance(author, str) or AUTHOR_PATTERN.fullmatch(author) is None:
            raise GitHubReceiptError(
                "GitHub returned an unsafe author login",
                code="invalid_github_response",
            )
        state = payload.get("state")
        if state not in {"open", "closed"}:
            raise GitHubReceiptError(
                "GitHub returned an invalid pull request state",
                code="invalid_github_response",
            )
        merged = payload.get("merged")
        draft = payload.get("draft")
        if not isinstance(merged, bool) or not isinstance(draft, bool):
            raise GitHubReceiptError(
                "GitHub returned invalid pull request flags",
                code="invalid_github_response",
            )
        head = _mapping(payload.get("head"), "pull request head")
        head_sha = _require_sha(head.get("sha"), "head SHA")
        base_sha = _require_sha(base.get("sha"), "base SHA")
        raw_merge_sha = payload.get("merge_commit_sha")
        merge_commit_sha = (
            _require_sha(raw_merge_sha, "merge commit SHA")
            if merged and raw_merge_sha is not None
            else None
        )
        return _PullDetails(
            repository=repository,
            number=number,
            url=canonical_reference.url,
            author=author,
            state=state,
            merged=merged,
            draft=draft,
            head_sha=head_sha,
            base_sha=base_sha,
            merge_commit_sha=merge_commit_sha,
            source_updated_at=_require_timestamp(
                payload.get("updated_at"), "pull request updated_at"
            ),
        )

    @staticmethod
    def _parse_checks(payload: Mapping[str, Any], expected_sha: str) -> _CheckSummary:
        total = _require_count(payload.get("total_count"), "check-run count")
        runs = _list(payload.get("check_runs"), "check-runs")
        if len(runs) > total or len(runs) > 100:
            raise GitHubReceiptError(
                "GitHub returned inconsistent check-run counts",
                code="invalid_github_response",
            )
        has_failure = False
        has_pending = False
        for raw_run in runs:
            run = _mapping(raw_run, "check-run")
            if _require_sha(run.get("head_sha"), "check-run head SHA") != expected_sha:
                raise GitHubReceiptError(
                    "GitHub returned a check-run for a different commit",
                    code="invalid_github_response",
                )
            status = run.get("status")
            if status not in CHECK_STATUSES:
                raise GitHubReceiptError(
                    "GitHub returned an unknown check-run status",
                    code="invalid_github_response",
                )
            if status != "completed":
                has_pending = True
                continue
            conclusion = run.get("conclusion")
            if conclusion in CHECK_FAILURES:
                has_failure = True
            elif conclusion not in CHECK_NON_FAILURES:
                raise GitHubReceiptError(
                    "GitHub returned an unknown check-run conclusion",
                    code="invalid_github_response",
                )
        return _CheckSummary(
            observed=len(runs),
            total=total,
            complete=len(runs) == total,
            has_failure=has_failure,
            has_pending=has_pending,
        )

    @staticmethod
    def _parse_statuses(
        payload: Mapping[str, Any], expected_sha: str
    ) -> _StatusSummary:
        if _require_sha(payload.get("sha"), "combined-status SHA") != expected_sha:
            raise GitHubReceiptError(
                "GitHub returned statuses for a different commit",
                code="invalid_github_response",
            )
        state = payload.get("state")
        if state not in COMBINED_STATUS_STATES:
            raise GitHubReceiptError(
                "GitHub returned an unknown combined-status state",
                code="invalid_github_response",
            )
        total = _require_count(payload.get("total_count"), "status count")
        statuses = _list(payload.get("statuses"), "statuses")
        if len(statuses) > total or len(statuses) > 100:
            raise GitHubReceiptError(
                "GitHub returned inconsistent status counts",
                code="invalid_github_response",
            )
        return _StatusSummary(
            observed=len(statuses),
            total=total,
            complete=len(statuses) == total,
            state=state,
        )


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _format_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise GitHubReceiptError(
            "receipt clock must return a timezone-aware datetime",
            code="invalid_receipt_clock",
        )
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_signed_receipt(
    evidence: PullRequestEvidence,
    *,
    issuer_did: str,
    private_key: Ed25519PrivateKey,
    observed_at: datetime,
) -> dict[str, Any]:
    validate_did(issuer_did)
    if did_from_private_key(private_key) != issuer_did:
        raise GitHubReceiptError(
            "receipt signing key does not match its issuer DID",
            code="receipt_issuer_mismatch",
        )
    payload: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "issuer": issuer_did,
        "source": RECEIPT_SOURCE,
        "api_version": GITHUB_API_VERSION,
        "repository": evidence.repository,
        "pull_number": evidence.number,
        "url": evidence.url,
        "author": evidence.author,
        "state": evidence.state,
        "merged": evidence.merged,
        "draft": evidence.draft,
        "head_sha": evidence.head_sha,
        "base_sha": evidence.base_sha,
        "merge_commit_sha": evidence.merge_commit_sha,
        "ci": evidence.ci,
        "ci_data_complete": evidence.ci_data_complete,
        "checks_observed": evidence.checks_observed,
        "checks_total": evidence.checks_total,
        "statuses_observed": evidence.statuses_observed,
        "statuses_total": evidence.statuses_total,
        "source_updated_at": evidence.source_updated_at,
        "observed_at": _format_timestamp(observed_at),
    }
    _validate_receipt_payload(payload)
    canonical = _canonical_json(payload)
    return {
        "payload": payload,
        "payload_sha256": hashlib.sha256(canonical).hexdigest(),
        "signature": sign_detached(private_key, canonical),
    }


def render_signed_receipt(receipt: Mapping[str, Any]) -> str:
    verify_signed_receipt(receipt)
    rendered = json.dumps(
        receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    if len(rendered) > 4096:
        raise GitHubReceiptError(
            "signed receipt exceeds the Technocore message limit",
            code="receipt_too_large",
        )
    return rendered


def verify_signed_receipt(receipt: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(receipt, str):
        try:
            decoded = json.loads(receipt)
        except json.JSONDecodeError as error:
            raise GitHubReceiptError(
                "receipt is not valid JSON", code="invalid_receipt"
            ) from error
    else:
        decoded = receipt
    if not isinstance(decoded, dict) or set(decoded) != {
        "payload",
        "payload_sha256",
        "signature",
    }:
        raise GitHubReceiptError(
            "receipt wrapper has unexpected fields", code="invalid_receipt"
        )
    payload = decoded.get("payload")
    if not isinstance(payload, dict):
        raise GitHubReceiptError(
            "receipt payload must be a JSON object", code="invalid_receipt"
        )
    _validate_receipt_payload(payload)
    canonical = _canonical_json(payload)
    expected_hash = hashlib.sha256(canonical).hexdigest()
    if decoded.get("payload_sha256") != expected_hash:
        raise GitHubReceiptError(
            "receipt payload hash does not match", code="invalid_receipt"
        )
    signature = decoded.get("signature")
    if not verify_detached_signature(payload["issuer"], canonical, signature):
        raise GitHubReceiptError(
            "receipt signature does not match its issuer", code="invalid_receipt"
        )
    return payload


def _validate_receipt_payload(payload: Mapping[str, Any]) -> None:
    if set(payload) != RECEIPT_PAYLOAD_KEYS:
        raise GitHubReceiptError(
            "receipt payload has unexpected fields", code="invalid_receipt"
        )
    _validate_receipt_header(payload)
    _validate_receipt_subject(payload)
    _validate_receipt_commits(payload)
    _validate_receipt_ci(payload)
    _require_timestamp(payload.get("source_updated_at"), "receipt source timestamp")
    _require_timestamp(payload.get("observed_at"), "receipt observation timestamp")


def _validate_receipt_header(payload: Mapping[str, Any]) -> None:
    if (
        payload.get("schema") != RECEIPT_SCHEMA
        or payload.get("source") != RECEIPT_SOURCE
        or payload.get("api_version") != GITHUB_API_VERSION
    ):
        raise GitHubReceiptError(
            "receipt payload uses an unsupported schema or source",
            code="invalid_receipt",
        )
    try:
        validate_did(payload.get("issuer"))
    except (ProtocolValueError, TypeError) as error:
        raise GitHubReceiptError(
            "receipt contains an invalid issuer DID", code="invalid_receipt"
        ) from error


def _validate_receipt_subject(payload: Mapping[str, Any]) -> None:
    repository = _parse_repository(payload.get("repository"))
    number = _require_count(payload.get("pull_number"), "receipt pull number")
    if number == 0:
        raise GitHubReceiptError(
            "receipt pull number must be positive", code="invalid_receipt"
        )
    reference = parse_github_pull_request_url(payload.get("url"))
    if reference.full_name != repository or reference.number != number:
        raise GitHubReceiptError(
            "receipt URL does not match its repository and number",
            code="invalid_receipt",
        )
    author = payload.get("author")
    if not isinstance(author, str) or AUTHOR_PATTERN.fullmatch(author) is None:
        raise GitHubReceiptError(
            "receipt contains an invalid author", code="invalid_receipt"
        )
    if payload.get("state") not in {"open", "closed"}:
        raise GitHubReceiptError(
            "receipt contains an invalid pull request state", code="invalid_receipt"
        )
    if not isinstance(payload.get("merged"), bool) or not isinstance(
        payload.get("draft"), bool
    ):
        raise GitHubReceiptError(
            "receipt contains invalid pull request flags", code="invalid_receipt"
        )


def _validate_receipt_commits(payload: Mapping[str, Any]) -> None:
    _require_sha(payload.get("head_sha"), "receipt head SHA")
    _require_sha(payload.get("base_sha"), "receipt base SHA")
    merge_sha = payload.get("merge_commit_sha")
    if payload["merged"] and merge_sha is not None:
        _require_sha(merge_sha, "receipt merge commit SHA")
    elif merge_sha is not None:
        raise GitHubReceiptError(
            "unmerged receipt must not claim a merge commit",
            code="invalid_receipt",
        )


def _validate_receipt_ci(payload: Mapping[str, Any]) -> None:
    if payload.get("ci") not in CI_STATES or not isinstance(
        payload.get("ci_data_complete"), bool
    ):
        raise GitHubReceiptError(
            "receipt contains an invalid CI summary", code="invalid_receipt"
        )
    signals, counts_complete = _validate_receipt_ci_counts(payload)
    if payload["ci"] == "no_signals" and signals != 0:
        raise GitHubReceiptError(
            "no-signals receipt contains CI records", code="invalid_receipt"
        )
    if payload["ci"] != "no_signals" and signals == 0:
        raise GitHubReceiptError(
            "receipt claims a CI state without CI records", code="invalid_receipt"
        )
    if payload["ci"] == "partial" and counts_complete:
        raise GitHubReceiptError(
            "partial CI cannot claim complete data", code="invalid_receipt"
        )
    if payload["ci"] in {"pending", "success"} and not counts_complete:
        raise GitHubReceiptError(
            "incomplete CI cannot be reported as pending or successful",
            code="invalid_receipt",
        )


def _validate_receipt_ci_counts(payload: Mapping[str, Any]) -> tuple[int, bool]:
    for key in (
        "checks_observed",
        "checks_total",
        "statuses_observed",
        "statuses_total",
    ):
        _require_count(payload.get(key), f"receipt {key}")
    if (
        payload["checks_observed"] > payload["checks_total"]
        or payload["statuses_observed"] > payload["statuses_total"]
    ):
        raise GitHubReceiptError(
            "receipt contains inconsistent CI counts", code="invalid_receipt"
        )
    counts_complete = (
        payload["checks_observed"] == payload["checks_total"]
        and payload["statuses_observed"] == payload["statuses_total"]
    )
    if payload["ci_data_complete"] != counts_complete:
        raise GitHubReceiptError(
            "receipt CI completeness does not match its counts",
            code="invalid_receipt",
        )
    signals = payload["checks_total"] + payload["statuses_total"]
    return signals, counts_complete


@dataclass
class ContributionReceiptService:
    issuer_did: str
    private_key: Ed25519PrivateKey
    client: GitHubPublicClient = field(default_factory=GitHubPublicClient)
    min_interval_seconds: float = 60.0
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    monotonic: Callable[[], float] = time.monotonic
    _last_attempt_at: float | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        validate_did(self.issuer_did)
        if (
            isinstance(self.min_interval_seconds, bool)
            or not isinstance(self.min_interval_seconds, (int, float))
            or not math.isfinite(self.min_interval_seconds)
            or not 0 <= float(self.min_interval_seconds) <= 3600.0
        ):
            raise ProtocolValueError(
                "GitHub receipt interval must be between 0 and 3600 seconds"
            )
        self.min_interval_seconds = float(self.min_interval_seconds)

    def issue(self, url: str) -> str:
        reference = parse_github_pull_request_url(url)
        now = self.monotonic()
        if self._last_attempt_at is not None:
            elapsed = now - self._last_attempt_at
            if elapsed < self.min_interval_seconds:
                retry_after = self.min_interval_seconds - max(elapsed, 0.0)
                raise GitHubReceiptError(
                    "GitHub receipt cooldown is active",
                    code="local_receipt_rate_limited",
                    retry_after=retry_after,
                )
        self._last_attempt_at = now
        evidence = self.client.inspect(reference)
        receipt = build_signed_receipt(
            evidence,
            issuer_did=self.issuer_did,
            private_key=self.private_key,
            observed_at=self.clock(),
        )
        return render_signed_receipt(receipt)
