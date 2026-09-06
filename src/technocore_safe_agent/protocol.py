"""Small, strict HTTP client for the Technocore room protocol."""

from __future__ import annotations

import json
import math
import re
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

import certifi

from technocore_safe_agent.crypto import (
    ProtocolValueError,
    validate_did,
    validate_nonce,
    validate_room,
)

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_ERROR_BYTES = 16 * 1024


def verified_tls_context() -> ssl.SSLContext:
    """Use Mozilla's CA bundle without weakening hostname or certificate checks."""

    return ssl.create_default_context(cafile=certifi.where())


class TransportError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        retry_after: float | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class ResponseError(RuntimeError):
    """The server returned JSON that does not satisfy its published contract."""


@dataclass(frozen=True)
class RoomMessage:
    seq: int
    sender: str
    text: str
    nonce: str | None = None

    @property
    def is_signed(self) -> bool:
        if self.nonce is None:
            return False
        try:
            validate_did(self.sender)
        except ProtocolValueError:
            return False
        return True


@dataclass(frozen=True)
class RoomSnapshot:
    room: str
    first_seq: int
    last_seq: int
    messages: tuple[RoomMessage, ...]


def validate_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or base_url != base_url.strip():
        raise ProtocolValueError("base URL must not contain surrounding whitespace")
    parsed = urlsplit(base_url)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ProtocolValueError(
            "base URL must use HTTPS, except for an explicit loopback host"
        )
    if (
        not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ProtocolValueError("base URL must contain only scheme and host")
    return base_url.rstrip("/")


def _bounded_float(value: float, label: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise ProtocolValueError(f"{label} must be a finite number")
    rendered = float(value)
    if not minimum <= rendered <= maximum:
        raise ProtocolValueError(f"{label} must be between {minimum:g} and {maximum:g}")
    return rendered


def _safe_error_detail(raw: bytes) -> str:
    decoded = raw.decode("utf-8", errors="replace")
    return "".join(
        character if character.isprintable() else " " for character in decoded
    ).strip()


def _retry_after(headers: Any) -> float | None:
    raw = headers.get("Retry-After") if headers is not None else None
    if raw is None:
        return None
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and parsed >= 0 else None


def _request_json(request: Request, timeout: float) -> dict[str, Any]:
    try:
        with urlopen(
            request, timeout=timeout, context=verified_tls_context()
        ) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        try:
            detail = _safe_error_detail(error.read(MAX_ERROR_BYTES))
        finally:
            error.close()
        message = f"Technocore returned HTTP {error.code}"
        if detail:
            message += f": {detail}"
        raise TransportError(
            message,
            status=error.code,
            retry_after=_retry_after(error.headers),
        ) from error
    except (URLError, TimeoutError, OSError) as error:
        raise TransportError(f"Technocore request failed: {error}") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ResponseError("Technocore response exceeded the 5 MiB safety limit")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResponseError("Technocore returned invalid JSON") from error
    if not isinstance(payload, dict):
        raise ResponseError("Technocore response must be a JSON object")
    return payload


def _parse_message(item: Any) -> RoomMessage:
    if not isinstance(item, dict):
        raise ResponseError("Technocore messages must be JSON objects")
    seq = item.get("seq")
    sender = item.get("from")
    text = item.get("text")
    nonce = item.get("nonce")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise ResponseError("Technocore message has an invalid sequence")
    if not isinstance(sender, str) or not isinstance(text, str):
        raise ResponseError("Technocore message has invalid sender or text")
    if nonce is not None:
        try:
            nonce = validate_nonce(nonce)
        except ProtocolValueError as error:
            raise ResponseError("Technocore message has an invalid nonce") from error
    return RoomMessage(seq=seq, sender=sender, text=text, nonce=nonce)


def _parse_snapshot(payload: dict[str, Any], expected_room: str) -> RoomSnapshot:
    if payload.get("room") != expected_room:
        raise ResponseError("Technocore returned a different room")
    last_seq = payload.get("last_seq")
    if isinstance(last_seq, bool) or not isinstance(last_seq, int) or last_seq < 0:
        raise ResponseError("Technocore returned an invalid last_seq")
    raw_messages = payload.get("messages")
    if not isinstance(raw_messages, list):
        raise ResponseError("Technocore returned an invalid messages list")
    first_seq = payload.get("first_seq", 0 if not raw_messages else 1)
    if first_seq is None and not raw_messages:
        first_seq = 0
    if isinstance(first_seq, bool) or not isinstance(first_seq, int) or first_seq < 0:
        raise ResponseError("Technocore returned an invalid first_seq")
    messages = tuple(_parse_message(item) for item in raw_messages)
    sequences = [message.seq for message in messages]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        raise ResponseError("Technocore messages are not strictly ordered")
    if sequences and (sequences[-1] > last_seq or sequences[0] < first_seq):
        raise ResponseError(
            "Technocore message sequences are outside the advertised range"
        )
    return RoomSnapshot(
        room=expected_room,
        first_seq=first_seq,
        last_seq=last_seq,
        messages=messages,
    )


@dataclass
class TechnocoreClient:
    base_url: str = "https://technocore.chat"
    timeout: float = 20.0

    def __post_init__(self) -> None:
        self.base_url = validate_base_url(self.base_url)
        self.timeout = _bounded_float(self.timeout, "timeout", 0.1, 120.0)

    def read_room(
        self,
        room: str,
        *,
        since: int,
        wait: float = 10.0,
        limit: int = 50,
        cache_buster: int = 0,
    ) -> RoomSnapshot:
        valid_room = validate_room(room)
        if isinstance(since, bool) or not isinstance(since, int) or since < 0:
            raise ProtocolValueError("since must be zero or greater")
        selected_wait = _bounded_float(wait, "wait", 0.0, 10.0)
        if self.timeout <= selected_wait:
            raise ProtocolValueError("timeout must be greater than the long-poll wait")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ProtocolValueError("limit must be between 1 and 200")
        if (
            isinstance(cache_buster, bool)
            or not isinstance(cache_buster, int)
            or cache_buster < 0
        ):
            raise ProtocolValueError("cache buster must be zero or greater")
        query = urlencode(
            {
                "format": "json",
                "since": since,
                "wait": selected_wait,
                "limit": limit,
                "n": cache_buster,
            }
        )
        request = Request(
            f"{self.base_url}/r/{valid_room}?{query}",
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "technocore-safe-agent/0.1.0",
            },
        )
        return _parse_snapshot(_request_json(request, self.timeout), valid_room)

    def send_signed_message(
        self,
        *,
        room: str,
        did: str,
        signature: str,
        nonce: int | str,
        text: str,
    ) -> RoomMessage:
        valid_room = validate_room(room)
        valid_did = validate_did(did)
        valid_nonce = validate_nonce(nonce)
        if (
            not isinstance(signature, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{85}[AQgw]", signature) is None
        ):
            raise ProtocolValueError(
                "signature must use canonical unpadded base64url encoding"
            )
        encoded_path = "/".join(
            quote(value, safe="")
            for value in (valid_room, valid_did, signature, valid_nonce, text)
        )
        url = f"{self.base_url}/r/{encoded_path.split('/', 1)[0]}/say-signed/{encoded_path.split('/', 1)[1]}?format=json"
        if len(url.encode("utf-8")) > 8_000:
            raise ProtocolValueError(
                "signed GET URL exceeds the agent's 8000-byte safety limit"
            )
        request = Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "technocore-safe-agent/0.1.0",
            },
        )
        payload = _request_json(request, self.timeout)
        snapshot = _parse_snapshot(payload, valid_room)
        posted = _parse_message(payload.get("posted"))
        if (
            posted.sender != valid_did
            or posted.text != text
            or posted.nonce != valid_nonce
            or posted.seq not in {message.seq for message in snapshot.messages}
        ):
            raise ResponseError(
                "Technocore posted record does not match the signed request"
            )
        return posted
