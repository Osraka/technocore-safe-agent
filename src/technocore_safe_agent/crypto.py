"""Technocore's Ed25519 identity and canonical message rules."""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
MULTICODEC_ED25519 = b"\xed\x01"
DID_PATTERN = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}\Z")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}\Z")
ROOM_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")


class IdentityError(ValueError):
    """The configured key material does not match the public identity."""


class ProtocolValueError(ValueError):
    """A value cannot be represented by the Technocore protocol."""


def _base58btc_encode(data: bytes) -> str:
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * leading_zeroes + encoded


def _base58btc_decode(value: str) -> bytes:
    if not value:
        raise ProtocolValueError("base58btc value must not be empty")
    number = 0
    for character in value:
        try:
            digit = BASE58BTC_ALPHABET.index(character)
        except ValueError as error:
            raise ProtocolValueError(
                "base58btc value contains an invalid character"
            ) from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + decoded


def private_key_from_seed(seed: str) -> Ed25519PrivateKey:
    """Load a production identity from an exact 32-byte hex seed.

    Passphrase hashing is deliberately not supported here: silently deriving a
    different key would make the agent speak as a different DID.
    """

    if not isinstance(seed, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", seed):
        raise IdentityError(
            "Keychain identity must be exactly 64 hexadecimal characters"
        )
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    did = "did:key:z" + _base58btc_encode(MULTICODEC_ED25519 + public_key)
    if DID_PATTERN.fullmatch(did) is None:
        raise IdentityError("derived an invalid Ed25519 did:key")
    return did


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Decode the exact Ed25519 multicodec form accepted by this agent."""

    valid_did = validate_did(did)
    decoded = _base58btc_decode(valid_did.removeprefix("did:key:z"))
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ProtocolValueError("DID does not contain a canonical Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(decoded[len(MULTICODEC_ED25519) :])


def fingerprint_of_did(did: str) -> str:
    validate_did(did)
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def validate_did(did: str) -> str:
    if not isinstance(did, str) or DID_PATTERN.fullmatch(did) is None:
        raise ProtocolValueError("DID must be a canonical Ed25519 did:key")
    return did


def validate_room(room: str) -> str:
    if not isinstance(room, str) or ROOM_PATTERN.fullmatch(room) is None:
        raise ProtocolValueError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return room


def validate_nonce(nonce: int | str) -> str:
    rendered = str(nonce)
    if isinstance(nonce, bool) or NONCE_PATTERN.fullmatch(rendered) is None:
        raise ProtocolValueError("nonce must contain 1-19 ASCII digits")
    return rendered


def sweep_text(text: str, *, limit: int = 4096) -> str:
    if not isinstance(text, str):
        raise ProtocolValueError("message text must be a string")
    swept = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not swept:
        raise ProtocolValueError("message has no visible text after the protocol sweep")
    if len(swept) > limit:
        raise ProtocolValueError(f"message exceeds the {limit}-character limit")
    return swept


def sign_detached(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise ProtocolValueError("signed payload must be bytes")
    signature = (
        base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")
    )
    if not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature):
        raise IdentityError("generated an invalid Ed25519 signature")
    return signature


def verify_detached_signature(did: str, payload: bytes, signature: str) -> bool:
    if not isinstance(payload, bytes) or not isinstance(signature, str):
        return False
    if re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None:
        return False
    try:
        decoded_signature = base64.urlsafe_b64decode(signature + "==")
        public_key_from_did(did).verify(decoded_signature, payload)
    except (InvalidSignature, ProtocolValueError, ValueError):
        return False
    return True


def sign_room_message(
    private_key: Ed25519PrivateKey,
    room: str,
    nonce: int | str,
    text: str,
) -> tuple[str, str]:
    valid_room = validate_room(room)
    valid_nonce = validate_nonce(nonce)
    swept = sweep_text(text)
    canonical = f"{valid_room}|{valid_nonce}|{swept}".encode("utf-8")
    return swept, sign_detached(private_key, canonical)
