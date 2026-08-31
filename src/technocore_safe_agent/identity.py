"""Public identity loading and macOS Keychain custody."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.crypto import (
    IdentityError,
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
    validate_did,
)


DEFAULT_AGENT_NAME = "SafeAgent"
DEFAULT_RUNTIME_DIRECTORY = Path(
    f"~/Library/Application Support/Technocore/{DEFAULT_AGENT_NAME}"
).expanduser()
DEFAULT_IDENTITY_PATH = DEFAULT_RUNTIME_DIRECTORY / "public-identity.json"


class SeedProvider(Protocol):
    def load_seed(self) -> str:
        """Return a 32-byte hex seed without logging it."""


@dataclass(frozen=True)
class IdentityRecord:
    did: str
    fingerprint: str
    keychain_service: str
    keychain_account: str

    @classmethod
    def load(cls, path: Path) -> "IdentityRecord":
        resolved = path.expanduser().resolve()
        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise IdentityError(
                f"cannot read public identity {resolved}: {error}"
            ) from error
        if not isinstance(payload, dict):
            raise IdentityError("public identity must contain a JSON object")
        custody = payload.get("custody")
        if not isinstance(custody, dict) or custody.get("backend") != "macos-keychain":
            raise IdentityError(
                "public identity must use the macos-keychain custody backend"
            )
        did = validate_did(payload.get("did"))
        fingerprint = payload.get("fingerprint")
        if fingerprint != fingerprint_of_did(did):
            raise IdentityError("public identity fingerprint does not match its DID")
        service = custody.get("service")
        account = custody.get("account")
        if not isinstance(service, str) or not service:
            raise IdentityError("public identity is missing the Keychain service")
        if not isinstance(account, str) or not account:
            raise IdentityError("public identity is missing the Keychain account")
        return cls(
            did=did,
            fingerprint=fingerprint,
            keychain_service=service,
            keychain_account=account,
        )


@dataclass(frozen=True)
class MacOSKeychainSeedProvider:
    service: str
    account: str
    security_binary: str = "/usr/bin/security"

    def load_seed(self) -> str:
        try:
            result = subprocess.run(
                [
                    self.security_binary,
                    "find-generic-password",
                    "-w",
                    "-s",
                    self.service,
                    "-a",
                    self.account,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as error:
            raise IdentityError("macOS security command is not available") from error
        except subprocess.CalledProcessError as error:
            raise IdentityError(
                f"cannot read Keychain item for service {self.service!r} and account {self.account!r}"
            ) from error
        return result.stdout.strip()


@dataclass(frozen=True)
class StaticSeedProvider:
    """Test-only provider; production CLI never accepts a raw seed."""

    seed: str

    def load_seed(self) -> str:
        return self.seed


def load_verified_private_key(
    record: IdentityRecord,
    provider: SeedProvider,
) -> Ed25519PrivateKey:
    private_key = private_key_from_seed(provider.load_seed())
    derived_did = did_from_private_key(private_key)
    if derived_did != record.did:
        raise IdentityError("Keychain key does not match the configured public DID")
    return private_key
