"""Key material and key-reference detection.

Two rules, both from the plan's security requirements:

1. Never surface private key material. This module reports *that* key material
   exists, its type, its size, and a SHA-256 fingerprint for correlation. The
   key bytes themselves are never returned, logged, or persisted.
2. Prefer references over secrets. A KMS key id, a keystore alias, or an HSM
   slot is the thing an enterprise actually wants to inventory.
"""

from __future__ import annotations

import hashlib
import re

# PEM/OpenSSH key headers, used only to classify the blob.
_KEY_HEADERS = {
    b"-----BEGIN RSA PRIVATE KEY-----": ("rsa", "private_key"),
    b"-----BEGIN DSA PRIVATE KEY-----": ("dsa", "private_key"),
    b"-----BEGIN EC PRIVATE KEY-----": ("ec", "private_key"),
    b"-----BEGIN OPENSSH PRIVATE KEY-----": ("openssh", "private_key"),
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----": ("encrypted", "private_key"),
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----": ("pgp", "private_key"),
    b"-----BEGIN PUBLIC KEY-----": ("", "public_key"),
    b"-----BEGIN RSA PUBLIC KEY-----": ("rsa", "public_key"),
}

# JKS / PKCS#12 / keystore containers.
_KEYSTORE_MAGIC = {
    b"\xfe\xed\xfe\xed": "jks",
    b"\x30\x82": "pkcs12_or_der",
}

# References to externally-held key material. These are the findings an
# enterprise actually acts on: where is my key material held?
KEY_REFERENCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS ARNs: key ids are UUIDs but aliases and arbitrary suffixes exist too,
    # so match the ARN shape rather than one exact id format.
    ("aws_kms", re.compile(r"arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(?:key|alias)/[A-Za-z0-9/_-]{4,}", re.I)),
    ("aws_acm", re.compile(r"arn:aws[a-z-]*:acm[a-z-]*:[a-z0-9-]+:\d{12}:certificate/[A-Za-z0-9/_-]{4,}", re.I)),
    ("aws_cloudhsm", re.compile(r"\bclusterId[\"'\s:=]+[a-z0-9]{12,}|\bcloudhsmv2\b", re.I)),
    ("aws_secretsmanager", re.compile(r"arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_-]{4,}", re.I)),
    ("gcp_kms", re.compile(r"projects/[^/\s\"']+/locations/[^/\s\"']+/keyRings/[^/\s\"']+/cryptoKeys/[^/\s\"']+", re.I)),
    ("azure_keyvault", re.compile(r"https://[A-Za-z0-9-]+\.vault\.azure\.net/(?:keys|certificates|secrets)/[A-Za-z0-9-]+", re.I)),
    ("azure_keyvault", re.compile(r"azure\.net/[A-Za-z0-9-]+/(?:keys|certificates|secrets)/[A-Za-z0-9-]+", re.I)),
    ("hashicorp_vault", re.compile(r"\b(?:transit|pki|awskms|gcpckms|azurekeyvault)/[A-Za-z0-9_./-]+", re.I)),
    ("pkcs11", re.compile(r"\b(?:pkcs11|pkcs#11|C_Initialize|C_GetSlotList|C_Login|C_Sign|C_Decrypt)\b", re.I)),
    ("hsm_reference", re.compile(r"\b(?:CloudHSM|cloudhsm|HSM_\w+|TPM2?_\w+|YubiKey|yubikey|PKCS11_?\w*)\b")),
]

# Vendor SDK entry points that indicate managed key usage in code.
KMS_SDK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_kms", re.compile(r"\b(?:boto3\.client|new KMSClient|KMSClient|KMS\(|AwsKms|aws\.kms)\b|client\(\s*[\"']kms[\"']", re.I)),
    ("aws_acm", re.compile(r"\b(?:acm\.|ACMClient|AwsAcm|client\(\s*[\"']acm[\"'])", re.I)),
    ("aws_cloudhsm", re.compile(r"\b(?:CloudHsmClient|cloudhsm|cloudhsmv2)\b", re.I)),
    ("gcp_kms", re.compile(r"\b(?:google\.cloud\.kms|google\.cloud import kms|cloudkms|KeyManagementServiceClient|gcp\.kms|google-cloud-kms)\b", re.I)),
    ("azure_keyvault", re.compile(r"\b(?:azure\.keyvault|azure-keyvault|KeyClient|SecretClient|CertificateClient|DefaultAzureCredential)\b", re.I)),
    ("hashicorp_vault", re.compile(r"\bhvac\b|\bvault\.(?:transit|pki|kv)\b|\bVaultClient\b", re.I)),
    ("pkcs11", re.compile(r"\b(?:python-pkcs11|pkcs11\b|libykcs11|sunpkcs11|pkcs11-tool)\b", re.I)),
    ("tpm", re.compile(r"\b(?:tpm2_pytss|tpm2-tools|TrustedPlatformModule|IbmTss)\b", re.I)),
]


def fingerprint(data: bytes) -> str:
    """SHA-256 of key material, for correlation only. Never reversible to the key."""
    return hashlib.sha256(data).hexdigest()


def classify_key_blob(data: bytes) -> tuple[str, str] | None:
    """Return (family, kind) for key material in `data`, or None."""
    for header, (family, kind) in _KEY_HEADERS.items():
        if header in data:
            return family or "", kind
    return None


def keystore_type(data: bytes) -> str | None:
    """Identify a key store container by magic bytes."""
    for magic, name in _KEYSTORE_MAGIC.items():
        if data.startswith(magic):
            return name
    return None


def public_key_detail(data: bytes) -> dict:
    """Describe a public key without exposing anything sensitive.

    Only public keys are decoded here; a private key blob is reported as a
    fingerprint and a type, never parsed into key material.
    """
    from cryptography.hazmat.primitives import serialization

    from .x509 import _public_key_detail

    try:
        public_key = serialization.load_pem_public_key(data)
    except Exception:  # noqa: BLE001
        return {}
    algo, key_size, curve = _public_key_detail(public_key)
    detail = {"public_key_algorithm": algo, "key_size": key_size}
    if curve:
        detail["curve"] = curve
    return detail


def find_key_references(text: str) -> list[dict]:
    """Locate references to externally-held key material in a line of text."""
    found: list[dict] = []
    for name, pattern in KEY_REFERENCE_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        # References are ids/paths, not secrets, so the matched text is safe to
        # keep -- but cap it so a pathological input cannot bloat a finding.
        found.append(
            {
                "kind": "key_reference",
                "family": "unknown",
                "system": name,
                "reference": match.group(0)[:200],
                "confidence": 0.9,
                "evidence": {
                    "type": "key_reference",
                    "detector": "keymaterial",
                    "value": match.group(0)[:200],
                    "system": name,
                },
            }
        )
    return found


def find_kms_sdk_usage(text: str) -> list[dict]:
    """Locate managed key-service SDK usage in a line of code or config."""
    found: list[dict] = []
    for name, pattern in KMS_SDK_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        found.append(
            {
                "kind": "cloud_crypto_service",
                "family": "unknown",
                "system": name,
                "symbol": match.group(0)[:120],
                "confidence": 0.75,
                "evidence": {
                    "type": "sdk_reference",
                    "detector": "keymaterial",
                    "value": match.group(0)[:120],
                    "system": name,
                },
            }
        )
    return found
