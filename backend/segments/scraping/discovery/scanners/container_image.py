"""Container image discovery.

Reads an image archive (the layout produced by `docker save`, or an OCI image
layout) and reports the cryptographic material inside it. Nothing is executed
and nothing is unpacked to disk: layers are read in memory and only inspected.

Recognised inputs:

    docker save tar   manifest.json + layer tars
    OCI layout        oci-layout + index.json + blobs/
    gzipped tarball   the above, compressed
    single layer      a bare layer tar, treated as one filesystem

What is discovered per layer:

    certificates / key stores / keys   via :mod:`certstore`
    executables and shared objects     via :mod:`binary`
    crypto references in config        environment, entrypoint, cmd, labels

Image metadata (entrypoint, environment, labels) is reported because that is
where TLS material paths and KMS identifiers are normally declared.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import tarfile
from dataclasses import dataclass, field

from . import binary as binary_mod
from . import certstore

# A layer member is only decoded if it looks like something we understand.
_CERT_SUFFIXES = certstore.CERT_SUFFIXES | certstore.KEY_SUFFIXES | certstore.STORE_SUFFIXES

# Crypto references in image metadata (env, labels, cmd).
_KMS_HINT = re.compile(
    r"(AWS_KMS|ARN:aws:kms|AZURE_KEY_VAULT|GCP_KMS|VAULT_ADDR|"
    r"HSM|PKCS11|SOFTHSM|KEYSTORE|JCEKS|TRUSTSTORE)",
    re.IGNORECASE,
)
_TLS_HINT = re.compile(
    r"(\.pem|\.crt|\.cer|\.der|\.p12|\.pfx|\.jks|\.key|ca-bundle|"
    r"TLS_CERT|TLS_KEY|SSL_CERT|SSL_KEY|CERT_FILE|KEY_FILE|CA_BUNDLE)",
    re.IGNORECASE,
)
_PQ_HINT = re.compile(
    r"(ML-KEM|MLKEM|kyber|ML-DSA|MLDSA|dilithium|XMSS|LMS|sphincs|"
    r"X25519MLKEM|kyber768|X448MLKEM)",
    re.IGNORECASE,
)

# Never read an unbounded member into memory.
MEMBER_CAP = 64 * 1024 * 1024
MAX_MEMBERS = 20000


@dataclass
class ImageLayout:
    """The structural facts about an image, before any content is read."""

    is_container: bool = False
    kind: str = ""
    layers: list[str] = field(default_factory=list)
    layer_members: list[str] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    image_id: str = ""
    tag: str = ""
    reason: str = ""


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def _maybe_gunzip(data: bytes) -> bytes:
    """Decompress a gzipped archive, refusing to silently truncate it.

    A partial decompression would look like a corrupt tar and fail with an
    opaque ReadError, so an over-large stream is rejected outright and reported
    as a skip by the caller instead.
    """
    if data[:2] != b"\x1f\x8b":
        return data
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            # Read one byte past the cap: if there is more, the result is not
            # usable and must not be passed off as a complete image.
            out = handle.read(MEMBER_CAP + 1)
    except Exception:  # noqa: BLE001 - a bad gzip is simply not a container
        return data
    if len(out) > MEMBER_CAP:
        raise _ArchiveTooLarge
    return out


class _ArchiveTooLarge(Exception):
    """Raised when a compressed image would exceed the decompression cap."""


def read_layout(data: bytes) -> ImageLayout:
    """Identify an image archive and enumerate its layers."""
    layout = ImageLayout()
    try:
        data = _maybe_gunzip(data)
    except _ArchiveTooLarge:
        layout.reason = "archive_too_large"
        return layout

    if not _is_tar(data):
        layout.reason = "not_a_tar_archive"
        return layout

    try:
        archive = tarfile.open(fileobj=io.BytesIO(data))
    except Exception:  # noqa: BLE001
        layout.reason = "unreadable_archive"
        return layout

    with archive:
        try:
            members = archive.getmembers()
        except Exception:  # noqa: BLE001 - a corrupt/truncated archive
            layout.reason = "unreadable_archive"
            return layout

        # `names` is normalised for matching (GNU tar writes "./layer.tar"), but
        # the raw member names are kept because that is what `discover` must
        # hand back to extractfile().
        normalised: dict[str, str] = {}
        for member in members:
            clean = member.name.lstrip("./")
            normalised.setdefault(clean, member.name)
        names = set(normalised)

        if "manifest.json" in names:
            layout.is_container = True
            layout.kind = "docker-save"
            layout.layers = sorted(
                name for name in names if "/" in name and _looks_like_layer(name)
            )
            layout.layer_members = sorted(
                normalised[name] for name in layout.layers if name in normalised
            )
            layout.image_id, layout.tag, layout.config = _docker_manifest(archive)
            return layout

        if "oci-layout" in names or "index.json" in names:
            layout.is_container = True
            layout.kind = "oci"
            layout.layers = sorted(
                name for name in names if name.startswith("blobs/") and name.endswith(".tar")
            )
            layout.layer_members = sorted(
                normalised[name] for name in layout.layers if name in normalised
            )
            layout.config = _oci_config(archive, names)
            return layout

        if any(_looks_like_layer(name) for name in names):
            layout.is_container = True
            layout.kind = "layer-only"
            layout.layers = sorted(name for name in names if _looks_like_layer(name))
            layout.layer_members = sorted(
                normalised[name] for name in layout.layers if name in normalised
            )
            return layout

    layout.reason = "no_image_manifest"
    return layout


def _looks_like_layer(name: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    return base.endswith(".tar") or base.endswith("/layer.tar") or base == "layer.tar"


def _load_json(archive: tarfile.TarFile, name: str) -> dict:
    try:
        member = archive.extractfile(name)
    except Exception:  # noqa: BLE001
        return {}
    if member is None:
        return {}
    try:
        return json.loads(member.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return {}


def _docker_manifest(archive: tarfile.TarFile) -> tuple[str, str, dict]:
    manifest = _load_json(archive, "manifest.json")
    if not isinstance(manifest, list) or not manifest:
        return "", "", {}
    entry = manifest[0] if isinstance(manifest[0], dict) else {}
    config_name = entry.get("Config") or ""
    config = _load_json(archive, config_name) if config_name else {}
    return str(entry.get("Id") or ""), str(entry.get("RepoTags", [""])[0] if entry.get("RepoTags") else ""), config


def _oci_config(archive: tarfile.TarFile, names: set[str]) -> dict:
    index = _load_json(archive, "index.json")
    manifests = index.get("manifests") or []
    if not manifests:
        return {}
    digest = str(manifests[0].get("digest") or "")
    if not digest.startswith("sha256:"):
        return {}
    manifest_blob = f"blobs/sha256/{digest.split(':', 1)[1]}"
    if manifest_blob not in names:
        return {}
    manifest = _load_json(archive, manifest_blob)
    config_digest = str((manifest.get("config") or {}).get("digest") or "")
    if not config_digest.startswith("sha256:"):
        return {}
    return _load_json(archive, f"blobs/sha256/{config_digest.split(':', 1)[1]}")


@dataclass
class Discovery:
    """Everything one image contributed."""

    certificates: list[dict] = field(default_factory=list)
    binaries: list[dict] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    layers_inspected: int = 0
    members_inspected: int = 0


def _reference_finding(image: str, origin: str, kind: str, matched: str) -> dict:
    return {
        "location": f"{image}:{origin}",
        "kind": kind,
        "family": "unknown",
        "algorithm": matched.strip(),
        "library": f"container {kind.replace('_', ' ')}",
        "confidence": 0.7,
        "evidence": {
            "type": "container_reference",
            "detector": "container_image",
            "value": matched.strip().lower(),
            "declared_in": origin,
            "layer": "image metadata",
        },
    }


def inspect_metadata(layout: ImageLayout, image: str) -> list[dict]:
    """Report crypto material declared in the image's own configuration."""
    findings: list[dict] = []
    image_config = (layout.config or {}).get("config") or {}
    blobs: list[tuple[str, str]] = []

    # Docker and OCI both express Env as a list of "KEY=value" strings.
    for entry in image_config.get("Env") or []:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            key, value = entry
        else:
            key, _, value = str(entry).partition("=")
        blobs.append((f"environment variable {key}", value))
    for key, value in (image_config.get("Labels") or {}).items():
        blobs.append((f"label {key}", str(value)))
    for field in ("Entrypoint", "Cmd"):
        value = image_config.get(field)
        if value:
            blobs.append((field.lower(), " ".join(str(part) for part in value)))

    for origin, blob in blobs:
        for pattern, kind in ((_TLS_HINT, "key_reference"), (_KMS_HINT, "key_reference"), (_PQ_HINT, "algorithm")):
            for match in pattern.finditer(blob):
                findings.append(_reference_finding(image, origin, kind, match.group(0)))
                break
    return findings


def discover(location: str, data: bytes, context=None) -> tuple[Discovery, ImageLayout]:
    """Discover cryptographic material inside one container image archive.

    `context` is the caller's ScanContext. Passing it is what makes a large
    image cancellable and lets unrecoverable members be reported as skips
    instead of silently vanishing.
    """
    result = Discovery()
    layout = read_layout(data)
    if not layout.is_container:
        return result, layout

    image = location
    result.references.extend(inspect_metadata(layout, image))

    # Re-open the (possibly decompressed) archive. read_layout already
    # validated and gunzipped it, so do that work once and reuse the result.
    try:
        data = _maybe_gunzip(data)
    except _ArchiveTooLarge:
        return result, layout
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return result, layout

    layer_names = set(layout.layer_members or layout.layers)
    inspected_layers = 0
    with archive:
        try:
            outer_members = archive.getmembers()
        except Exception:  # noqa: BLE001
            return result, layout

        for member in outer_members:
            if context:
                context.check_cancelled()
            if not member.isfile():
                continue
            if layer_names and member.name not in layer_names:
                continue
            if member.size > MEMBER_CAP:
                if context:
                    context.record_skip("member_too_large")
                continue
            with archive.extractfile(member) as handle:
                if handle is None:
                    if context:
                        context.record_skip("unreadable")
                    continue
                layer_bytes = handle.read(MEMBER_CAP)

            # Each layer is itself a tar of the image filesystem, so the walk
            # has to descend one level. Nothing is written to disk.
            members = _open_layer(layer_bytes)
            del layer_bytes
            if members is None:
                if context:
                    context.record_skip("unreadable_archive")
                continue
            inspected_layers += 1
            layer_label = member.name.split("/", 1)[0] if "/" in member.name else member.name

            with members as layer:
                try:
                    entries = layer.getmembers()
                except Exception:  # noqa: BLE001
                    if context:
                        context.record_skip("unreadable_archive")
                    continue

                for entry in entries:
                    if context:
                        context.check_cancelled()
                    if not entry.isfile():
                        continue
                    if entry.size > MEMBER_CAP:
                        if context:
                            context.record_skip("member_too_large")
                        continue
                    if result.members_inspected >= MAX_MEMBERS:
                        if context:
                            context.record_skip("member_limit")
                        break
                    with layer.extractfile(entry) as inner_handle:
                        if inner_handle is None:
                            if context:
                                context.record_skip("unreadable")
                            continue
                        body = inner_handle.read(MEMBER_CAP)
                    result.members_inspected += 1

                    suffix = _suffix_of(entry.name)
                    if suffix not in _CERT_SUFFIXES and not _is_executable(body[:4096]):
                        # Cheap gate: only decode plausible crypto material.
                        if not certstore.looks_like_candidate(suffix, body[:4096]):
                            continue

                    location_in_image = f"{image}:{entry.name}"
                    cert_result = certstore.discover(location_in_image, body)
                    for finding in cert_result.certificates:
                        finding["evidence"]["layer"] = layer_label
                        result.certificates.append(finding)
                    for finding in cert_result.key_references:
                        finding["evidence"]["layer"] = layer_label
                        result.certificates.append(finding)
                    for finding in cert_result.stores:
                        finding["evidence"]["layer"] = layer_label
                        result.certificates.append(finding)

                    for finding in binary_mod.findings_for(
                        location_in_image, body, entry.name
                    ):
                        finding["evidence"]["layer"] = layer_label
                        result.binaries.append(finding)

    result.layers_inspected = inspected_layers
    return result, layout


def _open_layer(data: bytes) -> tarfile.TarFile | None:
    """Open one layer tar, transparently handling gzip."""
    candidates = [data]
    try:
        candidates.insert(0, _maybe_gunzip(data))
    except _ArchiveTooLarge:
        return None
    for candidate in candidates:
        try:
            return tarfile.open(fileobj=io.BytesIO(candidate))
        except Exception:  # noqa: BLE001
            continue
    return None


def _suffix_of(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    dot = base.rfind(".")
    return base[dot:].lower() if dot > 0 else ""


def _is_executable(head: bytes) -> bool:
    return (
        head[:4] == b"\x7fELF"
        or head[:2] == b"MZ"
        or head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
    )
