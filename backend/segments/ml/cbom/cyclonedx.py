"""CycloneDX serialisation for the CBOM.

Milestone 11: a Cryptographic Bill of Materials in a format other tools
actually read. CycloneDX 1.6 is the current specification and is the first
version with a first-class ``cryptographic-asset`` component type and
``cryptoProperties``, which is exactly what discovery produces.

Written by hand rather than pulling in ``cyclonedx-python-lib`` so the project
keeps its existing dependency set and so the mapping from ECDAT's evidence model
to the spec's vocabulary is explicit and reviewable.

Two rules govern every field emitted here:

* **Never claim more than was observed.** ``cryptoFunctions`` describes what a
  primitive is *capable* of, which is a property of the algorithm; nothing in
  this module asserts that a given call site used it that way. Where a value
  cannot be determined it is omitted rather than defaulted, because CycloneDX
  consumers read a zero as a real measurement.
* **Every ECDAT-specific fact is kept** as a ``properties`` entry under the
  ``ecdat:`` namespace, so nothing is lost in translation.
"""

from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"
NAMESPACE = f"http://cyclonedx.org/schema/bom/{SPEC_VERSION}"
TOOL_NAME = "ECDAT"
TOOL_VERSION = "1.0"

# --- family -> CycloneDX cryptographic primitive ---------------------------
# The spec's enum. Where a family genuinely covers more than one primitive
# (ECC can be signing or key agreement) the base primitive is named and the
# ambiguity is recorded as a property rather than silently resolved.
_FAMILY_PRIMITIVE = {
    "rsa": "pke",
    "ecc": "pke",
    "dsa": "signature",
    "dh": "key-agree",
    "aes": "block-cipher",
    "des3": "block-cipher",
    "hash": "hash",
    "mac": "mac",
    "unknown": "unknown",
}

# PQC needs the specific primitive, and the algorithm name is enough to know it.
_PQC_PRIMITIVES = (
    (("ml-kem", "mlkem", "kyber"), "kem"),
    (("ml-dsa", "mldsa", "dilithium"), "signature"),
    (("slh-dsa", "sphincs"), "signature"),
    (("xmss",), "signature"),
)

# What each primitive is capable of. This is a property of the algorithm, not an
# observation about how the code uses it.
_PRIMITIVE_FUNCTIONS = {
    "pke": ["encrypt", "decrypt"],
    "signature": ["sign", "verify"],
    "hash": ["digest"],
    "mac": ["tag"],
    "kdf": ["keyderive"],
    # The spec's enum has `keyderive`, not `derive`; using the latter would make
    # the document schema-invalid.
    "key-agree": ["keyderive"],
    "kem": ["encapsulate", "decapsulate"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
    "ae": ["encrypt", "decrypt", "tag"],
    "drbg": ["generate"],
}

# NIST-equivalent classical security strength in bits, keyed by
# (family, key_size). Reporting the raw key length here would be wrong: the
# spec asks for security strength, and RSA-2048 is 112 bits, not 2048.
_RSA_STRENGTH = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 8192: 200}
_ECC_STRENGTH = {160: 80, 192: 96, 224: 112, 256: 128, 384: 192, 521: 256}
_HASH_STRENGTH = {
    160: 80, 192: 96, 224: 112, 256: 128, 384: 192, 512: 256,
    224: 112,
}
_DES3_STRENGTH = {168: 112}

# NIST post-quantum security categories for the algorithms we can name.
_PQC_NIST_LEVEL = {
    "ml-kem-512": 1, "ml-kem-768": 3, "ml-kem-1024": 5,
    "ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 5,
    "slh-dsa-128": 3,
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _primitive_for(family: str, algorithm: str) -> str:
    name = (algorithm or "").lower()
    if family == "pqc" or any(token in name for token in ("ml-kem", "kyber", "ml-dsa", "dilithium")):
        for tokens, primitive in _PQC_PRIMITIVES:
            if any(token in name for token in tokens):
                return primitive
        return "other"
    return _FAMILY_PRIMITIVE.get(family, "unknown")


def _classical_strength(family: str, key_size: int | None) -> int | None:
    """NIST-equivalent security strength in bits, or None when unknown."""
    if not key_size:
        return None
    if family == "rsa":
        return _RSA_STRENGTH.get(key_size)
    if family == "dsa":
        return _RSA_STRENGTH.get(key_size)
    if family == "dh":
        return _RSA_STRENGTH.get(key_size)
    if family == "ecc":
        return _ECC_STRENGTH.get(key_size)
    if family in ("aes",):
        return key_size if key_size in (128, 192, 256) else None
    if family == "des3":
        return _DES3_STRENGTH.get(key_size)
    if family == "hash":
        return _HASH_STRENGTH.get(key_size)
    return None


def _nist_level(algorithm: str) -> int | None:
    name = (algorithm or "").lower()
    for token, level in _PQC_NIST_LEVEL.items():
        if token in name:
            return level
    return None


def _mode_from_protocol(protocol: str) -> str | None:
    token = (protocol or "").strip().lower()
    if not token:
        return None
    for mode in ("gcm", "cbc", "ctr", "ccm", "ecb", "ofb", "cfb", "xts"):
        if mode in token:
            return mode
    return None


def _ref_for(asset: dict[str, Any], index: int) -> str:
    """A stable, unique bom-ref.

    Prefers ECDAT's content-derived identifier so the same artefact keeps the
    same ref across exports, which is what makes two CBOMs diffable.
    """
    for field in ("identifier", "asset_id", "id"):
        value = asset.get(field)
        if value:
            return f"urn:ecdat:asset:{value}"
    # No identifier recorded: derive one from the content so repeated exports of
    # the same asset still produce the same ref.
    name = str(asset.get("name") or "")
    digest = uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:{index}:{name}")
    return f"urn:ecdat:asset:{digest}"


def _component_type(asset: dict[str, Any]) -> str:
    """CycloneDX 1.6 component type.

    `cryptographic-asset` exists specifically for this content, so it is the
    default; a library reference is a `library` and a source location is a
    `file`.
    """
    kind = str(asset.get("kind") or asset.get("asset_type") or "").lower()
    if kind in ("library", "dependency"):
        return "library"
    if kind == "source_code":
        return "file"
    if kind == "application":
        return "application"
    if kind == "container":
        return "container"
    return "cryptographic-asset"


def _crypto_asset_type(family: str, kind: str) -> str:
    """CycloneDX `assetType`, which is coarser than the algorithm."""
    if kind == "certificate":
        return "certificate"
    if kind in ("key", "key_reference"):
        return "related-crypto-material"
    if kind == "protocol":
        return "protocol"
    if family == "hash":
        return "algorithm"
    return "algorithm"


def _component(asset: dict[str, Any], index: int) -> dict[str, Any]:
    family = str(asset.get("family") or "unknown").lower()
    algorithm = str(asset.get("algorithm") or "")
    kind = str(asset.get("kind") or asset.get("asset_type") or "").lower()
    key_size = asset.get("key_size")
    curve = str(asset.get("curve") or "")
    protocol = str(asset.get("protocol") or "")
    library = str(asset.get("library") or "")
    version = str(asset.get("library_version") or "")
    confidence = asset.get("confidence")
    status = str(asset.get("validation_status") or "")
    location = str(asset.get("location") or "")

    component: dict[str, Any] = {
        "type": _component_type(asset),
        "bom-ref": _ref_for(asset, index),
        "name": str(asset.get("name") or algorithm or family or "unknown"),
    }
    if version:
        component["version"] = version
    if library and component["type"] == "library":
        component["group"] = library
    elif library:
        component["publisher"] = library

    # --- cryptographic properties ----------------------------------------
    crypto: dict[str, Any] = {
        "assetType": _crypto_asset_type(family, kind),
    }

    algorithm_properties: dict[str, Any] = {
        "primitive": _primitive_for(family, algorithm),
        # Discovery is static: nothing is ever loaded or executed to make these
        # observations, so the execution environment is a known fact.
        "executionEnvironment": "software-plain-ram",
    }
    if key_size:
        algorithm_properties["parameterSetIdentifier"] = str(key_size)
    if curve:
        algorithm_properties["curve"] = curve
    functions = _PRIMITIVE_FUNCTIONS.get(algorithm_properties["primitive"])
    if functions:
        algorithm_properties["cryptoFunctions"] = list(functions)
    strength = _classical_strength(family, key_size)
    if strength is not None:
        algorithm_properties["classicalSecurityLevel"] = strength
    nist = _nist_level(algorithm)
    if nist is not None:
        algorithm_properties["nistQuantumSecurityLevel"] = nist
    mode = _mode_from_protocol(protocol)
    if mode:
        algorithm_properties["mode"] = mode
    if len(algorithm_properties) > 2:
        crypto["algorithmProperties"] = algorithm_properties

    if kind == "certificate":
        evidence = asset.get("evidence") or {}
        certificate = {}
        for source, target in (
            ("subject", "subjectName"),
            ("issuer", "issuerName"),
            ("not_before", "notValidBefore"),
            ("not_after", "notValidAfter"),
            ("serial", "serialNumber"),
        ):
            if evidence.get(source):
                certificate[target] = str(evidence[source])
        if evidence.get("sha256_fingerprint"):
            component["hashes"] = [
                {"alg": "SHA-256", "content": str(evidence["sha256_fingerprint"])}
            ]
        if certificate:
            crypto["certificateProperties"] = certificate

    if kind in ("key", "key_reference"):
        material = {"type": "key"}
        if kind == "key_reference":
            material["type"] = "public-key"
        if key_size:
            material["size"] = int(key_size)
        if asset.get("line"):
            material["id"] = f"line {asset['line']}"
        crypto["relatedCryptoMaterialProperties"] = material

    if kind == "protocol" or protocol:
        protocol_properties: dict[str, Any] = {}
        token = protocol.lower()
        for candidate, kind_name in (
            ("tls", "tls"), ("ssh", "ssh"), ("ipsec", "ipsec"),
            ("ike", "ike"), ("sstp", "sstp"), ("wpa", "wpa"),
        ):
            if candidate in token:
                protocol_properties["type"] = kind_name
                break
        if asset.get("protocol_version"):
            protocol_properties["version"] = str(asset["protocol_version"])
        if protocol_properties:
            crypto["protocolProperties"] = protocol_properties

    component["cryptoProperties"] = crypto

    # --- ECDAT-specific facts, kept rather than dropped -------------------
    properties: list[dict[str, str]] = []
    if family:
        properties.append({"name": "ecdat:family", "value": family})
    if key_size:
        properties.append({"name": "ecdat:key-size", "value": str(key_size)})
    if curve:
        properties.append({"name": "ecdat:curve", "value": curve})
    if protocol:
        properties.append({"name": "ecdat:protocol", "value": protocol})
    if library:
        properties.append({"name": "ecdat:library", "value": library})
    if version:
        properties.append({"name": "ecdat:library-version", "value": version})
    if location:
        properties.append({"name": "ecdat:location", "value": location})
    if status:
        properties.append({"name": "ecdat:validation-status", "value": status})
    if confidence is not None:
        properties.append({"name": "ecdat:confidence", "value": str(confidence)})
    if asset.get("explanation"):
        properties.append({"name": "ecdat:explanation", "value": str(asset["explanation"])})
    if asset.get("evidence_type"):
        properties.append({"name": "ecdat:evidence-type", "value": str(asset["evidence_type"])})
    if asset.get("detector"):
        properties.append({"name": "ecdat:detector", "value": str(asset["detector"])})
    if kind:
        properties.append({"name": "ecdat:kind", "value": kind})
    if properties:
        component["properties"] = properties

    return component


def _dependencies(
    refs: list[str],
    edges: list[tuple[str, str]] | None,
    root_ref: str,
) -> list[dict[str, Any]]:
    """CycloneDX dependency graph.

    Every component gets an entry, including ones with no outgoing edges --
    the spec expects a complete entry per component, and omitting them makes
    consumers treat the component as unknown rather than as a leaf.
    """
    outgoing: dict[str, list[str]] = {}
    for source, target in edges or []:
        outgoing.setdefault(source, []).append(target)
    entries = [{"ref": root_ref, "dependsOn": []}]
    for ref in refs:
        depends = [d for d in outgoing.get(ref, []) if d != ref]
        entries.append({"ref": ref, "dependsOn": sorted(set(depends))})
    return entries


def to_cyclonedx(
    native_document: dict[str, Any],
    dependency_edges: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Convert an ECDAT CBOM document into a CycloneDX 1.6 BOM."""
    assets = list(native_document.get("crypto_assets") or [])
    components = [_component(asset, index) for index, asset in enumerate(assets)]
    refs = [component["bom-ref"] for component in components]

    repository = native_document.get("repository") or {}
    root_component: dict[str, Any] = {
        "type": "application",
        "bom-ref": "urn:ecdat:repository",
        "name": str(repository.get("name") or "ECDAT inventory"),
    }
    if repository.get("url"):
        root_component["externalReferences"] = [
            {"type": "vcs", "url": str(repository["url"])}
        ]

    document: dict[str, Any] = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": native_document.get("generated_at") or _iso_now(),
            "tools": {
                "components": [
                    {"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}
                ]
            },
            "component": root_component,
            "properties": _summary_properties(native_document),
        },
        "components": components,
        "dependencies": _dependencies(refs, dependency_edges, "urn:ecdat:repository"),
    }
    return document


def _summary_properties(native_document: dict[str, Any]) -> list[dict[str, str]]:
    """Carry the ECDAT summary across as properties.

    A CycloneDX consumer has no notion of "needs review", and that distinction
    is the whole point of recording confidence, so it must survive export.
    """
    summary = native_document.get("summary") or {}
    properties: list[dict[str, str]] = []
    for key in (
        "total_assets", "confirmed_assets", "partial_assets",
        "needs_review_assets", "invalid_assets",
    ):
        if key in summary:
            properties.append({"name": f"ecdat:{key}", "value": str(summary[key])})
    for family, count in (summary.get("by_family") or {}).items():
        properties.append({"name": f"ecdat:family-count:{family}", "value": str(count)})
    return properties


# --- XML ------------------------------------------------------------------

def _xml_element(parent: ET.Element, tag: str, text: Any = None,
                 attrib: dict[str, str] | None = None) -> ET.Element:
    element = ET.SubElement(parent, tag, attrib or {})
    if text is not None:
        element.text = str(text)
    return element


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def to_cyclonedx_xml(document: dict[str, Any]) -> str:
    """Render a CycloneDX document as XML (1.6 schema namespace)."""
    ET.register_namespace("", NAMESPACE)
    root = ET.Element(f"{{{NAMESPACE}}}bom")

    _xml_element(root, "bomFormat", document["bomFormat"])
    _xml_element(root, "specVersion", document["specVersion"])
    _xml_element(root, "serialNumber", document["serialNumber"])
    _xml_element(root, "version", document["version"])

    metadata = ET.SubElement(root, "metadata")
    _xml_element(metadata, "timestamp", document["metadata"]["timestamp"])
    tools = ET.SubElement(metadata, "tools")
    for component in document["metadata"]["tools"]["components"]:
        node = ET.SubElement(tools, "component")
        _xml_element(node, "type", component["type"])
        _xml_element(node, "name", component["name"])
        _xml_element(node, "version", component["version"])
    root_component = document["metadata"]["component"]
    node = ET.SubElement(metadata, "component")
    _xml_element(node, "type", root_component["type"])
    _xml_element(node, "bom-ref", root_component["bom-ref"])
    _xml_element(node, "name", root_component["name"])
    for reference in root_component.get("externalReferences") or []:
        refs = ET.SubElement(node, "externalReferences")
        ref = ET.SubElement(refs, "reference")
        _xml_element(ref, "type", reference["type"])
        _xml_element(ref, "url", reference["url"])
    for prop in document["metadata"].get("properties") or []:
        properties = ET.SubElement(metadata, "properties")
        entry = ET.SubElement(properties, "property")
        _xml_element(entry, "name", prop["name"])
        _xml_element(entry, "value", prop["value"])

    components = ET.SubElement(root, "components")
    for component in document["components"]:
        _xml_component(components, component)

    dependencies = ET.SubElement(root, "dependencies")
    for entry in document["dependencies"]:
        node = ET.SubElement(dependencies, "dependency")
        _xml_element(node, "ref", entry["ref"])
        for ref in entry["dependsOn"]:
            _xml_element(node, "dependency", ref)

    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body


def _xml_component(parent: ET.Element, component: dict[str, Any]) -> None:
    node = ET.SubElement(parent, "component")
    _xml_element(node, "type", component["type"])
    _xml_element(node, "bom-ref", component["bom-ref"])
    _xml_element(node, "name", component["name"])
    if component.get("version"):
        _xml_element(node, "version", component["version"])
    if component.get("group"):
        _xml_element(node, "group", component["group"])
    if component.get("publisher"):
        _xml_element(node, "publisher", component["publisher"])

    for entry in component.get("hashes") or []:
        hashes = ET.SubElement(node, "hashes")
        hash_node = ET.SubElement(hashes, "hash")
        _xml_element(hash_node, "alg", entry["alg"])
        _xml_element(hash_node, "content", entry["content"])

    crypto = component.get("cryptoProperties")
    if crypto:
        crypto_node = ET.SubElement(node, "cryptoProperties")
        _xml_element(crypto_node, "assetType", crypto.get("assetType"))
        algorithm_properties = crypto.get("algorithmProperties")
        if algorithm_properties:
            properties = ET.SubElement(crypto_node, "algorithmProperties")
            for key, value in algorithm_properties.items():
                if key == "cryptoFunctions":
                    for function in value:
                        _xml_element(properties, "cryptoFunction", function)
                else:
                    _xml_element(properties, key, value)
        certificate = crypto.get("certificateProperties")
        if certificate:
            properties = ET.SubElement(crypto_node, "certificateProperties")
            for key, value in certificate.items():
                _xml_element(properties, key, value)
        material = crypto.get("relatedCryptoMaterialProperties")
        if material:
            properties = ET.SubElement(crypto_node, "relatedCryptoMaterialProperties")
            for key, value in material.items():
                _xml_element(properties, key, value)
        protocol_properties = crypto.get("protocolProperties")
        if protocol_properties:
            properties = ET.SubElement(crypto_node, "protocolProperties")
            for key, value in protocol_properties.items():
                _xml_element(properties, key, value)

    if component.get("properties"):
        properties = ET.SubElement(node, "properties")
        for prop in component["properties"]:
            entry = ET.SubElement(properties, "property")
            _xml_element(entry, "name", prop["name"])
            _xml_element(entry, "value", prop["value"])
