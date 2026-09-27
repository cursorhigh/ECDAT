"""Dependency manifest parsing.

Real parsers per ecosystem, not substring matching. A dependency without a
version and a scope is not much use, and "did the user actually depend on this
at runtime or only in a test file" changes what a finding means.

Every parser returns the same shape:

    {
        "package": "cryptography",
        "version": "42.0.5",       # best-effort, "" when unpinned
        "ecosystem": "pypi",
        "scope": "runtime",        # runtime | development
        "line": 12,                # 1-based, when the format has lines
    }
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - the backend requires 3.11+
    tomllib = None  # type: ignore[assignment]


@dataclass
class Dependency:
    package: str
    version: str = ""
    ecosystem: str = ""
    scope: str = "runtime"
    line: int | None = None
    extras: list[str] = field(default_factory=list)


# --- ecosystem file names ----------------------------------------------------

MANIFEST_FILES = {
    "package.json": "npm",
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "requirements_dev.txt": "pypi",
    "constraints.txt": "pypi",
    "pyproject.toml": "pypi",
    "Pipfile": "pypi",
    "Pipfile.lock": "pypi",
    "setup.py": "pypi",
    "setup.cfg": "pypi",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle",
    "Cargo.toml": "cargo",
    "go.mod": "gomod",
    "go.sum": "gomod",
    "Gemfile": "bundler",
    "composer.json": "composer",
    "packages.config": "nuget",
    "paket.dependencies": "paket",
}

NUGET_PROJECT_SUFFIXES = (".csproj", ".fsproj", ".vbproj")

# --- crypto relevance --------------------------------------------------------

# Ecosystems where a package is a crypto library *by being in the ecosystem*
# is not true, so relevance is explicit.
#
# level: 3 = a crypto implementation, 2 = a key/cert/transport library,
#        1 = a crypto-adjacent utility, 0 = not classified.
CRYPTO_PACKAGES: dict[str, tuple[int, str, str]] = {
    # (relevance, capability hint, family hint)
    "cryptography": (3, "crypto implementation", "rsa"),
    "pycryptodome": (3, "crypto implementation", "rsa"),
    "pycrypto": (3, "crypto implementation", "rsa"),
    "rsa": (3, "asymmetric crypto", "rsa"),
    "ecdsa": (3, "asymmetric crypto", "ecc"),
    "pynacl": (3, "asymmetric crypto", "ecc"),
    "libsodium": (3, "crypto implementation", "ecc"),
    "openssl": (3, "crypto implementation", "rsa"),
    "botan": (3, "crypto implementation", "rsa"),
    "mbedtls": (3, "crypto implementation", "rsa"),
    "boringssl": (3, "crypto implementation", "rsa"),
    "wolfssl": (3, "crypto implementation", "rsa"),
    "ring": (3, "crypto implementation", "ecc"),
    "rustls": (3, "transport security", "rsa"),
    "bouncycastle": (3, "crypto implementation", "rsa"),
    "bcpkix-jdk18on": (2, "certificate handling", "rsa"),
    "bcprov-jdk18on": (3, "crypto implementation", "rsa"),
    "system.security.cryptography": (3, "crypto implementation", "rsa"),
    "golang.org/x/crypto": (3, "crypto implementation", "rsa"),
    "crypto/tls": (3, "transport security", "rsa"),
    "crypto/x509": (2, "certificate handling", "rsa"),
    "jwt": (2, "token signing", "rsa"),
    "jwt-go": (2, "token signing", "rsa"),
    "pyjwt": (2, "token signing", "rsa"),
    "python-jose": (2, "token signing", "rsa"),
    "python-jwt": (2, "token signing", "rsa"),
    "jose": (2, "token signing", "rsa"),
    "jsonwebtoken": (2, "token signing", "rsa"),
    "jjwt": (2, "token signing", "rsa"),
    "nimbus-jose-jwt": (2, "token signing", "rsa"),
    "jose4j": (2, "token signing", "rsa"),
    "phpseclib": (3, "crypto implementation", "rsa"),
    "paramiko": (2, "transport security", "rsa"),
    "ssh.net": (2, "transport security", "rsa"),
    "asyncssh": (2, "transport security", "ecc"),
    "certbot": (2, "certificate handling", "rsa"),
    "acme": (2, "certificate handling", "rsa"),
    "asn1crypto": (2, "certificate handling", "rsa"),
    "asn1crypto": (2, "certificate handling", "rsa"),
    "pyasn1": (2, "certificate handling", "rsa"),
    "certifi": (1, "trust store", ""),
    "bcrypt": (2, "password hashing", ""),
    "argon2": (2, "password hashing", ""),
    "passlib": (2, "password hashing", ""),
    "scrypt": (2, "password hashing", ""),
    "pbkdf2": (2, "password hashing", ""),
    "tpm2-pytss": (3, "hardware module", ""),
    "tpm2-tss": (3, "hardware module", ""),
    "trousers": (2, "hardware module", ""),
    "softhsm": (2, "hardware module", ""),
    "python-pkcs11": (3, "hardware module", ""),
    "pkcs11": (3, "hardware module", ""),
    "pykcs11": (3, "hardware module", ""),
    "node-pkcs11": (3, "hardware module", ""),
    "pkcs11js": (3, "hardware module", ""),
    "miekg/pkcs11": (3, "hardware module", ""),
    "libykcs11": (3, "hardware module", ""),
    "sunpkcs11": (3, "hardware module", ""),
    "crypto-js": (3, "crypto implementation", "aes"),
    "node-forge": (3, "crypto implementation", "rsa"),
    "jsrsasign": (3, "crypto implementation", "rsa"),
    "tweetnacl": (3, "asymmetric crypto", "ecc"),
    "hashids": (0, "", ""),
    "crypto": (3, "crypto implementation", "rsa"),
    "rsa.js": (3, "asymmetric crypto", "rsa"),
}

# Managed key services: a dependency on these means key material is held
# outside the application.
KMS_PACKAGES = {
    "boto3": "aws",
    "botocore": "aws",
    "@aws-sdk/client-kms": "aws",
    "@aws-sdk/client-acm": "aws",
    "aws-sdk": "aws",
    "aws-sdk-kms": "aws",
    "aws-sdk-java-kms": "aws",
    "aws-sdk-go": "aws",
    "google-cloud-kms": "gcp",
    "google-cloud-security": "gcp",
    "azure-keyvault-keys": "azure",
    "azure-keyvault-secrets": "azure",
    "azure-keyvault-certificates": "azure",
    "azure-security-keyvault-keys": "azure",
    "azure-keyvault": "azure",
    "azure-identity": "azure",
    "hvac": "hashicorp",
    "oci-python-sdk": "oracle",
    "alibabacloud-kms20160120": "alibaba",
}

# Recognised PQC implementations, per the plan's migration direction.
PQC_PACKAGES = {
    "liboqs-python", "pyspx", "kyber-py", "dilithium-py", "pqcrypto",
    "oqs", "liboqs", "pqclean", "classic-mceliece", "hqc",
}


def _line_of(text: str, needle: str) -> int | None:
    key = needle.lower()
    for index, line in enumerate(text.splitlines(), start=1):
        if key in line.lower():
            return index
    return None


# --- parsers -----------------------------------------------------------------

def parse_package_json(text: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[Dependency] = []
    if not isinstance(data, dict):
        return out
    for field, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("peerDependencies", "runtime"),
        ("optionalDependencies", "runtime"),
    ):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for package, spec in block.items():
            version = str(spec).lstrip("^~>=< ") if not isinstance(spec, dict) else ""
            out.append(
                Dependency(
                    package=package,
                    version=version,
                    ecosystem="npm",
                    scope=scope,
                    line=_line_of(text, package),
                )
            )
    return out


_PY_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$")
# Any version-ish token after a comparator, so a range spec still records the
# version the author actually asked for.
_VERSION_TOKEN = re.compile(r"(?:[=<>!~]=|===)\s*([0-9][A-Za-z0-9._+!*-]*)")


def _version_token(rest: str) -> str:
    match = _VERSION_TOKEN.search(rest or "")
    return match.group(1) if match else ""


def parse_requirements_txt(text: str) -> list[Dependency]:
    out: list[Dependency] = []
    scope = "development" if re.search(r"requirements[-_]dev", text[:400], re.I) else "runtime"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-r", "--", "-e", "-c")):
            continue
        match = _PY_REQUIREMENT.match(stripped)
        if not match:
            continue
        package, rest = match.group(1), match.group(2).strip()
        if package.lower() in ("git", "https", "http"):
            continue
        version = _version_token(rest)
        out.append(
            Dependency(
                package=package,
                version=version,
                ecosystem="pypi",
                scope=scope,
                line=_line_of(text, package),
            )
        )
    return out


def parse_pyproject_toml(text: str) -> list[Dependency]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001 - a malformed manifest is simply unparsed
        return []
    out: list[Dependency] = []

    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    for field, scope in (("dependencies", "runtime"), ("optional-dependencies", "runtime")):
        block = project.get(field)
        if isinstance(block, list):
            for spec in block:
                dep = _pep508(str(spec), "pypi", scope, text)
                if dep:
                    out.append(dep)
        elif isinstance(block, dict):
            for group in block.values():
                for spec in group or []:
                    dep = _pep508(str(spec), "pypi", scope, text)
                    if dep:
                        out.append(dep)

    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            for field, scope in (("dependencies", "runtime"), ("dev-dependencies", "development")):
                block = poetry.get(field)
                if isinstance(block, dict):
                    for package, spec in block.items():
                        if package.lower() == "python":
                            continue
                        version = spec if isinstance(spec, str) else str(spec.get("version", ""))
                        out.append(
                            Dependency(
                                package=package,
                                version=version.lstrip("^~"),
                                ecosystem="pypi",
                                scope=scope,
                                line=_line_of(text, package),
                            )
                        )
    return out


def _pep508(spec: str, ecosystem: str, scope: str, text: str) -> Dependency | None:
    spec = spec.split(";", 1)[0].strip()
    spec = spec.split("@", 1)[0].strip()  # drop direct references / URLs
    match = _PY_REQUIREMENT.match(spec)
    if not match:
        return None
    package, rest = match.group(1), match.group(2).strip()
    version = ""
    for operator in ("===", "==", "~=", ">=", "<="):
        if rest.startswith(operator):
            version = rest[len(operator):].strip().split(",")[0].strip()
            break
    return Dependency(
        package=package,
        version=version,
        ecosystem=ecosystem,
        scope=scope,
        line=_line_of(text, package),
    )


def parse_pom_xml(text: str) -> list[Dependency]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[Dependency] = []
    for dependency in root.iter():
        tag = dependency.tag.split("}")[-1]
        if tag != "dependency":
            continue
        group = child_text(dependency, "groupId")
        artifact = child_text(dependency, "artifactId")
        if not artifact:
            continue
        package = f"{group}:{artifact}" if group else artifact
        scope = (child_text(dependency, "scope") or "compile").lower()
        out.append(
            Dependency(
                package=package,
                version=child_text(dependency, "version") or "",
                ecosystem="maven",
                scope="development" if scope in ("test", "provided") else "runtime",
                line=_line_of(text, artifact),
            )
        )
    return out


def child_text(element, name: str) -> str:
    for child in element:
        if child.tag.split("}")[-1] == name:
            return (child.text or "").strip()
    return ""


_GRADLE_DEP = re.compile(
    r"""^\s*(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|
        testCompile|testRuntimeOnly|annotationProcessor|kapt)\s*[( ]\s*['"]([^'"]+)['"]""",
    re.M | re.X,
)


def parse_gradle(text: str) -> list[Dependency]:
    out: list[Dependency] = []
    for index, line in enumerate(text.splitlines(), start=1):
        match = _GRADLE_DEP.search(line)
        if not match:
            continue
        configuration, notation = match.group(1), match.group(2)
        # Gradle notation is group:artifact:version. Splitting on the first
        # colon would report "org.bouncycastle" as the package and the artifact
        # as the version, so take the last segment as the version.
        head, separator, tail = notation.rpartition(":")
        package = head if separator else notation
        version = tail if separator else ""
        out.append(
            Dependency(
                package=package,
                version=version,
                ecosystem="gradle",
                scope="development" if configuration.lower().startswith("test") else "runtime",
                line=index,
            )
        )
    return out


def parse_cargo_toml(text: str) -> list[Dependency]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return []
    out: list[Dependency] = []
    for field, scope in (("dependencies", "runtime"), ("dev-dependencies", "development"),
                         ("build-dependencies", "development")):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for package, spec in block.items():
            version = ""
            if isinstance(spec, dict):
                version = str(spec.get("version", ""))
            elif isinstance(spec, str):
                version = spec
            out.append(
                Dependency(
                    package=package,
                    version=version,
                    ecosystem="cargo",
                    scope=scope,
                    line=_line_of(text, package),
                )
            )
    return out


_GO_REQUIRE = re.compile(r"^\s*([a-z0-9.\-]+\.[a-z0-9.\-]+/[^\s]+)\s*(v[^\s]*)?$", re.M)
_GO_EXCLUDE = re.compile(r"^\s*//\s*indirect\b", re.M)


def parse_go_mod(text: str) -> list[Dependency]:
    out: list[Dependency] = []
    in_block = False
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        candidate = None
        if in_block:
            match = re.match(r"^([^\s]+)\s*(v[^\s]+)?", stripped)
            if match:
                candidate = (match.group(1), match.group(2) or "")
        elif stripped.startswith("require "):
            match = re.match(r"^require\s+([^\s]+)\s*(v[^\s]+)?", stripped)
            if match:
                candidate = (match.group(1), match.group(2) or "")
        if not candidate:
            continue
        package, version = candidate
        if package in ("github.com/pkg/errors",):  # keep parsing simple
            pass
        out.append(
            Dependency(
                package=package,
                version=version.lstrip("v"),
                ecosystem="gomod",
                # `// indirect` marks a transitive dependency.
                scope="development" if "// indirect" in stripped else "runtime",
                line=index,
            )
        )
    return out


_GEM = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", re.M)


def parse_gemfile(text: str) -> list[Dependency]:
    out: list[Dependency] = []
    in_development = False
    for index, line in enumerate(text.splitlines(), start=1):
        if re.search(r"^\s*group\s+:development\b", line) or re.search(r"^\s*group\s+:test\b", line):
            in_development = True
        elif re.match(r"^\s*end\s*$", line):
            in_development = False

        match = re.match(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line)
        if not match:
            continue
        out.append(
            Dependency(
                package=match.group(1),
                version=match.group(2) or "",
                ecosystem="bundler",
                scope="development" if in_development else "runtime",
                line=index,
            )
        )
    return out


def parse_composer_json(text: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Dependency] = []
    for field, scope in (("require", "runtime"), ("require-dev", "development")):
        block = data.get(field)
        if isinstance(block, dict):
            for package, version in block.items():
                if package == "php":
                    continue
                out.append(
                    Dependency(
                        package=package,
                        version=str(version).lstrip("^~"),
                        ecosystem="composer",
                        scope=scope,
                        line=_line_of(text, package),
                    )
                )
    return out


def parse_nuget_project(text: str) -> list[Dependency]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[Dependency] = []
    for reference in root.iter():
        if reference.tag.split("}")[-1] != "PackageReference":
            continue
        package = reference.attrib.get("Include", "")
        if not package:
            continue
        version = reference.attrib.get("Version", "")
        out.append(
            Dependency(
                package=package,
                version=version,
                ecosystem="nuget",
                scope="development" if "PrivateAssets" in ET.tostring(reference, encoding="unicode") else "runtime",
                line=_line_of(text, package),
            )
        )
    return out


_PARSERS = {
    "npm": parse_package_json,
    "pypi": None,  # chosen by filename
    "maven": parse_pom_xml,
    "gradle": parse_gradle,
    "cargo": parse_cargo_toml,
    "gomod": parse_go_mod,
    "bundler": parse_gemfile,
    "composer": parse_composer_json,
    "nuget": parse_nuget_project,
}


def ecosystem_for(filename: str) -> str:
    """Ecosystem for a manifest filename, or "" when it is not a manifest."""
    if filename in MANIFEST_FILES:
        return MANIFEST_FILES[filename]
    if filename.endswith(NUGET_PROJECT_SUFFIXES):
        return "nuget"
    return ""


def parse_manifest(filename: str, text: str) -> list[Dependency]:
    """Parse a manifest into dependencies. Unknown files yield nothing."""
    ecosystem = ecosystem_for(filename)
    if not ecosystem:
        return []
    if ecosystem == "pypi":
        if filename == "pyproject.toml":
            return parse_pyproject_toml(text)
        if filename == "Pipfile":
            return parse_pipfile(text)
        if filename == "Pipfile.lock":
            return parse_pipfile_lock(text)
        if filename in ("setup.py", "setup.cfg"):
            return parse_setup(text)
        return parse_requirements_txt(text)
    parser = _PARSERS.get(ecosystem)
    return parser(text) if parser else []


def parse_pipfile(text: str) -> list[Dependency]:
    out: list[Dependency] = []
    for index, line in enumerate(text.splitlines(), start=1):
        match = re.match(r"""^\s*["']?([A-Za-z0-9._-]+)["']?\s*=\s*["']([^"']+)["']""", line)
        if not match:
            continue
        version = match.group(2).lstrip("=")
        if match.group(1) == "python":
            continue
        out.append(
            Dependency(
                package=match.group(1),
                version=version.lstrip("*"),
                ecosystem="pypi",
                scope="development" if "[dev-packages]" in text[:index] else "runtime",
                line=index,
            )
        )
    return out


def parse_pipfile_lock(text: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[Dependency] = []
    for field, scope in (("default", "runtime"), ("develop", "development")):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for package, spec in block.items():
            version = ""
            if isinstance(spec, dict):
                version = str(spec.get("version", "")).lstrip("=")
            out.append(
                Dependency(
                    package=package,
                    version=version,
                    ecosystem="pypi",
                    scope=scope,
                    line=_line_of(text, package),
                )
            )
    return out


_SETUP_CALL = re.compile(r"""["']([A-Za-z0-9._-]+)\s*(?:[=<>!~]=|>=)\s*([0-9][^"']*)["']""")


def parse_setup(text: str) -> list[Dependency]:
    out: list[Dependency] = []
    for match in _SETUP_CALL.finditer(text):
        out.append(
            Dependency(
                package=match.group(1),
                version=match.group(2).strip(),
                ecosystem="pypi",
                scope="runtime",
                line=text.count("\n", 0, match.start()) + 1,
            )
        )
    return out


# --- classification ----------------------------------------------------------

# .NET and Java ship crypto inside larger namespace trees, so a single package
# name never matches. Match on the namespace prefix instead.
NAMESPACE_CRYPTO: list[tuple[str, int, str, str]] = [
    ("system.security.cryptography", 3, "crypto implementation", "rsa"),
    ("microsoft.identitymodel", 2, "token signing", "rsa"),
    ("bouncycastle.cryptography", 3, "crypto implementation", "rsa"),
    ("azure.security.keyvault", 2, "externally held key material", ""),
    ("awssdk.kms", 2, "externally held key material", ""),
    ("org.bouncycastle", 3, "crypto implementation", "rsa"),
    ("com.nimbusds.jose", 2, "token signing", "rsa"),
    ("io.jsonwebtoken", 2, "token signing", "rsa"),
    ("org.apache.tomcat", 1, "transport security", "rsa"),
    ("software.amazon.awssdk", 2, "externally held key material", ""),
]


def classify_dependency(dependency: Dependency) -> dict:
    """Classify a dependency's cryptographic relevance.

    Relevance is a discovery fact about the package, not a verdict about the
    application. A dev-only test helper and a production KMS client are both
    "crypto", and the difference matters later.
    """
    package = dependency.package.lower()
    base = package.split("/")[-1].split(":")[-1].split(".")[-1] if package else ""

    if package in KMS_PACKAGES or base in KMS_PACKAGES:
        return {
            "is_crypto": True,
            "relevance": "managed_key_service",
            "capability": "externally held key material",
            "system": KMS_PACKAGES.get(package) or KMS_PACKAGES.get(base, ""),
            "family": "unknown",
        }

    if package in PQC_PACKAGES or base in PQC_PACKAGES:
        return {
            "is_crypto": True,
            "relevance": "post_quantum",
            "capability": "post-quantum algorithm",
            "family": "pqc",
        }

    for name, (relevance, capability, family) in CRYPTO_PACKAGES.items():
        if package == name or base == name:
            return {
                "is_crypto": True,
                "relevance": {3: "core", 2: "supporting", 1: "adjacent"}[relevance],
                "capability": capability,
                "family": family or "unknown",
            }

    for namespace, relevance, capability, family in NAMESPACE_CRYPTO:
        if package.startswith(namespace):
            return {
                "is_crypto": True,
                "relevance": {3: "core", 2: "supporting", 1: "adjacent"}[relevance],
                "capability": capability,
                "family": family or "unknown",
            }

    return {
        "is_crypto": False,
        "relevance": "",
        "capability": "",
        "family": "unknown",
    }
