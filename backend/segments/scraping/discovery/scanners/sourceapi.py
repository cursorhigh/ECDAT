"""Cryptographic API detection in source code.

Python is parsed with `ast`, so findings carry the real call, its line, and the
literal algorithm argument. Other languages use curated symbol tables: without a
parser for each grammar, a precise symbol match with a recorded line is the
honest maximum, and the evidence says so (`type: "symbol_match"` vs
`"ast_call"`) so downstream reasoning can weight them differently.

Confidence reflects how the observation was made. Nothing here asserts that a
use is safe or unsafe -- that judgement belongs to the Understand stage.
"""

from __future__ import annotations

import ast
import re

# --- algorithm normalisation -------------------------------------------------

_ALGORITHM_FAMILIES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^rsa|rsassa|rsadsa|pkcs1|oaep|pss", re.I), "rsa"),
    (re.compile(r"^ecdsa|^ecdsa_|^ec$|secp|prime256|curve25519|^ed25519|^ed448|^x25519|^x448", re.I), "ecc"),
    (re.compile(r"^dsa", re.I), "dsa"),
    (re.compile(r"^dh$|diffie|ecdh|^dh_", re.I), "dh"),
    (re.compile(r"^ml-kem|^mlkem|kyber|^ml-dsa|^mldsa|dilithium|^slh-dsa|^slhdsa|falcon|^sphincs", re.I), "pqc"),
    (re.compile(r"^aes|^aes-", re.I), "aes"),
    (re.compile(r"^des$|^des-|\bdesede|^3des|^tripledes|^des3", re.I), "des3"),
    # Not an algorithm family the inventory models: record the name, let the
    # family fall through to `unknown` rather than inventing a bucket.
    (re.compile(r"^blowfish|^rc2|^rc4|^rc5", re.I), "unknown"),
    (re.compile(r"^chacha|^salsa|^aria|^camellia|^sm4", re.I), "unknown"),
    (re.compile(r"^sha-?(?:1|224|256|384|512)|^sha$|^sha3|^shake", re.I), "hash"),
    (re.compile(r"^md5|^md4|^md2", re.I), "hash"),
    (re.compile(r"^hmac", re.I), "mac"),
    (re.compile(r"^cmac|^gmac|^poly1305", re.I), "mac"),
    (re.compile(r"^hkdf|^pbkdf2|^scrypt|^argon2|^bcrypt", re.I), "unknown"),
    (re.compile(r"^tls|^ssl|^mtls|^https$", re.I), "unknown"),
]

_WEAK_ALGORITHMS = re.compile(
    r"^(?:des|des-ede|desede3|3des|tripledes|rc2|rc4|rc5|blowfish|md4|md2)$", re.I
)
_DEPRECATED_HASHES = re.compile(r"^(?:sha-?1|sha1|md5|md4|md2)$", re.I)
_SMALL_RSA = re.compile(r"rsa[^0-9]{0,12}([0-9]{3,4})\b", re.I)

# --- Python: crypto API surface ---------------------------------------------

_PY_CRYPTO_CALLS: dict[str, str] = {
    # --- key generation (cryptography) ---------------------------------
    "rsa.generate_private_key": "rsa",
    "rsa.RSAPrivateNumbers": "rsa",
    "rsa.RSAPublicNumbers": "rsa",
    "rsa_crt.RSAPrivateNumbers": "rsa",
    "ec.generate_private_key": "ecc",
    "ec.derive_private_key": "ecc",
    "ec.EllipticCurvePrivateKey": "ecc",
    "ec.EllipticCurvePublicKey": "ecc",
    "dsa.generate_private_key": "dsa",
    "dsa.DSAPrivateNumbers": "dsa",
    "dh.generate_parameters": "dh",
    "dh.generate_private_key": "dh",
    "x25519.X25519PrivateKey.generate": "ecc",
    "x25519.X25519PublicKey.from_public_bytes": "ecc",
    "x448.X448PrivateKey.generate": "ecc",
    "ed25519.Ed25519PrivateKey.generate": "ecc",
    "ed25519.Ed25519PublicKey.from_public_bytes": "ecc",
    "ed448.Ed448PrivateKey.generate": "ecc",
    # --- symmetric ------------------------------------------------------
    "Cipher": "aes", "AES.new": "aes", "AESGCM": "aes", "AESCBC": "aes",
    "Fernet": "aes", "ChaCha20Poly1305": "aes", "ChaCha20.new": "aes",
    "TripleDES.new": "des3", "DES3.new": "des3", "des3.new": "des3",
    "Blowfish.new": "legacy", "ARC4.new": "legacy", "ARC2.new": "legacy",
    "CAST5.new": "legacy", "IDEA.new": "legacy",
    # --- hashes / mac ---------------------------------------------------
    "hashlib.md5": "hash", "hashlib.sha1": "hash", "hashlib.sha224": "hash",
    "hashlib.sha256": "hash", "hashlib.sha384": "hash", "hashlib.sha512": "hash",
    "hashlib.sha3_224": "hash", "hashlib.sha3_256": "hash", "hashlib.sha3_512": "hash",
    "hashlib.blake2b": "hash", "hashlib.blake2s": "hash", "hashlib.new": "hash",
    "md5": "hash", "sha1": "hash", "sha256": "hash", "new": "hash",
    "hmac.new": "mac", "hmac.digest": "mac", "hmac.compare_digest": "mac",
    "CMAC.new": "mac", "GMAC.new": "mac", "poly1305.Poly1305": "mac",
    # --- kdf ------------------------------------------------------------
    "PBKDF2HMAC": "kdf", "Scrypt": "kdf", "HKDF": "kdf", "HKDFExpand": "kdf",
    "bcrypt.hashpw": "kdf", "bcrypt.gensalt": "kdf", "bcrypt.kdf": "kdf",
    "argon2.PasswordHasher": "kdf", "derive": "kdf", "scrypt": "kdf",
    # --- keys / certificates -------------------------------------------
    "serialization.load_pem_private_key": "key",
    "serialization.load_der_private_key": "key",
    "serialization.load_pem_public_key": "key",
    "serialization.load_der_public_key": "key",
    "serialization.load_ssh_public_key": "key",
    "serialization.load_ssh_private_key": "key",
    "load_pem_private_key": "key", "load_pem_public_key": "key",
    "load_ssh_public_key": "key", "load_ssh_private_key": "key",
    "x509.load_pem_x509_certificate": "certificate",
    "x509.load_der_x509_certificate": "certificate",
    "x509.load_pem_x509_certificates": "certificate",
    "load_pem_x509_certificate": "certificate",
    "CertificateStore": "certificate", "PKCS12": "certificate",
    # --- transport / protocol ------------------------------------------
    "ssl.SSLContext": "protocol", "ssl.wrap_socket": "protocol",
    "ssl.create_default_context": "protocol", "ssl.SSLSocket": "protocol",
    "jwt.encode": "protocol", "jwt.decode": "protocol",
    "jose.jwt": "protocol", "JoseJWT": "protocol",
    "nacl.signing.SigningKey": "ecc", "nacl.public.PublicKey": "ecc",
}

_PY_ALGORITHM_LITERALS = re.compile(
    r"^(?:rsa|dsa|ec|ecdsa|ecc|aes(?:-\d+)?|aes-\d+-(?:gcm|cbc|ctr|cfb|ofb|ecb)?|"
    r"des|desede|desede3|3des|chacha20|chacha20-poly1305|arc4|rc4|blowfish|"
    r"sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512|blake2b|blake2s|md5|"
    r"hmac|pbkdf2|scrypt|argon2)$",
    re.I,
)


def normalise_algorithm(raw: str) -> tuple[str, str]:
    """Map a raw algorithm token to (family, display name)."""
    name = (raw or "").strip()
    for pattern, family in _ALGORITHM_FAMILIES:
        if pattern.search(name):
            return family, name
    return "unknown", name


def classify_algorithm_strength(algorithm: str, key_size: int | None) -> str | None:
    """Return a factual weakness note (NIST SP 800-131A / OWASP), never a verdict."""
    algo = (algorithm or "").strip()
    if not algo:
        return None
    if _WEAK_ALGORITHMS.match(algo):
        return "legacy_primitive"
    if _DEPRECATED_HASHES.match(algo):
        return "deprecated_hash"
    small = _SMALL_RSA.search(algo)
    if key_size and key_size < 2048 and re.search(r"rsa|dsa", algo, re.I):
        return "key_below_2048"
    if small and int(small.group(1)) < 2048:
        return "key_below_2048"
    return None


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _string_args(call: ast.Call) -> list[str]:
    values = []
    for arg in list(call.args)[:4] + [kw.value for kw in call.keywords[:3]]:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            values.append(arg.value)
    return values


def _int_args(call: ast.Call) -> int | None:
    """First integer argument, positional or keyword.

    Key size is usually passed by keyword (`key_size=2048`), so checking
    positional args only loses the single most useful field on a finding.
    """
    for arg in list(call.args)[:4]:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
            return arg.value
    for keyword in call.keywords[:3]:
        if keyword.arg in ("key_size", "keySize", "keyLength", "strength", "modulus"):
            if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, int):
                return keyword.value.value
    return None


# Call-name tails that genuinely name an algorithm, so they can be used as the
# reported algorithm. Anything else (generate_private_key, new, getInstance)
# would be noise.
_PY_ALGORITHM_TAILS = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_512", "blake2b", "blake2s",
    "aes", "fernet", "des3", "tripledes", "blowfish", "arc4", "arc2",
    "cast5", "idea", "chacha20poly1305", "rsa", "dsa", "ec", "dh",
    "ed25519", "ed448", "x25519", "x448", "pbkdf2hmac", "scrypt", "hkdf",
    "hkdfexpand", "hqsha", "poly1305",
}


def _algorithm_hint(name: str, literals: list[str]) -> str:
    """Best available algorithm name for a call.

    Order: an explicit algorithm-ish string argument, then the call's own final
    name segment when that segment is an algorithm token (so `hashlib.md5`
    reports MD5 while `rsa.generate_private_key` reports nothing rather than
    reporting "generate_private_key").
    """
    for value in literals:
        if _PY_ALGORITHM_LITERALS.match(value):
            return value
        # Cipher-style strings such as "DES-ECB" or "AES-256-GCM" are still the
        # algorithm even though they carry a mode suffix.
        if re.match(r"^(?:aes|des|desede|3des|rsa|dsa|ec|chacha20|arc4|rc4|blowfish)[-/]", value, re.I):
            return value
    tail = name.rsplit(".", 1)[-1]
    if tail.lower() in _PY_ALGORITHM_TAILS:
        return tail
    return ""


def detect_python(text: str) -> list[dict]:
    """Detect cryptographic API use in Python source using the real AST."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        # A file that is not valid Python is not a Python finding; other
        # detectors still apply. Recorded honestly rather than guessed at.
        return []

    findings: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        tail = name.rsplit(".", 1)[-1]
        family = None
        kind = "crypto_api"

        for candidate, candidate_family in _PY_CRYPTO_CALLS.items():
            if name == candidate or name.endswith("." + candidate):
                family = candidate_family
                break
        if family is None:
            continue

        if family == "key":
            kind = "key_reference"
        elif family == "certificate":
            kind = "certificate"
        elif family == "protocol":
            kind = "protocol"
        elif family == "kdf":
            kind = "crypto_api"

        algorithm = _algorithm_hint(name, _string_args(node))
        key_size = _int_args(node)
        if not algorithm and family in ("rsa", "ecc", "dsa", "dh", "aes", "des3", "hash", "mac"):
            algorithm = family.upper()

        family_name, display = normalise_algorithm(algorithm) if algorithm else (family, "")
        if algorithm and family_name == "unknown":
            family_name = family
        if not algorithm and family in ("key", "certificate", "protocol", "kdf"):
            # These describe a use or a category, not an algorithm family.
            family_name = "unknown"
            display = ""

        evidence_value = name
        if algorithm:
            evidence_value = f"{name}({algorithm})"
        if key_size:
            evidence_value = f"{evidence_value}, {key_size}"

        findings.append(
            {
                "kind": kind,
                "family": family_name,
                "algorithm": display or (family.upper() if family != "unknown" else ""),
                "key_size": key_size,
                "library": name.split(".")[0] if "." in name else "",
                "confidence": 0.95,
                "line": getattr(node, "lineno", None),
                "evidence": {
                    "type": "ast_call",
                    "detector": "python_ast",
                    "value": evidence_value[:200],
                },
                "strength": classify_algorithm_strength(algorithm or display, key_size),
            }
        )
    return findings


# --- Other languages: curated symbol tables ---------------------------------

_GENERIC_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Java / JCA -- algorithm is captured so overlapping tables collapse cleanly
    ("unknown", "crypto_api", re.compile(r"KeyPairGenerator\.getInstance\(\s*\"(RSA|DSA|EC|ECDSA)\"")),
    ("unknown", "crypto_api", re.compile(r"Cipher\.getInstance\(\s*\"(AES|DES|DESede|DESede3|3DES|TripleDES|RC2|RC4|Blowfish|CAST5|IDEA|ChaCha20)(?:/|\")")),
    ("mac", "crypto_api", re.compile(r"Mac\.getInstance\(\s*\"([^\"]+)\"")),
    ("hash", "crypto_api", re.compile(r"MessageDigest\.getInstance\(\s*\"([^\"]+)\"")),
    # JCA algorithm constants used outside a getInstance call
    ("rsa", "crypto_api", re.compile(r"\bRSA(?:/ECB/OAEPWithSHA-?1AndMGF1Padding)?\b")),
    ("aes", "crypto_api", re.compile(r"\bAES/(?:GCM|CBC|CTR|ECB)\b")),
    ("hash", "crypto_api", re.compile(r"\bSHA-?(?:1|224|256|384|512)\b")),
    ("hash", "crypto_api", re.compile(r"\bMD5\b")),
    # Go
    ("rsa", "crypto_api", re.compile(r"rsa\.(?:GenerateKey|SignPKCS1v15|SignPSS)\b")),
    ("ecc", "crypto_api", re.compile(r"ecdsa\.(?:GenerateKey|Sign)\b")),
    ("ecc", "crypto_api", re.compile(r"ecdh\.(?:GenerateKey|ComputeSharedSecret)\b")),
    ("aes", "crypto_api", re.compile(r"aes\.NewCipher\b")),
    ("hash", "crypto_api", re.compile(r"\b(?:md5|sha1|sha256|sha512)\.(?:New|Sum)\b")),
    ("mac", "crypto_api", re.compile(r"hmac\.New\b")),
    # JS / TS
    ("hash", "crypto_api", re.compile(r"crypto\.createHash\(\s*['\"]([a-z0-9-]+)['\"]")),
    ("rsa", "crypto_api", re.compile(r"crypto\.createSign\(\s*['\"](RSA|PSM)['\"]")),
    ("rsa", "crypto_api", re.compile(r"crypto\.publicEncrypt\(")),
    ("aes", "crypto_api", re.compile(r"crypto\.createCipheriv?\(")),
    ("mac", "crypto_api", re.compile(r"crypto\.createHmac\(")),
    # C# / .NET
    ("rsa", "crypto_api", re.compile(r"\bRSACryptoServiceProvider\b")),
    ("rsa", "crypto_api", re.compile(r"\bRSA\.Create\(")),
    ("aes", "crypto_api", re.compile(r"\bAes\.Create\(")),
    # Rust
    ("rsa", "crypto_api", re.compile(r"\bRsa(?:PrivateKey|PublicKey)\b")),
    ("ecc", "crypto_api", re.compile(r"\b(?:P256|P384|Ed25519|X25519)\w*\b")),
    # PHP
    ("rsa", "crypto_api", re.compile(r"\bopenssl_(?:private_encrypt|public_encrypt|sign|verify)\b")),
    ("hash", "crypto_api", re.compile(r"\bhash\(\s*['\"]?(md5|sha1|sha256)", re.I)),
    # Ruby
    ("rsa", "crypto_api", re.compile(r"\bOpenSSL::PKey::RSA\b")),
    ("hash", "crypto_api", re.compile(r"\bOpenSSL::Digest::(MD5|SHA1)\b")),
]

_CONFIG_CRYPTO_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # TLS / cipher configuration
    ("unknown", "tls", re.compile(r"^\s*ssl_protocols\s+(.+)$", re.I | re.M)),
    ("unknown", "tls_ciphers", re.compile(r"^\s*ssl_ciphers\s+(.+)$", re.I | re.M)),
    ("unknown", "tls", re.compile(r"^\s*(?:SSLProtocols|SSLCipherSuites|TlsClientAuth|Tls)\b", re.I | re.M)),
    ("unknown", "tls", re.compile(r"^\s*Host\s+.*:443\b", re.I | re.M)),
    ("unknown", "ssh_host_key", re.compile(r"^\s*(?:HostKeyAlgorithms|HostKey)\s+(.+)$", re.I | re.M)),
    ("unknown", "openssl_conf", re.compile(r"^\s*(?:default_md|encrypt_key|cipher|digest)\s*=\s*(\S+)", re.I | re.M)),
]

_MAX_LINE = 200


def detect_symbols(text: str) -> list[dict]:
    """Detect crypto API symbols by curated pattern, recording the line."""
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()

    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        if len(line) > 2000:
            line = line[:2000]
        for family, kind, pattern in _GENERIC_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            # Dedupe on the matched span, not the algorithm text: one
            # `Cipher.getInstance("DES/...")` matches several tables and must
            # still be reported once.
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        if len(line) > 2000:
            line = line[:2000]
        covered: set[str] = set()
        for family, kind, pattern in _GENERIC_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            algorithm = (match.group(1) if match.groups() else "") or match.group(0)
            normalised, _display = normalise_algorithm(algorithm)
            # A specific API match (e.g. `Cipher.getInstance("DES/...")`) also
            # satisfies the bare-token tables. Report the first, most specific
            # one only, otherwise every call site is double counted.
            if normalised in covered:
                continue
            span = (index, match.start())
            if span in seen:
                continue
            seen.add(span)
            covered.add(normalised)
            family_name, display = normalise_algorithm(algorithm)
            if family_name == "unknown":
                family_name = family
            findings.append(
                {
                    "kind": kind,
                    "family": family_name,
                    "algorithm": display[:64] or family.upper(),
                    "library": _guess_library(line),
                    "confidence": 0.7,
                    "line": index,
                    "evidence": {
                        "type": "symbol_match",
                        "detector": "pattern_table",
                        "value": match.group(0)[:_MAX_LINE],
                    },
                    "strength": classify_algorithm_strength(display, None),
                }
            )
    return findings


CONFIG_SUFFIXES = {
    ".conf", ".cfg", ".ini", ".cnf", ".properties", ".yaml", ".yml",
    ".toml", ".env", ".xml", ".pem",
}


def detect_config(text: str) -> list[dict]:
    """Detect cryptographic configuration directives (TLS, ciphers, digests).

    Only call this for configuration files. The directive names (`cipher`,
    `digest`) are ordinary identifiers in source code, so running this over
    Python would report every crypto call as a config directive.
    """
    findings: list[dict] = []
    for family, label, pattern in _CONFIG_CRYPTO_PATTERNS:
        for match in pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            value = (match.group(1) if match.groups() else match.group(0)).strip()[:_MAX_LINE]
            findings.append(
                {
                    "kind": "crypto_configuration",
                    "family": family,
                    "algorithm": label,
                    "protocol": label if family == "protocol" else "",
                    "confidence": 0.85,
                    "line": line_no,
                    "evidence": {
                        "type": "config_directive",
                        "detector": "config_patterns",
                        "value": match.group(0).strip()[:_MAX_LINE],
                    },
                    "strength": classify_algorithm_strength(value, None),
                }
            )
    return findings


_LIBRARIES = (
    ("OpenSSL", re.compile(r"\b(?:OPENSSL_init_crypto|EVP_\w+|SSL_CTX_new|openssl)", re.I)),
    ("BoringSSL", re.compile(r"\bBoringSSL\b", re.I)),
    ("wolfSSL", re.compile(r"\bwolfSSL\b|\bwolfSSL_\w+", re.I)),
    ("mbedTLS", re.compile(r"\bmbedtls\b|\bmbedtls_\w+", re.I)),
    ("NSS", re.compile(r"\bNSS_?Init\b|\bnss3\b", re.I)),
    ("CryptoAPI", re.compile(r"\bCryptAcquireContext\w*|\bBCrypt\w+", re.I)),
    ("JCA", re.compile(r"javax\.crypto|java\.security", re.I)),
    ("BouncyCastle", re.compile(r"\borg\.bouncycastle", re.I)),
    ("cryptography", re.compile(r"^\s*(?:from|import)\s+cryptography", re.I | re.M)),
    ("PyCryptodome", re.compile(r"^\s*(?:from|import)\s+Crypto\b", re.I | re.M)),
    ("jose", re.compile(r"^\s*(?:from|import)\s+jose\b", re.I | re.M)),
    ("PyJWT", re.compile(r"^\s*(?:from|import)\s+jwt\b", re.I | re.M)),
    ("node:crypto", re.compile(r"require\(\s*['\"]crypto['\"]\s*\)|from\s+['\"]crypto['\"]", re.I)),
)


def _guess_library(line: str) -> str:
    for name, pattern in _LIBRARIES:
        if pattern.search(line):
            return name
    return ""


# --- Dependency manifests ----------------------------------------------------

CRYPTO_DEPENDENCIES: dict[str, str] = {
    # JS / TS
    "crypto-js": "aes", "node-forge": "rsa", "jsrsasign": "rsa",
    "jsonwebtoken": "protocol", "jose": "protocol", "tweetnacl": "ecc",
    "@aws-sdk/client-kms": "cloud_crypto_service", "aws-sdk": "cloud_crypto_service",
    "google-cloud-kms": "cloud_crypto_service", "@azure/keyvault-keys": "cloud_crypto_service",
    "@azure/keyvault-secrets": "cloud_crypto_service", "@azure/keyvault-certificates": "cloud_crypto_service",
    "node-pkcs11": "hardware_module", "pkcs11js": "hardware_module",
    # Python
    "cryptography": "rsa", "pycryptodome": "rsa", "pycrypto": "rsa",
    "paramiko": "protocol", "jwt": "protocol", "python-jose": "protocol",
    "python-jwt": "protocol", "authlib": "protocol", "certbot": "certificate",
    "python-pkcs11": "hardware_module", "asn1crypto": "certificate",
    "ecdsa": "ecc", "pynacl": "ecc", "bcrypt": "kdf", "passlib": "kdf",
    "google-cloud-kms": "cloud_crypto_service", "boto3": "cloud_crypto_service",
    "azure-keyvault": "cloud_crypto_service", "hvac": "cloud_crypto_service",
    # Java / JVM
    "bouncycastle": "rsa", "bcpkix-jdk18on": "certificate", "bcprov-jdk18on": "rsa",
    "jjwt": "protocol", "nimbus-jose-jwt": "protocol", "google-auth-library": "protocol",
    "aws-java-sdk-kms": "cloud_crypto_service", "azure-security-keyvault": "cloud_crypto_service",
    # Go
    "crypto/tls": "protocol", "crypto/x509": "certificate", "golang.org/x/crypto": "ecc",
    "github.com/aws/aws-sdk-go/service/kms": "cloud_crypto_service",
    "cloud.google.com/go/kms": "cloud_crypto_service",
    "github.com/miekg/pkcs11": "hardware_module", "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault": "cloud_crypto_service",
    # .NET
    "System.Security.Cryptography": "rsa", "Microsoft.IdentityModel": "protocol",
    "Azure.Security.KeyVault": "cloud_crypto_service", "AWSSDK.KMS": "cloud_crypto_service",
    "BouncyCastle.Cryptography": "rsa", "SSH.NET": "protocol",
    # Rust
    "ring": "ecc", "rustls": "protocol", "aws-sdk-kms": "cloud_crypto_service",
    "openssl": "rsa", "pkcs11": "hardware_module", "rsa": "rsa", "p256": "ecc",
    # Ruby / PHP
    "openssl": "rsa", "jwt": "protocol", "ruby-openssl": "rsa",
    # generic
    "openssl": "rsa", "boringssl": "rsa", "libsodium": "ecc", "libsodium": "ecc",
    "tpm2-pytss": "hardware_module", "trousers": "hardware_module", "softhsm": "hardware_module",
}

MANIFEST_FILES = {
    "package.json", "requirements.txt", "pyproject.toml", "Pipfile", "setup.py",
    "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml", "go.mod",
    "Gemfile", "composer.json", "packages.config", "paket.lock",
}


def _dependency_present(haystack_lower: str, package: str) -> bool:
    """Match a package name as a token, not as a substring of another name.

    Plain `in` matching reported `pkcs11` for `node-pkcs11` and `rsa` for
    `cryptography-rsa`, inventing dependencies that were never declared.
    """
    needle = package.lower()
    # Allow an optional scope or path prefix (@scope/name, a.b.c/name).
    pattern = re.compile(
        r"(?<![\w@/.-])" + re.escape(needle) + r"(?![\w.-])"
    )
    return bool(pattern.search(haystack_lower))


def detect_dependencies(filename: str, text: str) -> list[dict]:
    """Find cryptographically-relevant dependencies in a manifest."""
    findings: list[dict] = []
    lowered = text.lower()
    seen: set[str] = set()

    for package, family in CRYPTO_DEPENDENCIES.items():
        if not _dependency_present(lowered, package):
            continue
        key = package.lower()
        if key in seen:
            continue
        seen.add(key)
        line_no = None
        for index, line in enumerate(lowered.splitlines(), start=1):
            if _dependency_present(line, package):
                line_no = index
                break
        findings.append(
            {
                "kind": "dependency",
                "family": family if family in ("rsa", "ecc", "dsa", "dh", "aes", "des3", "hash", "mac", "pqc") else "unknown",
                "algorithm": "",
                "library": package,
                "confidence": 0.9,
                "line": line_no,
                "evidence": {
                    "type": "manifest_entry",
                    "detector": "dependency_scan",
                    "value": package,
                    "manifest": filename,
                },
            }
        )
    return findings
