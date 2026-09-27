"""Binary and executable inspection.

Real format parsing with the standard library only -- no external dependency
needed. What is extracted is deliberately narrow and factual:

* container format, architecture, bitness, and build metadata
* imported/exported symbol names, matched against a curated crypto symbol set
* embedded certificate and key material markers

Every finding carries the symbol or marker that produced it, so a claim is
always traceable back to something in the file. Binary parsing is best-effort
by nature: an unrecognised or truncated format yields no findings rather than
a guess, and the caller records that as a skip.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

# Formats we can identify from a magic number.
_MAGIC = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xcf\xfa\xed\xfe", "macho"), (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"), (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xca\xfe\xba\xbe", "macho_fat"),
    (b"PK\x03\x04", "zip"),          # also APK / JAR / docx / wheel
    (b"\xd0\xcf\x11\xe0", "ole"),     # also .NET assemblies
    (b"!<arch>", "ar"),               # also .deb / static libraries
    (b"\x1f\x8b", "gzip"),
    (b"dex\n", "dex"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\xfd7zXZ", "xz"),
    (b"BZh", "bzip2"),
)

_ARCH_BY_MACHINE = {
    0x03: ("x86", 32), 0x08: ("mips", 32), 0x14: ("ppc", 32), 0x15: ("ppc", 32),
    0x16: ("s390", 32), 0x28: ("arm", 32), 0x2A: ("superh", 32), 0x32: ("ia64", 64),
    0x3E: ("x86", 64), 0xB7: ("arm", 64), 0xB8: ("aarch64", 64), 0xF3: ("riscv", 64),
}

# Crypto-relevant imported/exported symbols. The presence of a symbol is a
# fact about the binary; what it is used for is not inferred here.
_CRYPTO_SYMBOLS: dict[str, tuple[str, str]] = {
    # OpenSSL / BoringSSL / LibreSSL
    "EVP_PKEY_new": ("rsa", "key material"), "EVP_PKEY_free": ("rsa", "key material"),
    "EVP_PKEY_CTX_new": ("rsa", "key material"), "EVP_PKEY_sign": ("rsa", "signing"),
    "EVP_PKEY_verify": ("rsa", "verification"), "EVP_PKEY_encrypt": ("rsa", "encryption"),
    "EVP_PKEY_decrypt": ("rsa", "decryption"), "EVP_PKEY_derive": ("ecc", "key agreement"),
    "EVP_DigestSignInit": ("hash", "signing"), "EVP_DigestVerifyInit": ("hash", "verification"),
    "EVP_CipherInit_ex": ("aes", "symmetric encryption"), "EVP_CIPHER_CTX_new": ("aes", "symmetric encryption"),
    "EVP_aes_128_gcm": ("aes", "symmetric encryption"), "EVP_aes_256_gcm": ("aes", "symmetric encryption"),
    "EVP_aes_128_cbc": ("aes", "symmetric encryption"), "EVP_aes_256_cbc": ("aes", "symmetric encryption"),
    "EVP_des_ede3": ("des3", "symmetric encryption"), "EVP_rc4": ("legacy", "symmetric encryption"),
    "EVP_sha256": ("hash", "hashing"), "EVP_sha1": ("hash", "hashing"),
    "EVP_md5": ("hash", "hashing"), "SSL_CTX_new": ("rsa", "transport security"),
    "SSL_new": ("rsa", "transport security"), "TLS_method": ("rsa", "transport security"),
    "X509_verify_cert": ("rsa", "certificate handling"),
    "X509_STORE_add_cert": ("rsa", "certificate handling"),
    "d2i_X509": ("rsa", "certificate handling"), "i2d_X509": ("rsa", "certificate handling"),
    "PEM_read_bio_PrivateKey": ("rsa", "key material"),
    "PKCS8_decrypt": ("rsa", "key material"),
    # Windows CNG / CryptoAPI
    "BCryptOpenAlgorithmProvider": ("aes", "symmetric encryption"),
    "BCryptEncrypt": ("aes", "symmetric encryption"), "BCryptDecrypt": ("aes", "symmetric encryption"),
    "BCryptGenerateSymmetricKey": ("aes", "key material"),
    "BCryptSignHash": ("rsa", "signing"), "BCryptVerifySignature": ("rsa", "verification"),
    "BCryptImportKeyPair": ("rsa", "key material"),
    "NCryptOpenStorageProvider": ("rsa", "key management"),
    "CertOpenStore": ("rsa", "certificate handling"),
    "CertFindCertificateInStore": ("rsa", "certificate handling"),
    "CertGetCertificateChain": ("rsa", "certificate handling"),
    "CryptAcquireContext": ("rsa", "key material"),
    "CryptGenRandom": ("unknown", "randomness"),
    "CryptSignHash": ("rsa", "signing"),
    "CryptEncrypt": ("rsa", "encryption"),
    # NSS
    "NSS_Init": ("rsa", "key management"), "PK11SDR_Decrypt": ("rsa", "key material"),
    "CERT_DecodeCertFromPackage": ("rsa", "certificate handling"),
    # mbedTLS / wolfSSL / libsodium / BouncyCastle-ish
    "mbedtls_ssl_init": ("rsa", "transport security"), "mbedtls_rsa_pkcs1_encrypt": ("rsa", "encryption"),
    "mbedtls_ecdsa_sign": ("ecc", "signing"), "mbedtls_md5": ("hash", "hashing"),
    "wolfSSL_CTX_new": ("rsa", "transport security"), "wc_EVP_PKEY_new": ("rsa", "key material"),
    "sodium_crypto_sign": ("ecc", "signing"), "sodium_crypto_box": ("ecc", "key exchange"),
    "libsodium_init": ("ecc", "crypto implementation"),
    # Go runtime crypto
    "crypto/rsa.GenerateKey": ("rsa", "key material"),
    "crypto/ecdsa.GenerateKey": ("ecc", "key material"),
    "crypto/tls.Conn.Handshake": ("rsa", "transport security"),
    "crypto/x509.ParseCertificate": ("rsa", "certificate handling"),
    # JNI / JVM
    "Java_security_KeyPairGenerator_KeyPairGenerator": ("rsa", "key material"),
    "Java_security_Signature_sign": ("rsa", "signing"),
    "Java_javax_crypto_Cipher_doFinal": ("aes", "symmetric encryption"),
    "sun_security_x509_X509CertImpl": ("rsa", "certificate handling"),
    # .NET
    "System_Security_Cryptography_RSACryptoServiceProvider": ("rsa", "key material"),
    "System_Security_Cryptography_Aes_TransformFinalBlock": ("aes", "symmetric encryption"),
    # generic algorithm initialisation seen in many bindings
    "RSA_sign": ("rsa", "signing"), "RSA_verify": ("rsa", "verification"),
    "RSA_new": ("rsa", "key material"), "RSA_generate_key": ("rsa", "key material"),
    "AES_set_encrypt_key": ("aes", "symmetric encryption"),
    "AES_set_decrypt_key": ("aes", "symmetric encryption"),
    "DES_set_key": ("des3", "symmetric encryption"),
    "MD5_Init": ("hash", "hashing"), "SHA256_Init": ("hash", "hashing"),
    "EVP_EncryptInit": ("aes", "symmetric encryption"),
    "EVP_DecryptInit": ("aes", "symmetric encryption"),
}

# Certificates compiled into a binary leave PEM markers behind.
_PEM_CERT_MARKER = re.compile(rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----")
_PEM_KEY_MARKER = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
_DER_CERT_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01"  # X.500 id-ce
_RSA_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
_ECC_OID = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"          # prime256v1

# Packed-file / container hints worth reporting alongside the symbol hits.
_ARCHIVE_SUFFIXES = {
    ".apk": "android package", ".jar": "java archive", ".war": "java archive",
    ".ear": "java archive", ".aar": "android library", ".whl": "python wheel",
    ".egg": "python distribution", ".nupkg": "nuget package", ".deb": "debian package",
    ".rpm": "rpm package", ".so": "shared library", ".dll": "dynamic library",
    ".dylib": "dynamic library", ".exe": "portable executable", ".sys": "driver",
    ".wasm": "webassembly module", ".o": "object file", ".ko": "kernel module",
}


@dataclass
class BinaryDetail:
    fmt: str = ""
    arch: str = ""
    bits: int | None = None
    endianness: str = ""
    is_library: bool = False
    is_driver: bool = False
    container_hint: str = ""
    symbols: list[str] = field(default_factory=list)

    def as_evidence(self) -> dict:
        return {
            "format": self.fmt,
            "architecture": self.arch,
            "bits": self.bits,
            "endianness": self.endianness,
            "is_library": self.is_library,
            "container_hint": self.container_hint,
            "symbol_count": len(self.symbols),
        }


def identify_format(data: bytes) -> str:
    for magic, name in _MAGIC:
        if data.startswith(magic):
            return name
    return ""


def _parse_elf(data: bytes) -> tuple[str, int | None, str, bool]:
    if len(data) < 20:
        return "", None, "", False
    bits = {1: 32, 2: 64}.get(data[4])
    endianness = "little" if data[5] == 1 else "big"
    is64 = data[4] == 2
    prefix = "<" if endianness == "little" else ">"
    try:
        if is64:
            e_type = struct.unpack_from(prefix + "H", data, 16)[0]
            e_machine = struct.unpack_from(prefix + "H", data, 18)[0]
        else:
            e_type, e_machine = struct.unpack_from(prefix + "HH", data, 16)
    except struct.error:
        return "", bits, endianness, False
    arch = _ARCH_BY_MACHINE.get(e_machine, (f"machine_{e_machine}", bits))[0]
    # ET_DYN (3) covers both shared objects and PIE executables; a name hint
    # is more reliable than the type alone.
    is_lib = e_type == 3
    return arch, bits, endianness, is_lib


def _parse_pe(data: bytes) -> tuple[str, int | None, str, bool]:
    if len(data) < 0x40:
        return "", None, "", False
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return "", None, "", False
    if pe_offset + 6 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return "", None, "", False
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    arch, bits = {
        0x014C: ("x86", 32), 0x8664: ("x86", 64), 0x01C0: ("arm", 32),
        0xAA64: ("aarch64", 64), 0x0200: ("ia64", 64),
    }.get(machine, (f"machine_{machine:#x}", None))
    return arch, bits, "little", False


def _parse_macho(data: bytes) -> tuple[str, int | None, str, bool]:
    if len(data) < 8:
        return "", None, "", False
    # A little-endian Mach-O carries magic 0xfeedfacf, so cputype is a
    # little-endian uint32; the big-endian variant carries 0xfeedface. Reading
    # both as big-endian reports every Apple Silicon binary as an unknown CPU.
    if data[:4] == b"\xfe\xed\xfa\xce":
        cputype = struct.unpack_from(">I", data, 4)[0]
    else:
        cputype = struct.unpack_from("<I", data, 4)[0]
    arch, bits = {
        7: ("x86", 32), 0x01000007: ("x86", 64),
        12: ("arm", 32), 0x0100000C: ("arm", 64),
        0x0100000F: ("aarch64", 64),
    }.get(cputype, (f"cpu_{cputype:#x}", None))
    return arch, bits, "little", True


def extract_ascii_strings(data: bytes, minimum: int = 4, limit: int = 400_000) -> list[str]:
    """Printable ASCII runs, which is where symbol names live in a binary."""
    if len(data) > limit:
        data = data[:limit]
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    return [m.group(0).decode("ascii", "ignore") for m in pattern.finditer(data)]


def analyse(data: bytes, filename: str = "") -> BinaryDetail:
    """Identify a binary and collect its crypto-relevant symbols."""
    detail = BinaryDetail()
    detail.fmt = identify_format(data)
    if not detail.fmt:
        return detail

    if detail.fmt == "elf":
        detail.arch, detail.bits, detail.endianness, detail.is_library = _parse_elf(data)
    elif detail.fmt == "pe":
        detail.arch, detail.bits, detail.endianness, _ = _parse_pe(data)
    elif detail.fmt.startswith("macho"):
        detail.arch, detail.bits, detail.endianness, detail.is_library = _parse_macho(data)
    elif detail.fmt == "ole":
        detail.bits = 32  # .NET assemblies are 32-bit IL by default

    suffix = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    detail.container_hint = _ARCHIVE_SUFFIXES.get(suffix, "")
    detail.is_driver = suffix in (".sys", ".ko")

    strings = extract_ascii_strings(data)
    joined = "\n".join(strings)
    for symbol, _info in _CRYPTO_SYMBOLS.items():
        # Boundary-aware on purpose: a plain substring search reports
        # `CryptEncrypt` for `BCryptEncrypt` and `MD5_Init` for `HMAC_MD5_Init`,
        # inventing symbols the binary does not import.
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])"
        )
        if pattern.search(joined):
            detail.symbols.append(symbol)
    return detail


def findings_for(location: str, data: bytes, filename: str = "") -> list[dict]:
    """Turn a binary into findings, one per observed capability."""
    detail = analyse(data, filename)
    if not detail.fmt:
        return []

    out: list[dict] = []

    def emit(**kwargs) -> None:
        payload = {
            "location": location,
            "kind": kwargs.pop("kind", "crypto_api"),
            "family": kwargs.pop("family", "unknown"),
            "algorithm": kwargs.pop("algorithm", ""),
            "library": kwargs.pop("library", ""),
            "key_size": kwargs.pop("key_size", None),
            "confidence": kwargs.pop("confidence", 0.9),
            "evidence": {
                "type": "binary_symbol",
                "detector": "binary_inspector",
                **detail.as_evidence(),
                **kwargs.pop("evidence", {}),
            },
        }
        payload.update(kwargs)
        out.append(payload)

    for symbol in detail.symbols:
        family, capability = _CRYPTO_SYMBOLS[symbol]
        emit(
            family=family,
            algorithm=capability,
            confidence=0.9,
            evidence={"symbol": symbol, "capability": capability},
        )

    if _PEM_CERT_MARKER.search(data):
        emit(
            kind="certificate",
            family="rsa",
            algorithm="Embedded certificate material",
            confidence=0.75,
            evidence={"marker": "PEM certificate header"},
        )
    if _PEM_KEY_MARKER.search(data):
        emit(
            kind="key_reference",
            family="unknown",
            algorithm="Embedded private key material",
            confidence=0.85,
            evidence={"marker": "PEM private key header"},
            strength="private_key_material",
        )
    if _RSA_OID in data or _ECC_OID in data:
        emit(
            kind="algorithm",
            family="rsa" if _RSA_OID in data else "ecc",
            algorithm="Embedded key object identifier",
            confidence=0.7,
            evidence={"marker": "ASN.1 key OID"},
        )

    return out
