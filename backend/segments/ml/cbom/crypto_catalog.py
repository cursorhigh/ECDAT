"""
Cryptographic Knowledge Base & Reference Catalog (crypto_catalog.py)

Deterministic, offline, version-controlled reference catalog aligning with:
- NIST SP 800-57 Part 1 Rev 5 (Recommendation for Key Management)
- NIST SP 800-131A Rev 2 (Transitioning the Use of Cryptographic Algorithms and Key Lengths)
- NIST FIPS 140-3 (Security Requirements for Cryptographic Modules)
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- OWASP CycloneDX 1.6 Cryptographic Properties Specification
- ECDAT 37-Feature Canonical Feature Schema

Contains no LLM dependencies. Provides deterministic lookups for canonical algorithm naming,
cryptographic primitive categorization, classical security bit estimation, NIST quantum
security levels (0-5), quantum vulnerability, and standard OIDs.
"""

from typing import Dict, Any, List, Optional, Tuple
import re

# Canonical Algorithm Registry
# Maps canonical algorithm identifier to its normative cryptographic specification
CRYPTO_CATALOG: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # Asymmetric Cryptography (Vulnerable to Shor's Algorithm)
    # -------------------------------------------------------------------------
    "RSA-1024": {
        "canonical_name": "RSA-1024",
        "family": "asymmetric",
        "primitive": "asymmetric",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify", "encrypt", "decrypt", "key-encapsulate"],
        "key_or_hash_size_bits": 1024,
        "classical_security_bits_est": 80,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": True,
        "oid": "1.2.840.113549.1.1.1",
        "aliases": ["rsa 1024", "rsa-1024", "rsa1024", "rsa_1024"],
    },
    "RSA-2048": {
        "canonical_name": "RSA-2048",
        "family": "asymmetric",
        "primitive": "asymmetric",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify", "encrypt", "decrypt", "key-encapsulate"],
        "key_or_hash_size_bits": 2048,
        "classical_security_bits_est": 112,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.1.1",
        "aliases": ["rsa", "rsa-2048", "rsa2048", "rsa_2048", "rsa 2048"],
    },
    "RSA-3072": {
        "canonical_name": "RSA-3072",
        "family": "asymmetric",
        "primitive": "asymmetric",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify", "encrypt", "decrypt", "key-encapsulate"],
        "key_or_hash_size_bits": 3072,
        "classical_security_bits_est": 128,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.1.1",
        "aliases": ["rsa-3072", "rsa3072", "rsa_3072", "rsa 3072"],
    },
    "RSA-4096": {
        "canonical_name": "RSA-4096",
        "family": "asymmetric",
        "primitive": "asymmetric",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify", "encrypt", "decrypt", "key-encapsulate"],
        "key_or_hash_size_bits": 4096,
        "classical_security_bits_est": 152,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.1.1",
        "aliases": ["rsa-4096", "rsa4096", "rsa_4096", "rsa 4096"],
    },
    "ECDSA-P224": {
        "canonical_name": "ECDSA-P224",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 224,
        "classical_security_bits_est": 112,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-224",
        "oid": "1.2.840.10045.2.1",
        "aliases": ["ecdsa-p224", "ecdsa-secp224r1", "secp224r1", "p-224"],
    },
    "ECDSA-P256": {
        "canonical_name": "ECDSA-P256",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-256",
        "oid": "1.2.840.10045.3.1.7",
        "aliases": ["ecdsa", "ecdsa-p256", "ecdsa-secp256r1", "secp256r1", "prime256v1", "p-256", "p256"],
    },
    "ECDSA-P384": {
        "canonical_name": "ECDSA-P384",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 384,
        "classical_security_bits_est": 192,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-384",
        "oid": "1.3.132.0.34",
        "aliases": ["ecdsa-p384", "secp384r1", "p-384", "p384"],
    },
    "ECDSA-P521": {
        "canonical_name": "ECDSA-P521",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 521,
        "classical_security_bits_est": 256,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-521",
        "oid": "1.3.132.0.35",
        "aliases": ["ecdsa-p521", "secp521r1", "p-521", "p521"],
    },
    "ECDH-P224": {
        "canonical_name": "ECDH-P224",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 224,
        "classical_security_bits_est": 112,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-224",
        "oid": "1.3.132.1.12",
        "aliases": ["ecdh-p224", "ecdh-secp224r1"],
    },
    "ECDH-P256": {
        "canonical_name": "ECDH-P256",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-256",
        "oid": "1.3.132.1.12",
        "aliases": ["ecdh", "ecdh-p256", "ecdh-secp256r1"],
    },
    "ECDH-P384": {
        "canonical_name": "ECDH-P384",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 384,
        "classical_security_bits_est": 192,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-384",
        "oid": "1.3.132.1.12",
        "aliases": ["ecdh-p384", "ecdh-secp384r1"],
    },
    "ECDH-P521": {
        "canonical_name": "ECDH-P521",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 521,
        "classical_security_bits_est": 256,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "P-521",
        "oid": "1.3.132.1.12",
        "aliases": ["ecdh-p521", "ecdh-secp521r1"],
    },
    "Ed25519": {
        "canonical_name": "Ed25519",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "Ed25519",
        "oid": "1.3.101.112",
        "aliases": ["ed25519", "ed-25519", "edward25519"],
    },
    "Ed448": {
        "canonical_name": "Ed448",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 448,
        "classical_security_bits_est": 224,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "Ed448",
        "oid": "1.3.101.113",
        "aliases": ["ed448", "ed-448"],
    },
    "X25519": {
        "canonical_name": "X25519",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "X25519",
        "oid": "1.3.101.110",
        "aliases": ["x25519", "curve25519"],
    },
    "X448": {
        "canonical_name": "X448",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 448,
        "classical_security_bits_est": 224,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "curve": "X448",
        "oid": "1.3.101.111",
        "aliases": ["x448", "curve448"],
    },
    "DH-2048": {
        "canonical_name": "DH-2048",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 2048,
        "classical_security_bits_est": 112,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.3.1",
        "aliases": ["dh", "diffie-hellman", "dh-2048", "dh2048"],
    },
    "DH-3072": {
        "canonical_name": "DH-3072",
        "family": "asymmetric",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement"],
        "key_or_hash_size_bits": 3072,
        "classical_security_bits_est": 128,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.3.1",
        "aliases": ["dh-3072", "dh3072"],
    },
    "DSA-1024": {
        "canonical_name": "DSA-1024",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 1024,
        "classical_security_bits_est": 80,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": True,
        "oid": "1.2.840.10040.4.1",
        "aliases": ["dsa-1024", "dsa1024"],
    },
    "DSA-2048": {
        "canonical_name": "DSA-2048",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 2048,
        "classical_security_bits_est": 112,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.10040.4.1",
        "aliases": ["dsa", "dsa-2048", "dsa2048"],
    },
    "DSA-3072": {
        "canonical_name": "DSA-3072",
        "family": "asymmetric",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 3072,
        "classical_security_bits_est": 128,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Shor",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.10040.4.1",
        "aliases": ["dsa-3072", "dsa3072"],
    },

    # -------------------------------------------------------------------------
    # Symmetric Cryptography (Impacted by Grover's Algorithm)
    # -------------------------------------------------------------------------
    "AES-128": {
        "canonical_name": "AES-128",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.1.2",
        "aliases": ["aes-128", "aes128", "aes_128", "aes-128-cbc", "aes-128-gcm", "aes-128-ctr"],
    },
    "AES-192": {
        "canonical_name": "AES-192",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 192,
        "classical_security_bits_est": 192,
        "nist_security_category": 3,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.1.22",
        "aliases": ["aes-192", "aes192", "aes_192", "aes-192-cbc", "aes-192-gcm"],
    },
    "AES-256": {
        "canonical_name": "AES-256",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.1.42",
        "aliases": ["aes", "aes-256", "aes256", "aes_256", "aes-256-cbc", "aes-256-gcm", "aes-gcm", "aes-cbc", "aes-ctr"],
    },
    "3DES-112": {
        "canonical_name": "3DES-112",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 112,
        "classical_security_bits_est": 80,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Legacy/weak",
        "deprecated_or_disallowed": True,
        "oid": "1.2.840.113549.3.7",
        "aliases": ["3des", "triple-des", "tdes", "3des-112", "des-ede3-cbc"],
    },
    "DES": {
        "canonical_name": "DES",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 56,
        "classical_security_bits_est": 56,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Legacy/weak",
        "deprecated_or_disallowed": True,
        "oid": "1.3.14.3.2.7",
        "aliases": ["des", "des-cbc", "des-ecb"],
    },
    "Blowfish-128": {
        "canonical_name": "Blowfish-128",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 64,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Legacy/weak",
        "deprecated_or_disallowed": True,
        "oid": "1.3.6.1.4.1.3029.1.2",
        "aliases": ["blowfish", "blowfish-128"],
    },
    "Camellia-128": {
        "canonical_name": "Camellia-128",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.392.200011.61.1.1.1.2",
        "aliases": ["camellia-128", "camellia128"],
    },
    "Camellia-256": {
        "canonical_name": "Camellia-256",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.392.200011.61.1.1.1.4",
        "aliases": ["camellia", "camellia-256", "camellia256"],
    },
    "ChaCha20": {
        "canonical_name": "ChaCha20",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.9.16.3.18",
        "aliases": ["chacha20", "chacha"],
    },
    "ChaCha20-Poly1305": {
        "canonical_name": "ChaCha20-Poly1305",
        "family": "symmetric",
        "primitive": "AEAD",
        "crypto_role": "AEAD",
        "crypto_functions": ["encrypt", "decrypt", "mac"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.9.16.3.18",
        "aliases": ["chacha20-poly1305", "chacha20poly1305"],
    },
    "RC4": {
        "canonical_name": "RC4",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 0,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Legacy/weak",
        "deprecated_or_disallowed": True,
        "oid": "1.2.840.113549.3.4",
        "aliases": ["rc4", "arcfour"],
    },
    "ARIA-128": {
        "canonical_name": "ARIA-128",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.410.200046.1.1.1",
        "aliases": ["aria-128", "aria128"],
    },
    "ARIA-256": {
        "canonical_name": "ARIA-256",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.410.200046.1.1.11",
        "aliases": ["aria-256", "aria256", "aria"],
    },
    "SEED-128": {
        "canonical_name": "SEED-128",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.410.200004.1.4",
        "aliases": ["seed", "seed-128"],
    },
    "Twofish-256": {
        "canonical_name": "Twofish-256",
        "family": "symmetric",
        "primitive": "symmetric",
        "crypto_role": "encryption",
        "crypto_functions": ["encrypt", "decrypt"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.3.6.1.4.1.3029.1.2",
        "aliases": ["twofish", "twofish-256"],
    },

    # -------------------------------------------------------------------------
    # Cryptographic Hash & MAC & KDF Primitives
    # -------------------------------------------------------------------------
    "SHA-256": {
        "canonical_name": "SHA-256",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 2,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.1",
        "aliases": ["sha256", "sha-256", "sha_256", "sha-2"],
    },
    "SHA-384": {
        "canonical_name": "SHA-384",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 384,
        "classical_security_bits_est": 192,
        "nist_security_category": 4,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.2",
        "aliases": ["sha384", "sha-384", "sha_384"],
    },
    "SHA-512": {
        "canonical_name": "SHA-512",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 512,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.3",
        "aliases": ["sha512", "sha-512", "sha_512"],
    },
    "SHA-224": {
        "canonical_name": "SHA-224",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 224,
        "classical_security_bits_est": 112,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.4",
        "aliases": ["sha224", "sha-224", "sha_224"],
    },
    "SHA-1": {
        "canonical_name": "SHA-1",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 160,
        "classical_security_bits_est": 0,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Legacy/weak",
        "deprecated_or_disallowed": True,
        "oid": "1.3.14.3.2.26",
        "aliases": ["sha1", "sha-1", "sha_1"],
    },
    "MD5": {
        "canonical_name": "MD5",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 0,
        "nist_security_category": 0,
        "quantum_vulnerable": True,
        "quantum_attack_type": "Legacy/weak",
        "deprecated_or_disallowed": True,
        "oid": "1.2.840.113549.2.5",
        "aliases": ["md5"],
    },
    "SHA3-256": {
        "canonical_name": "SHA3-256",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 2,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.8",
        "aliases": ["sha3-256", "sha3_256", "sha3"],
    },
    "SHA3-384": {
        "canonical_name": "SHA3-384",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 384,
        "classical_security_bits_est": 192,
        "nist_security_category": 4,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.9",
        "aliases": ["sha3-384", "sha3_384"],
    },
    "SHA3-512": {
        "canonical_name": "SHA3-512",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "hash",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 512,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.10",
        "aliases": ["sha3-512", "sha3_512"],
    },
    "SHAKE128": {
        "canonical_name": "SHAKE128",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "XOF",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.11",
        "aliases": ["shake128", "shake-128"],
    },
    "SHAKE256": {
        "canonical_name": "SHAKE256",
        "family": "hash",
        "primitive": "digest",
        "crypto_role": "XOF",
        "crypto_functions": ["digest"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.2.12",
        "aliases": ["shake256", "shake-256"],
    },
    "HMAC-SHA256": {
        "canonical_name": "HMAC-SHA256",
        "family": "symmetric",
        "primitive": "mac",
        "crypto_role": "MAC",
        "crypto_functions": ["mac", "verify"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 2,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.2.9",
        "aliases": ["hmac-sha256", "hmac_sha256", "hmac-sha-256", "hmac"],
    },
    "HMAC-SHA512": {
        "canonical_name": "HMAC-SHA512",
        "family": "symmetric",
        "primitive": "mac",
        "crypto_role": "MAC",
        "crypto_functions": ["mac", "verify"],
        "key_or_hash_size_bits": 512,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "Grover",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.2.11",
        "aliases": ["hmac-sha512", "hmac_sha512", "hmac-sha-512"],
    },
    "HKDF-SHA256": {
        "canonical_name": "HKDF-SHA256",
        "family": "symmetric",
        "primitive": "kdf",
        "crypto_role": "KDF",
        "crypto_functions": ["kdf"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 128,
        "nist_security_category": 2,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.9.16.3.28",
        "aliases": ["hkdf", "hkdf-sha256", "hkdf_sha256"],
    },
    "Poly1305": {
        "canonical_name": "Poly1305",
        "family": "symmetric",
        "primitive": "mac",
        "crypto_role": "MAC",
        "crypto_functions": ["mac", "verify"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "1.2.840.113549.1.9.16.3.18",
        "aliases": ["poly1305"],
    },

    # -------------------------------------------------------------------------
    # Post-Quantum Cryptography (NIST FIPS 203, FIPS 204, FIPS 205 Standards)
    # -------------------------------------------------------------------------
    "ML-KEM-512": {
        "canonical_name": "ML-KEM-512",
        "family": "pqc",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-encapsulate"],
        "key_or_hash_size_bits": 512,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.4.1",
        "aliases": ["kyber512", "kyber-512", "ml-kem-512", "mlkem512"],
    },
    "ML-KEM-768": {
        "canonical_name": "ML-KEM-768",
        "family": "pqc",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-encapsulate"],
        "key_or_hash_size_bits": 768,
        "classical_security_bits_est": 192,
        "nist_security_category": 3,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.4.2",
        "aliases": ["kyber", "kyber768", "kyber-768", "ml-kem-768", "mlkem768", "ml-kem"],
    },
    "ML-KEM-1024": {
        "canonical_name": "ML-KEM-1024",
        "family": "pqc",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-encapsulate"],
        "key_or_hash_size_bits": 1024,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.4.3",
        "aliases": ["kyber1024", "kyber-1024", "ml-kem-1024", "mlkem1024"],
    },
    "ML-DSA-44": {
        "canonical_name": "ML-DSA-44",
        "family": "pqc",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 44,
        "classical_security_bits_est": 128,
        "nist_security_category": 2,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.3.17",
        "aliases": ["dilithium2", "dilithium-2", "ml-dsa-44", "mldsa44"],
    },
    "ML-DSA-65": {
        "canonical_name": "ML-DSA-65",
        "family": "pqc",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 65,
        "classical_security_bits_est": 192,
        "nist_security_category": 3,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.3.18",
        "aliases": ["dilithium", "dilithium3", "dilithium-3", "ml-dsa-65", "mldsa65", "ml-dsa"],
    },
    "ML-DSA-87": {
        "canonical_name": "ML-DSA-87",
        "family": "pqc",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 87,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.3.19",
        "aliases": ["dilithium5", "dilithium-5", "ml-dsa-87", "mldsa87"],
    },
    "SLH-DSA-SHA2-128s": {
        "canonical_name": "SLH-DSA-SHA2-128s",
        "family": "pqc",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 128,
        "classical_security_bits_est": 128,
        "nist_security_category": 1,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.3.22",
        "aliases": ["sphincs+", "sphincs-128s", "slh-dsa-sha2-128s", "slh-dsa"],
    },
    "SLH-DSA-SHA2-192s": {
        "canonical_name": "SLH-DSA-SHA2-192s",
        "family": "pqc",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 192,
        "classical_security_bits_est": 192,
        "nist_security_category": 3,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.3.24",
        "aliases": ["sphincs-192s", "slh-dsa-sha2-192s"],
    },
    "SLH-DSA-SHA2-256s": {
        "canonical_name": "SLH-DSA-SHA2-256s",
        "family": "pqc",
        "primitive": "signature",
        "crypto_role": "signature",
        "crypto_functions": ["sign", "verify"],
        "key_or_hash_size_bits": 256,
        "classical_security_bits_est": 256,
        "nist_security_category": 5,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "oid": "2.16.840.1.101.3.4.3.26",
        "aliases": ["sphincs-256s", "slh-dsa-sha2-256s"],
    },

    # -------------------------------------------------------------------------
    # Hybrid Post-Quantum Key Establishment & Signatures
    # -------------------------------------------------------------------------
    "X25519+ML-KEM-768": {
        "canonical_name": "X25519+ML-KEM-768",
        "family": "hybrid",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement", "key-encapsulate"],
        "key_or_hash_size_bits": 1024,
        "classical_security_bits_est": 192,
        "nist_security_category": 3,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "pqc_status": "HYBRID_PQC",
        "classical_component": "X25519",
        "pqc_component": "ML-KEM-768",
        "oid": "1.3.6.1.4.1.6222.1.1",
        "aliases": [
            "x25519+ml-kem-768",
            "x25519+mlkem768",
            "x25519-mlkem768",
            "x25519kyber768",
            "x25519+kyber768",
            "x25519_kyber768",
            "x25519_mlkem768",
        ],
    },
    "SecP256r1+ML-KEM-768": {
        "canonical_name": "SecP256r1+ML-KEM-768",
        "family": "hybrid",
        "primitive": "key_establishment",
        "crypto_role": "key_establishment",
        "crypto_functions": ["key-agreement", "key-encapsulate"],
        "key_or_hash_size_bits": 1024,
        "classical_security_bits_est": 192,
        "nist_security_category": 3,
        "quantum_vulnerable": False,
        "quantum_attack_type": "None known",
        "deprecated_or_disallowed": False,
        "pqc_status": "HYBRID_PQC",
        "classical_component": "ECDH-P256",
        "pqc_component": "ML-KEM-768",
        "oid": "1.3.6.1.4.1.6222.1.2",
        "aliases": [
            "secp256r1+ml-kem-768",
            "p256+ml-kem-768",
            "p256+mlkem768",
            "ecdh-p256+ml-kem-768",
            "p256_kyber768",
        ],
    },
}

# Fast Alias Index
_ALIAS_TO_CANONICAL: Dict[str, str] = {}
for canonical_id, data in CRYPTO_CATALOG.items():
    _ALIAS_TO_CANONICAL[canonical_id.lower()] = canonical_id
    for alias in data.get("aliases", []):
        _ALIAS_TO_CANONICAL[alias.lower()] = canonical_id


def classify_pqc_status(
    algorithm_name: Optional[str],
    catalog_entry: Optional[Dict[str, Any]] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Classifies the Post-Quantum Cryptography status of an algorithm:
    - PQC_NATIVE: NIST FIPS 203/204/205 native algorithms (ML-KEM, ML-DSA, SLH-DSA)
    - HYBRID_PQC: Composite classical + PQC constructions (e.g. X25519+ML-KEM-768)
    - SYMMETRIC_QUANTUM_RESILIENT: 256-bit symmetric and SHA-2/3 hashes (AES-256, ChaCha20, SHA-256)
    - SYMMETRIC_TRANSITIONAL: 128-bit symmetric ciphers (AES-128)
    - LEGACY_DEPRECATED: 3DES, DES, RC4, MD5, SHA-1
    - CLASSICAL_VULNERABLE: Classical asymmetric ciphers broken by Shor (RSA, ECDSA, ECDH, Ed25519)
    """
    algo_str = str(algorithm_name or "").strip().upper()
    entry = catalog_entry or lookup_crypto_algorithm(algorithm_name)
    params = parameters or {}

    # 1. Check Hybrid
    if (
        (entry and entry.get("family") == "hybrid")
        or "+" in algo_str
        or "HYBRID" in str(params.get("mode", "")).upper()
        or (params.get("classical") and params.get("pqc"))
        or any(h in algo_str for h in ["X25519KYBER", "X25519MLKEM", "P256KYBER", "P256MLKEM"])
    ):
        return "HYBRID_PQC"

    # 2. Check PQC Native
    if (
        (entry and entry.get("family") == "pqc")
        or any(p in algo_str for p in ["ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA", "KYBER", "DILITHIUM", "SPHINCS"])
    ):
        return "PQC_NATIVE"

    # 3. Check Legacy / Deprecated
    if (
        (entry and entry.get("deprecated_or_disallowed"))
        or any(w in algo_str for w in ["3DES", "DES", "RC4", "MD5", "SHA1", "SHA-1", "BLOWFISH"])
    ):
        return "LEGACY_DEPRECATED"

    # 4. Check Symmetric & Hashes
    fam = entry.get("family", "") if entry else ""
    bits = entry.get("key_or_hash_size_bits", 0) if entry else 0

    if fam in ("symmetric", "hash") or any(s in algo_str for s in ["AES", "CHACHA", "SHA2", "SHA3", "SHAKE", "HMAC"]):
        if "128" in algo_str or bits == 128:
            return "SYMMETRIC_TRANSITIONAL"
        return "SYMMETRIC_QUANTUM_RESILIENT"

    # 5. Default to Classical Vulnerable (RSA, ECC, DSA, DH)
    return "CLASSICAL_VULNERABLE"


def lookup_crypto_algorithm(
    algorithm_name: Optional[str],
    key_size: Optional[int] = None,
    curve: Optional[str] = None,
    mode: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Looks up normative cryptographic metadata for an algorithm name and parameters.
    Performs deterministic alias canonicalization and parameter synthesis.

    :param algorithm_name: Raw algorithm string (e.g. "RSA", "AES-GCM", "ECDSA")
    :param key_size: Optional bit length (e.g. 2048, 256)
    :param curve: Optional curve string (e.g. "secp256r1", "P-256", "Ed25519")
    :param mode: Optional cipher mode (e.g. "GCM", "CBC")
    :return: Canonical catalog dictionary or None if not recognized
    """
    if not algorithm_name:
        return None

    cleaned_name = str(algorithm_name).strip()
    raw_lower = cleaned_name.lower()

    # 1. Direct match with parameter synthesis
    # Try exact alias
    if raw_lower in _ALIAS_TO_CANONICAL:
        canonical = _ALIAS_TO_CANONICAL[raw_lower]
        entry = dict(CRYPTO_CATALOG[canonical])
        return entry

    # 2. Key-size guided resolution (e.g., name="RSA", key_size=4096 -> RSA-4096)
    if key_size:
        candidate = f"{cleaned_name}-{key_size}".lower()
        if candidate in _ALIAS_TO_CANONICAL:
            return dict(CRYPTO_CATALOG[_ALIAS_TO_CANONICAL[candidate]])

    # 3. Curve guided resolution (e.g., name="ECDSA", curve="P-256" -> ECDSA-P256)
    if curve:
        curve_clean = curve.replace("secp", "P").replace("r1", "").upper()
        if "256" in curve_clean:
            curve_clean = "P256"
        elif "384" in curve_clean:
            curve_clean = "P384"
        elif "521" in curve_clean:
            curve_clean = "P521"
        elif "224" in curve_clean:
            curve_clean = "P224"

        candidate_curve = f"{cleaned_name}-{curve_clean}".lower()
        if candidate_curve in _ALIAS_TO_CANONICAL:
            return dict(CRYPTO_CATALOG[_ALIAS_TO_CANONICAL[candidate_curve]])

    # 4. Pattern prefix matching
    if raw_lower.startswith("rsa"):
        if key_size == 1024:
            return dict(CRYPTO_CATALOG["RSA-1024"])
        elif key_size == 3072:
            return dict(CRYPTO_CATALOG["RSA-3072"])
        elif key_size == 4096:
            return dict(CRYPTO_CATALOG["RSA-4096"])
        return dict(CRYPTO_CATALOG["RSA-2048"])

    if raw_lower.startswith("aes"):
        if key_size == 128:
            return dict(CRYPTO_CATALOG["AES-128"])
        elif key_size == 192:
            return dict(CRYPTO_CATALOG["AES-192"])
        return dict(CRYPTO_CATALOG["AES-256"])

    if raw_lower.startswith("ecdsa"):
        if curve and ("384" in curve):
            return dict(CRYPTO_CATALOG["ECDSA-P384"])
        elif curve and ("521" in curve):
            return dict(CRYPTO_CATALOG["ECDSA-P521"])
        elif curve and ("224" in curve):
            return dict(CRYPTO_CATALOG["ECDSA-P224"])
        return dict(CRYPTO_CATALOG["ECDSA-P256"])

    if raw_lower.startswith("ecdh"):
        if curve and ("384" in curve):
            return dict(CRYPTO_CATALOG["ECDH-P384"])
        elif curve and ("521" in curve):
            return dict(CRYPTO_CATALOG["ECDH-P521"])
        elif curve and ("224" in curve):
            return dict(CRYPTO_CATALOG["ECDH-P224"])
        return dict(CRYPTO_CATALOG["ECDH-P256"])

    return None


def canonicalize_algorithm_name(
    name: Optional[str],
    key_size: Optional[int] = None,
    curve: Optional[str] = None,
) -> str:
    """
    Returns the normalized canonical string for an algorithm.
    """
    entry = lookup_crypto_algorithm(name, key_size=key_size, curve=curve)
    if entry:
        return entry["canonical_name"]
    return str(name or "unknown").strip()


def is_quantum_vulnerable(algorithm_name: Optional[str], key_size: Optional[int] = None) -> bool:
    """
    Returns True if the algorithm is vulnerable to Shor's or Grover's algorithm or is weak.
    """
    entry = lookup_crypto_algorithm(algorithm_name, key_size=key_size)
    if entry:
        return bool(entry.get("quantum_vulnerable", False))
    return False


def get_nist_quantum_level(algorithm_name: Optional[str], key_size: Optional[int] = None) -> int:
    """
    Returns the NIST quantum security level (0..5).
    """
    entry = lookup_crypto_algorithm(algorithm_name, key_size=key_size)
    if entry:
        return int(entry.get("nist_security_category", 0))
    return 0


def get_classical_security_level(algorithm_name: Optional[str], key_size: Optional[int] = None) -> int:
    """
    Returns the estimated classical security strength in bits (0..512).
    """
    entry = lookup_crypto_algorithm(algorithm_name, key_size=key_size)
    if entry:
        return int(entry.get("classical_security_bits_est", 0))
    return 0
