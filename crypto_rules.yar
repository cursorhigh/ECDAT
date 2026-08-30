/*
 * ECDAT crypto discovery YARA rules.
 *
 * These rules are heuristic detectors for common cryptographic algorithm
 * usage and libraries in source/binary files. They are intentionally broad:
 * scanning seeks to *discover* candidate crypto artefacts, not to be a full
 * static analysis. Confidence can be tuned per-rule later.
 *
 * Each rule emits "key_size" / "algorithm" / "kind" metadata strings to help
 * downstream aggregation.
 */

rule Crypto_RSA
{
    meta:
        description = "RSA key/cipher usage"
        algorithm = "RSA"
        kind = "public_key"
        reference = "RSA"
    strings:
        $main = "RSA" nocase
        $key = "BEGIN PUBLIC KEY" nocase
        $pri = "BEGIN RSA PRIVATE KEY" nocase
        $rsa = "rsa" nocase
        $PKCS = "PKCS"
    condition:
        filesize < 4MB and
        (
            ($main and #main > 2) or
            $key or $pri or $rsa or $PKCS
        )
}

rule Crypto_ECC
{
    meta:
        description = "Elliptic-curve cryptography usage"
        algorithm = "ECC"
        kind = "public_key"
        reference = "ECC"
    strings:
        $ec = "ecdsa" nocase
        $ecdh = "ecdh" nocase
        $ecp = "ecp" nocase ascii wide
        $curve = "prime256v1" nocase
        $secp = "secp256k1" nocase
        $x25519 = "x25519" nocase
        $ed25519 = "ed25519" nocase
    condition:
        filesize < 4MB and any of them
}

rule Crypto_AES
{
    meta:
        description = "AES symmetric cipher usage"
        algorithm = "AES"
        kind = "symmetric"
        reference = "AES"
    strings:
        $aes = "aes" nocase ascii
        $cbc = "aes-128-cbc" nocase
        $gcm = "aes-128-gcm" nocase
        $ctr = "aes-256-ctr" nocase
        $cipher = "AES/ECB" nocase
    condition:
        filesize < 4MB and (#aes >= 2 or any of ($cbc, $gcm, $ctr, $cipher))
}

rule Crypto_Hash
{
    meta:
        description = "Hash function usage"
        algorithm = "HASH"
        kind = "hash"
        reference = "HASH"
    strings:
        $sha1 = "sha1" nocase
        $sha256 = "sha256" nocase
        $sha512 = "sha512" nocase
        $md5 = "md5" nocase
        $sha3 = "sha3" nocase
        $blake = "blake2" nocase
    condition:
        filesize < 4MB and any of them
}

rule Crypto_WeakHash_MD5
{
    meta:
        description = "MD5 usage (weak, avoid)"
        algorithm = "MD5"
        kind = "hash"
        reference = "MD5"
    strings:
        $md5 = "md5" nocase
        $md5_ctx = "MD5_Init" nocase
        $md5_digest = "MD5_Digest" nocase
    condition:
        filesize < 4MB and (#md5 >= 2 or $md5_ctx or $md5_digest)
}

rule Crypto_PostQuantum
{
    meta:
        description = "Post-quantum algorithm usage"
        algorithm = "PQC"
        kind = "post_quantum"
        reference = "PQC"
    strings:
        $mlkem = "ml-kem" nocase
        $kyber = "kyber" nocase
        $mldsa = "ml-dsa" nocase
        $dilithium = "dilithium" nocase
        $slhdsa = "slh-dsa" nocase
        $sphincs = "sphincs" nocase
        $falcon = "falcon" nocase
    condition:
        filesize < 4MB and any of them
}

rule Crypto_TLS
{
    meta:
        description = "TLS/SSL protocol usage"
        algorithm = "TLS"
        kind = "protocol"
        reference = "TLS"
    strings:
        $ssl = "ssl" nocase
        $tls = "tls" nocase
        $open = "openssl" nocase
        $handshake = "ssl_connect" nocase
    condition:
        filesize < 4MB and (#ssl >= 2 or $open or $tls or $handshake)
}

rule Crypto_Library_BoringSSL
{
    meta:
        description = "BoringSSL library usage"
        algorithm = "BoringSSL"
        kind = "library"
        reference = "BoringSSL"
    strings:
        $boring = "bssl" nocase
        $fips = "BORINGSSL_FIPS" nocase
    condition:
        filesize < 4MB and any of them
}
