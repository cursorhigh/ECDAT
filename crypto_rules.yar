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

/*
 * Platform/key-material rules.
 *
 * These catch what the pipeline-level detectors miss: X.509 certificates
 * (PEM and DER), private keys (PKCS#1/#8, OpenSSH), SSH public keys, OpenPGP
 * keyrings, PKCS#12 containers and Diffie-Hellman parameters. They make the
 * per-OS discovery profiles actually return findings from system PKI trees,
 * key containers and ~/.ssh.
 */

rule Crypto_Certificate_RSA
{
    meta:
        description = "X.509 certificate carrying an RSA public key (PEM or DER)"
        algorithm = "X509-RSA"
        kind = "certificate"
        reference = "RSA"
    strings:
        $pem = "BEGIN CERTIFICATE" ascii nocase
        $trusted = "BEGIN TRUSTED CERTIFICATE" ascii nocase
        $oid = {06 09 2a 86 48 86 f7 0d 01 01 01}    /* rsaEncryption */
    condition:
        filesize < 4MB and ($pem or $trusted or $oid)
}

rule Crypto_Certificate_EC
{
    meta:
        description = "X.509 certificate carrying an EC public key (PEM or DER)"
        algorithm = "X509-EC"
        kind = "certificate"
        reference = "ECC"
    strings:
        $pem = "BEGIN CERTIFICATE" ascii nocase
        $trusted = "BEGIN TRUSTED CERTIFICATE" ascii nocase
        $oid = {06 07 2a 86 48 ce 3d 02 01}          /* id-ecPublicKey */
    condition:
        filesize < 4MB and ($pem or $trusted or $oid)
}

rule Crypto_PrivateKey_RSA
{
    meta:
        description = "RSA private key (PKCS#1 PEM or PKCS#8 with rsaEncryption OID)"
        algorithm = "RSA-private"
        kind = "private_key"
        reference = "RSA"
    strings:
        $pkcs1 = "BEGIN RSA PRIVATE KEY" ascii nocase
        $pkcs8 = "BEGIN PRIVATE KEY" ascii nocase
        $enc = "BEGIN ENCRYPTED PRIVATE KEY" ascii nocase
        $oid = {06 09 2a 86 48 86 f7 0d 01 01 01}    /* rsaEncryption */
    condition:
        filesize < 4MB and ($pkcs1 or (($pkcs8 or $enc) and $oid))
}

rule Crypto_PrivateKey_EC
{
    meta:
        description = "EC private key (SEC1 PEM or PKCS#8 with id-ecPublicKey OID)"
        algorithm = "EC-private"
        kind = "private_key"
        reference = "ECC"
    strings:
        $sec1 = "BEGIN EC PRIVATE KEY" ascii nocase
        $pkcs8 = "BEGIN PRIVATE KEY" ascii nocase
        $enc = "BEGIN ENCRYPTED PRIVATE KEY" ascii nocase
        $oid = {06 07 2a 86 48 ce 3d 02 01}          /* id-ecPublicKey */
    condition:
        filesize < 4MB and ($sec1 or (($pkcs8 or $enc) and $oid))
}

rule Crypto_PrivateKey_DSA
{
    meta:
        description = "DSA private key (PKCS#1-style PEM header)"
        algorithm = "DSA-private"
        kind = "private_key"
        reference = "DSA"
    strings:
        $dsa = "BEGIN DSA PRIVATE KEY" ascii nocase
    condition:
        filesize < 4MB and $dsa
}

rule Crypto_PrivateKey_OpenSSH
{
    meta:
        description = "OpenSSH private key container"
        algorithm = "OpenSSH-private"
        kind = "private_key"
        reference = "OpenSSH"
    strings:
        $hdr = "-----BEGIN OPENSSH PRIVATE KEY" ascii
        $rsa = "ssh-rsa " ascii
        $ed = "ssh-ed25519 " ascii
        $kdf = "bcrypt" ascii
    condition:
        filesize < 4MB and ($hdr or ($kdf and ($rsa or $ed)))
}

rule Crypto_SSH_RSA
{
    meta:
        description = "SSH RSA public key line"
        algorithm = "RSA-SSH"
        kind = "public_key"
        reference = "SSH"
    strings:
        $r = "ssh-rsa " ascii
    condition:
        filesize < 4MB and $r
}

rule Crypto_SSH_ECDSA
{
    meta:
        description = "SSH ECDSA public key line"
        algorithm = "ECDSA-SSH"
        kind = "public_key"
        reference = "SSH"
    strings:
        $e = "ecdsa-sha2-nistp" ascii
    condition:
        filesize < 4MB and #e >= 1
}

rule Crypto_SSH_Ed25519
{
    meta:
        description = "SSH Ed25519 public key line"
        algorithm = "Ed25519-SSH"
        kind = "public_key"
        reference = "SSH"
    strings:
        $e = "ssh-ed25519 " ascii
    condition:
        filesize < 4MB and $e
}

rule Crypto_SSH_DSA
{
    meta:
        description = "SSH DSA public key line"
        algorithm = "DSA-SSH"
        kind = "public_key"
        reference = "SSH"
    strings:
        $d = "ssh-dss " ascii
    condition:
        filesize < 4MB and $d
}

rule Crypto_OpenPGP
{
    meta:
        description = "OpenPGP armored key block"
        algorithm = "OpenPGP"
        kind = "public_key"
        reference = "OpenPGP"
    strings:
        $arm = "-----BEGIN PGP" ascii nocase
    condition:
        filesize < 4MB and $arm
}

rule Crypto_PKCS12
{
    meta:
        description = "PKCS#12/PFX container"
        algorithm = "PKCS12"
        kind = "container"
        reference = "PKCS12"
    strings:
        $pem = "-----BEGIN PKCS12" ascii nocase
        $oid = {06 0a 2a 86 48 86 f7 0d 01 0c 0a 01} /* pkcs-12-PBE/pfx */
    condition:
        filesize < 4MB and ($pem or $oid)
}

rule Crypto_DH_Parameters
{
    meta:
        description = "Diffie-Hellman parameters"
        algorithm = "DH"
        kind = "public_key"
        reference = "DH"
    strings:
        $pem = "BEGIN DH PARAMETERS" ascii nocase
        $ffdhe = "ffdhe" ascii nocase
        $rfc = "rfc3526" ascii nocase
    condition:
        filesize < 4MB and any of them
}
