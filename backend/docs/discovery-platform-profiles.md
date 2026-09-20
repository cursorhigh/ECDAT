# Platform-aware discovery profiles

ECDAT's Discovery scanner is per-OS aware: the set of directories it walks for
a *Quick* or *Whole System* scan is chosen from researched, canonical
crypto-material locations, not from a single project folder. A *Specified
Path* scan walks exactly the folder the user chose.

Scope resolution lives in `segments/scraping/discovery/scanners/platform.py`; the engine that
walks the roots is `segments/scraping/discovery/scanners/crypto_artefact.py`.

## The three scan scopes

| Scope      | What it walks                                                                  | Budget (default)          |
|------------|--------------------------------------------------------------------------------|---------------------------|
| `quick`    | Curated high-yield platform locations + the ECDAT workspace (`BASE_DIR`).      | 10k files · depth 12      |
| `whole`    | Every drive (Windows) or the filesystem root (POSIX), minus pruned dirs.       | 200k files · depth 64     |
| `specified`| The exact folder the user selected.                                            | 20k files · depth 32      |

Budgets are per-run and overridable via `ScanJob.config` keys `max_files`,
`max_depth`, `max_file_size`, `extensions`. Files larger than `max_file_size`
are skipped; directories named in the platform `prune_names` (plus the global
VCS/dependency set) are never descended into.

## What we look for per platform

### Linux / generic POSIX
- **System PKI / TLS**: `/etc/ssl/{certs,private}`, `/etc/pki/tls/{certs,private}`,
  `/etc/pki/CA/{certs,private}`, `/usr/share/ca-certificates`,
  `/usr/local/share/ca-certificates`, `/etc/letsencrypt/{live,archive}`,
  `/etc/ssl/ca/private`, `/usr/lib/ssl`, `/usr/local/ssl`.
- **SSH**: `/etc/ssh` host keys, `/root/.ssh`, `~/.ssh` (keys carry no extension,
  so these roots bypass the extension filter).
- **Services**: nginx/apache/haproxy TLS dirs, `/etc/cockpit/ws-certs.d`,
  postgres/mysql/redis TLS configs, `/etc/ipsec.d`, `/etc/ppp`,
  `/etc/openvpn`, `/etc/wireguard`, `/etc/stunnel`, dovecot/postfix.
- **Developer/cloud credentials**: `~/.gnupg` (OpenPGP keyrings),
  `~/.kube/config`, `~/.docker/config.json`, `~/.aws/{config,credentials}`,
  `~/.azure`, `~/.gcloud`, `~/.config/git`, `~/.pki/nssdb`, firefox NSS DBs.
- **Keystores**: Java `cacerts` (per distro: `/etc/ssl/certs/java`,
  `/etc/pki/java`, every JDK under `/usr/lib/jvm`), `~/.java`, `~/.gradle`,
  `~/.m2`, `/opt/tomcat/conf`.
- **Never scanned**: pseudo-FS (`/proc /sys /dev /run`), `tmp`, mounts,
  snap/flatpak and cache trees.

### Windows
- **CNG / CryptoAPI key containers** (GUID files, no extension — bypass the
  extension filter): `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys`,
  `...\DSS\MachineKeys`, `...\Keys`, `...\SystemKeys`,
  `%APPDATA%\Microsoft\Crypto`, `%APPDATA%\Microsoft\SystemCertificates`,
  `%APPDATA%\Microsoft\Protect` (DPAPI master keys).
- **AD CS**: `%SystemRoot%\System32\CertSrv\CertEnroll`, `CertLog`.
- **IIS**: `%SystemRoot%\System32\inetsrv\config` (`applicationHost.config`
  HTTPS bindings).
- **User crypto**: `%USERPROFILE%\.ssh`, `%APPDATA%\PuTTY` (`.ppk`),
  `%APPDATA%\gnupg`, `%USERPROFILE%\.kube`, `.docker`, `.aws`, `.azure`.
- **OpenSSL / Git-for-Windows**: `Program Files\Git\{mingw64,usr}\ssl`,
  `Program Files\OpenSSL-Win64|Win32`.
- **Keystores**: `%USERPROFILE%\.java/.gradle/.m2`, SQL Server config dirs.
- **Pruned during whole scans**: `$Recycle.Bin`, `System Volume Information`,
  `Temp`, WinSxS/WindowsApps/servicing/SoftwareDistribution/Installer caches.

### macOS
- **Keychains** (SQLite databases read as files): `~/Library/Keychains`
  (login + iCloud), `/Library/Keychains` (System/apsd/FileVaultMaster),
  `/System/Library/Keychains` (SystemRootCertificates — SIP may block reads,
  handled gracefully).
- **System TLS/PKI**: `/etc/ssl`, `/etc/security`, `/etc/openldap`,
  `/etc/apache2`, `/etc/nginx`, `/etc/ssh`.
- **User crypto**: `~/Library/Application Support`, `~/Library/Preferences`,
  `~/.ssh`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.aws`, `~/.azure`, `~/.gcloud`.
- **Pruned during whole scans**: `/System`, `/Volumes`, cores/networks, caches.

### Other POSIX (FreeBSD/NetBSD/AIX/Solaris/...)
- Generic aliases (`/usr/local/share/certs`, `/etc/openssl/certs`,
  `/var/ssl/certs`) plus the home credential dirs. Detection is content-based,
  so unknown distros still get good coverage.

## Why these locations

- Certificate/root bundles live in per-distro trees that even Go, OpenSSL and
  Java hard-code (`/etc/ssl/certs`, `/etc/pki/{tls,ca-trust}`, `/usr/lib/ssl`).
- Private key material concentrates in a small number of well-documented
  places: PKI private dirs, service configs, SSH, GnuPG, and CNG/CryptoAPI
  machine-key containers on Windows.
- Windows key-container files have no useful extension, so the scanned roots
  are flagged `scan_all` (bypass the extension filter).

## Content rules added alongside the profiles

Walking `/etc/pki` or `MachineKeys` only pays off if the detector can actually
recognise the material. The following rules were added to `crypto_rules.yar`
(and mapped in `_RULE_META`):

`Crypto_Certificate_RSA`, `Crypto_Certificate_EC` (PEM/DER certs, RSA/EC OIDs),
`Crypto_PrivateKey_{RSA,EC,DSA,OpenSSH}` (PKCS#1/#8/OpenSSH headers),
`Crypto_SSH_{RSA,ECDSA,Ed25519,DSA}` (`ssh-rsa`/`ecdsa-sha2-*`/`ssh-ed25519`/
`ssh-dss` lines), `Crypto_OpenPGP` (armored PGP blocks), `Crypto_PKCS12`
(PFX/PKCS12 marker), `Crypto_DH_Parameters` (DH PEM / ffdhe groups).

## Reference list of files

- `segments/scraping/discovery/scanners/platform.py` — profiles, detection, root resolution.
- `segments/scraping/discovery/scanners/crypto_artefact.py` — scope-aware walker + rule metadata.
- `segments/scraping/discovery/services.py` — stores `scan_type` in `ScanJob.config`.
- `crypto_rules.yar` — key-material YARA rules.
- `segments/scraping/discovery/views.py` + `segments/scraping/discovery/urls.py` — `/api/scan-preview/` endpoint.
- `segments/reporting/dashboard/templates/dashboard/discovery.html` — scan-type cards + preview.