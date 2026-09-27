"""Platform-aware discovery targets.

Decides *what* a discovery scan walks based on the operating system and the
requested scan scope:

    quick     -> curated "most proven places" per platform (high-yield paths)
                 plus the current workspace (BASE_DIR).
    whole     -> the whole filesystem (all drives on Windows, "/" on POSIX).
    specified -> the exact folder the user gave (single root, no profile).

The profiles encode well-documented, canonical crypto-material locations:

  * Linux/POSIX: /etc/ssl + /etc/pki trees, /etc/letsencrypt (ACME),
    /etc/ssh host keys, ~/.ssh, ~/.gnupg, kube/docker/aws/azure/gcloud CLI
    creds, Java cacerts/keystore locations, per-service TLS dirs
    (nginx, apache, haproxy, postgres, mysql, redis, ipsec, wireguard...).
  * Windows: CNG/CryptoAPI key containers
    (%ProgramData%\\Microsoft\\Crypto, %APPDATA%\\Microsoft\\Crypto),
    AD CS (CertSrv\\CertEnroll, CertLog), IIS HTTPS config
    (applicationHost.config), SSH/PuTTY/GnuPG/kube/aws/docker app dirs,
    Git-for-Windows / OpenSSL ssl directories.
  * macOS: Keychain SQLite databases (~/Library/Keychains,
    /Library/Keychains, /System/Library/Keychains), /etc/ssl trees,
    /etc/ssh, ~/.ssh, ~/.gnupg, app-support/credential dirs.
  * other (FreeBSD/NetBSD/AIX/Solaris/...): generic POSIX aliases
    (/usr/local/share/certs, /etc/openssl/certs, /var/ssl/certs) + home
    credential dirs. Detection is content-based (YARA) so unknown distros
    still work.

Only directories that actually exist are returned by ``resolve_scan_roots``,
so a profile degrades gracefully (fewer, or zero, roots) on hosts that do not
have every package installed.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Platform detection
# --------------------------------------------------------------------------

PLATFORM_WINDOWS = "windows"
PLATFORM_LINUX = "linux"
PLATFORM_DARWIN = "darwin"
PLATFORM_OTHER = "other"


def detect_platform() -> str:
    """Return the discovery platform family for the running OS."""
    if os.name == "nt" or sys.platform.startswith("win"):
        return PLATFORM_WINDOWS
    if sys.platform.startswith("linux"):
        return PLATFORM_LINUX
    if sys.platform == "darwin":
        return PLATFORM_DARWIN
    return PLATFORM_OTHER


# --------------------------------------------------------------------------
# Scope defaults
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ScopeLimits:
    """Walker budget for one scan scope (override via ScanJob.config).

    Every field is optional: ``None`` means unbounded, so discovery covers the
    whole target by default and nothing is silently truncated. A caller can
    still set an explicit ceiling through ``ScanJob.config``; when one is hit
    the scan reports PARTIAL with the reason rather than reporting success.
    """

    max_files: int | None = None
    max_depth: int | None = None
    max_file_size: int | None = None  # bytes; None = inspect files of any size


# Discovery covers everything by default. Limits exist only as an opt-in
# ceiling for very large targets.
UNBOUNDED = ScopeLimits()

SCOPE_LIMITS = {
    "quick": UNBOUNDED,
    "whole": UNBOUNDED,
    "specified": UNBOUNDED,
}

# VCS / dependency / build-cache directory names skipped in every walk.
GLOBAL_PRUNE_NAMES = frozenset(
    {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__", "staticfiles"}
)

# Extra per-platform directory names to skip while walking (empty/fake FS
# mounts, recycle bins, Windows servicing stores, caches). These live here so
# a "whole" sweep does not churn through pseudo-filesystems or 10 GB temp
# trees, while still covering every real crypto-bearing location.
_LINUX_PRUNE_NAMES = frozenset({"proc", "sys", "dev", "run", "tmp", "mnt", "media",
                                "lost+found", "snap", "flatpak", "core", "cache"})
_WINDOWS_PRUNE_NAMES = frozenset({"$Recycle.Bin", "System Volume Information", "Temp",
                                  "tmp", "cache", "WinSxS", "WindowsApps", "servicing",
                                  "SoftwareDistribution", "Installer", "Recovery", "core"})
_DARWIN_PRUNE_NAMES = frozenset({"System", "private", "Volumes", "cores", "Network",
                                 "tmp", "dev", "proc", "cache", "SystemRoot"})
_OTHER_PRUNE_NAMES = frozenset({"proc", "sys", "dev", "run", "tmp", "mnt", "media",
                                "lost+found", "core", "cache"})


# --------------------------------------------------------------------------
# Per-platform profiles
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RootTarget:
    """One directory the walker scans.

    ``scan_all`` bypasses the extension filter (key-material dirs whose files
    carry no extension: Windows CNG key containers, SSH keys, GnuPG, PGP fds).
    """

    root: str          # raw path; ~ and env vars are expanded at resolve time
    label: str         # human label used as the finding-location prefix
    scan_all: bool = False


@dataclass(frozen=True)
class PlatformProfile:
    """Everything the walker needs to know about one operating system."""

    platform: str
    quick_roots: tuple[RootTarget, ...] = ()
    whole_roots: tuple[str, ...] = ()          # raw patterns; drives handled at runtime
    prune_names: frozenset[str] = frozenset()  # extra directory names to skip
    whole_from_drives: bool = False            # Windows: enumerate all drives


def _r(path: str, scan_all: bool = False) -> RootTarget:
    return RootTarget(root=path, label=path, scan_all=scan_all)


# -- Linux / generic POSIX ------------------------------------------------

_LINUX_QUICK_ROOTS = (
    # System PKI / TLS
    _r("/etc/ssl"),
    _r("/etc/pki/tls"),
    _r("/etc/pki/CA"),
    _r("/usr/local/share/ca-certificates"),
    _r("/usr/share/ca-certificates"),
    _r("/etc/letsencrypt/live"),
    _r("/etc/letsencrypt/archive"),
    _r("/etc/ssl/ca/private"),
    _r("/etc/ipsec.d"),
    _r("/etc/ppp"),
    # SSH (system + root + user) - key files carry no extension
    RootTarget("/etc/ssh", "/etc/ssh", scan_all=True),
    RootTarget("/root/.ssh", "/root/.ssh", scan_all=True),
    RootTarget("~/.ssh", "~/.ssh", scan_all=True),
    # Web / reverse proxies
    _r("/etc/nginx"),
    _r("/etc/apache2"),
    _r("/etc/haproxy"),
    _r("/etc/cockpit/ws-certs.d"),
    # Databases / messaging / VPN services
    _r("/etc/postgresql"),
    _r("/etc/mysql"),
    _r("/etc/redis"),
    _r("/etc/openvpn"),
    RootTarget("/etc/wireguard", "/etc/wireguard", scan_all=True),
    _r("/etc/stunnel"),
    _r("/etc/dovecot"),
    _r("/etc/postfix"),
    # User / developer credential dirs
    RootTarget("~/.gnupg", "~/.gnupg", scan_all=True),
    _r("~/.kube"),
    _r("~/.docker"),
    _r("~/.aws"),
    _r("~/.azure"),
    _r("~/.gcloud"),
    _r("~/.config/git"),
    _r("~/.pki/nssdb"),
    _r("~/.mozilla/firefox"),
    _r("~/.java"),
    _r("~/.gradle"),
    _r("~/.m2"),
    # Java keystores (system, incl. every installed JDK)
    _r("/etc/ssl/certs/java"),
    _r("/etc/pki/java"),
    _r("/usr/lib/jvm"),
    _r("/opt/tomcat/conf"),
)

_LINUX_PROFILE = PlatformProfile(
    platform=PLATFORM_LINUX,
    quick_roots=_LINUX_QUICK_ROOTS,
    whole_roots=("/",),
    prune_names=_LINUX_PRUNE_NAMES,
)


# -- Windows --------------------------------------------------------------

_WINDOWS_QUICK_ROOTS = (
    # CNG / CryptoAPI key containers (machine + per-user) - GUID files, no ext
    RootTarget(r"%ProgramData%\Microsoft\Crypto\RSA\MachineKeys",
               r"%ProgramData%\Microsoft\Crypto\RSA", scan_all=True),
    RootTarget(r"%ProgramData%\Microsoft\Crypto\DSS\MachineKeys",
               r"%ProgramData%\Microsoft\Crypto\DSS", scan_all=True),
    RootTarget(r"%ProgramData%\Microsoft\Crypto\Keys",
               r"%ProgramData%\Microsoft\Crypto", scan_all=True),
    RootTarget(r"%ProgramData%\Microsoft\Crypto\SystemKeys",
               r"%ProgramData%\Microsoft\Crypto", scan_all=True),
    RootTarget(r"%APPDATA%\Microsoft\Crypto", r"%APPDATA%\Microsoft\Crypto", scan_all=True),
    _r(r"%APPDATA%\Microsoft\SystemCertificates"),
    _r(r"%APPDATA%\Microsoft\Protect"),
    # AD CS publishing / cert DB
    _r(r"%SystemRoot%\System32\CertSrv\CertEnroll"),
    _r(r"%SystemRoot%\System32\CertLog"),
    # IIS HTTPS bindings / TLS config
    _r(r"%SystemRoot%\System32\inetsrv\config"),
    # SSH / PuTTY / GnuPG (per-user)
    RootTarget(r"%USERPROFILE%\.ssh", r"%USERPROFILE%\.ssh", scan_all=True),
    _r(r"%APPDATA%\PuTTY"),
    RootTarget(r"%APPDATA%\gnupg", r"%APPDATA%\gnupg", scan_all=True),
    # Cloud / container CLI credentials
    _r(r"%USERPROFILE%\.kube"),
    _r(r"%USERPROFILE%\.docker"),
    _r(r"%USERPROFILE%\.aws"),
    _r(r"%USERPROFILE%\.azure"),
    # OpenSSL / Git-for-Windows SSL config
    _r(r"%ProgramFiles%\Git\mingw64\ssl"),
    _r(r"%ProgramFiles%\Git\usr\ssl"),
    _r(r"%ProgramFiles%\OpenSSL-Win64"),
    _r(r"%ProgramFiles%\OpenSSL-Win32"),
    # Java / app keystores
    _r(r"%USERPROFILE%\.java"),
    _r(r"%USERPROFILE%\.gradle"),
    _r(r"%USERPROFILE%\.m2"),
    _r(r"%APPDATA%\Microsoft\Microsoft SQL Server"),
)

_WINDOWS_PROFILE = PlatformProfile(
    platform=PLATFORM_WINDOWS,
    quick_roots=_WINDOWS_QUICK_ROOTS,
    whole_roots=(),
    prune_names=_WINDOWS_PRUNE_NAMES,
    whole_from_drives=True,
)


# -- macOS ----------------------------------------------------------------

_DARWIN_QUICK_ROOTS = (
    # Keychains (SQLite files on disk; encrypted - matched by format where possible)
    RootTarget("~/Library/Keychains", "~/Library/Keychains", scan_all=True),
    RootTarget("/Library/Keychains", "/Library/Keychains", scan_all=True),
    RootTarget("/System/Library/Keychains", "/System/Library/Keychains", scan_all=True),
    # System TLS / PKI
    _r("/etc/ssl"),
    _r("/etc/security"),
    _r("/etc/openldap"),
    _r("/etc/apache2"),
    _r("/etc/nginx"),
    RootTarget("/etc/ssh", "/etc/ssh", scan_all=True),
    # User credential / dev dirs
    _r("~/Library/Application Support"),
    _r("~/Library/Preferences"),
    RootTarget("~/.ssh", "~/.ssh", scan_all=True),
    RootTarget("~/.gnupg", "~/.gnupg", scan_all=True),
    _r("~/.kube"),
    _r("~/.docker"),
    _r("~/.aws"),
    _r("~/.azure"),
    _r("~/.gcloud"),
    _r("~/.java"),
    _r("~/.gradle"),
    _r("~/.m2"),
)

_DARWIN_PROFILE = PlatformProfile(
    platform=PLATFORM_DARWIN,
    quick_roots=_DARWIN_QUICK_ROOTS,
    whole_roots=("/",),
    prune_names=_DARWIN_PRUNE_NAMES,
)


# -- Other POSIX ----------------------------------------------------------

_OTHER_QUICK_ROOTS = (
    _r("/etc/ssl"),
    _r("/usr/local/share/certs"),
    _r("/etc/openssl/certs"),
    _r("/var/ssl/certs"),
    RootTarget("/etc/ssh", "/etc/ssh", scan_all=True),
    RootTarget("/root/.ssh", "/root/.ssh", scan_all=True),
    RootTarget("~/.ssh", "~/.ssh", scan_all=True),
    RootTarget("~/.gnupg", "~/.gnupg", scan_all=True),
    _r("~/.kube"),
    _r("~/.docker"),
    _r("~/.aws"),
    _r("~/.azure"),
    _r("~/.gcloud"),
    _r("~/.java"),
    _r("~/.gradle"),
    _r("~/.m2"),
)

_OTHER_PROFILE = PlatformProfile(
    platform=PLATFORM_OTHER,
    quick_roots=_OTHER_QUICK_ROOTS,
    whole_roots=("/",),
    prune_names=_OTHER_PRUNE_NAMES,
)


PLATFORM_PROFILES = {
    PLATFORM_WINDOWS: _WINDOWS_PROFILE,
    PLATFORM_LINUX: _LINUX_PROFILE,
    PLATFORM_DARWIN: _DARWIN_PROFILE,
    PLATFORM_OTHER: _OTHER_PROFILE,
}


# --------------------------------------------------------------------------
# Root resolution
# --------------------------------------------------------------------------

def _expand(path: str) -> str:
    """Expand ~ and environment variables to an absolute path."""
    return os.path.abspath(os.path.expandvars(os.path.expanduser(path)))


def _list_drives() -> list[str]:
    """Return existing drive roots (Windows) or ["/"] (POSIX)."""
    if os.name != "nt":
        return ["/"]
    import string

    from ctypes import windll

    roots: list[str] = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            root = f"{letter}:\\"
            if os.path.isdir(root):
                roots.append(root)
        bitmask >>= 1
    return roots or ["C:\\"]


def _workspace_root() -> RootTarget | None:
    """The ECDAT project directory, when present (used by quick scans)."""
    from django.conf import settings

    base = getattr(settings, "BASE_DIR", None)
    if base and os.path.isdir(base):
        return RootTarget(root=str(base), label="WORKSPACE", scan_all=False)
    return None


def _profile_for(scan_job) -> PlatformProfile:
    return PLATFORM_PROFILES.get(detect_platform(), _OTHER_PROFILE)


def _scan_type_of(scan_job) -> str:
    config = scan_job.config or {}
    target = (scan_job.target or "").strip().lower()
    scan_type = str(config.get("scan_type") or target or "specified").strip().lower()
    return scan_type if scan_type in SCOPE_LIMITS else "specified"


def resolve_scan_roots(scan_job) -> list[RootTarget]:
    """Return the RootTargets to walk for a ScanJob's scope.

    Scope is read from ``ScanJob.config["scan_type"]`` (falling back to the
    ``target`` token for jobs queued before the config field existed). Only
    existing directories are returned; ``[]`` means the caller should fall
    back to its own default target.
    """
    scan_type = _scan_type_of(scan_job)
    profile = _profile_for(scan_job)
    roots: list[RootTarget] = []

    if scan_type == "quick":
        for target in profile.quick_roots:
            expanded = _expand(target.root)
            if os.path.isdir(expanded):
                roots.append(RootTarget(root=expanded, label=target.label, scan_all=target.scan_all))
        workspace = _workspace_root()
        if workspace and workspace.root not in {r.root for r in roots}:
            roots.append(workspace)
    elif scan_type == "whole":
        if profile.whole_from_drives:
            roots = [RootTarget(root=drive, label=drive) for drive in _list_drives()]
        else:
            for raw in profile.whole_roots:
                expanded = _expand(raw)
                if os.path.isdir(expanded):
                    roots.append(RootTarget(root=expanded, label=expanded))
    else:
        raw_target = (scan_job.target or "").strip()
        if raw_target and raw_target.lower() not in ("quick", "whole"):
            expanded = _expand(raw_target)
            if os.path.isdir(expanded):
                # An explicitly chosen target is scanned in full. The extension
                # filter exists to keep broad `quick`/`whole` sweeps tractable,
                # not to hide extension-less material (SSH keys, /etc/ssl files)
                # from someone who deliberately pointed discovery at it.
                roots.append(RootTarget(root=expanded, label=expanded, scan_all=True))

    return roots


def scan_type_of(scan_job) -> str:
    """Normalized scan scope for a ScanJob (quick/whole/specified)."""
    return _scan_type_of(scan_job)


def get_scan_limits(scan_job) -> ScopeLimits:
    """Merge per-scope defaults with per-job config overrides.

    Scopes are unbounded by default; an explicit ``max_files`` / ``max_depth``
    / ``max_file_size`` in ``ScanJob.config`` narrows a run on request.
    """
    default = SCOPE_LIMITS[_scan_type_of(scan_job)]
    config = scan_job.config or {}

    def limit(name: str) -> int | None:
        raw = config.get(name)
        if raw in (None, ""):
            return getattr(default, name)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise ValueError(
                f"Invalid {name} limit: {raw!r} is not an integer."
            ) from None
        return value if value > 0 else None

    return ScopeLimits(
        max_files=limit("max_files"),
        max_depth=limit("max_depth"),
        max_file_size=limit("max_file_size"),
    )


def prune_names_for(scan_job) -> frozenset[str]:
    """Directory names to skip while walking the given job's scope."""
    return GLOBAL_PRUNE_NAMES | _profile_for(scan_job).prune_names