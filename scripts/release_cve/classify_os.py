"""Every open Debian CVE of the image's packages (not the kernel), with a class and a
reason. Evidence: img-facts.json (what running processes map, setuid files, listeners),
the backend's code (which stdlib modules / OS commands it uses), sshd -T on the image.
Output: os-assessed.json. Exit 1 if any entry has no class."""
import collections
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# WORK: the directory with img-facts.json and img-deb-result.json; CACHE: the offline CVE cache
C = Path(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else Path.cwd()
CACHE = Path(os.environ.get("VULNIX_CVE_CACHE", "")) if os.environ.get("VULNIX_CVE_CACHE") else None
rows = [x for x in json.load(open(C / "img-deb-result.json")) if not x["source"].startswith("linux")]
tracker = json.load(open(CACHE / "debian-tracker.json"))

UNUSED = ("NOT_USED", "installed but not used: no running service maps it (/proc/*/maps scan), Vulnix never "
          "executes it; only an administrator's own command would reach it")
BOOT = ("BOOT_ONLY", "used only by cloud-init at boot, on the platform's own metadata; never loaded by Vulnix "
        "(the backend uses its own vendored packages)")
BOOTCHAIN = ("NR_PRIVILEGED", "boot chain / initramfs tooling: runs as root at boot or package installation, on root-owned input")

PKG = {
    # boot-time / cloud-init chain
    "pyjwt": BOOT, "python-oauthlib": BOOT, "python-cryptography": BOOT, "python-urllib3": BOOT,
    "requests": BOOT, "jinja2": BOOT, "configobj": BOOT, "libyaml": BOOT,
    "grub2": BOOTCHAIN, "shim": BOOTCHAIN, "efivar": BOOTCHAIN, "dracut": BOOTCHAIN, "initramfs-tools": BOOTCHAIN,
    "cpio": BOOTCHAIN, "lvm2": BOOTCHAIN,
    # administrator tools only
    "coreutils": UNUSED, "diffutils": UNUSED, "perl": UNUSED, "attr": UNUSED, "nano": UNUSED, "ncurses": UNUSED,
    "slang2": UNUSED, "popt": UNUSED, "libpng1.6": UNUSED, "bash-completion": UNUSED, "bash": UNUSED, "dpkg": UNUSED,
    "sysvinit": UNUSED, "elfutils": ("NOT_USED", "libelf/libdw: linked by iproute2/libbpf for BPF object loading (root); the readelf/eu-* tools are not installed"),
    "bzip2": ("NOT_USED", "affects the bzip2recover tool, which nothing runs"),
    "libtirpc": ("NOT_USED", "SunRPC server transports: no RPC service runs (no rpcbind/NFS); iproute2 links the library only"),
    "p11-kit": ("NOT_USED", "p11-kit RPC server is not running; nothing uses PKCS#11 modules"),
    "iptables": ("NOT_USED", "iptables is removed; libxtables remains for iproute2/nftables, the --syn match is an iptables rule feature"),
    "apt": ("MITIGATED", "apt-key is not used; repositories use signed-by keyrings"),
    "python-apt": ("MITIGATED", "used by unattended-upgrades on Debian's signed repository metadata"),
    "glib2.0": ("NOT_USED", "GLib is loaded by boot/network tooling (netplan, python3-dbus); no service passes it untrusted input"),
    "libseccomp": ("MITIGATED", "Debian placeholder entries without description (fixed upstream in 2.6.1); Vulnix builds its worker seccomp filter itself (verified by the probe); libseccomp only compiles the systemd unit filters, which are defense in depth"),
    "acl": ("MITIGATED", "path-based ACL functions on attacker-writable paths: Vulnix sets no ACLs; systemd-tmpfiles works on root-owned paths; fs.protected_symlinks=1"),
    "shadow": ("MITIGATED", "setuid passwd/chsh/chfn are reachable only by local accounts: services run nologin accounts, workers have no_new_privs (setuid ignored)"),
    "gcc-14": ("UNCONFIRMED", "libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts)"),
    "sqlite3": ("MITIGATED", "the backend opens only its own database files (0700 data directory) with fixed, parameterised SQL; FTS3/4/5, R-Tree, session and zipfile extensions and the sqlite3 shell (not installed) are not used"),
    "expat": ("MITIGATED", "dbus-daemon parses only root-owned configuration; the backend never parses XML (it only builds it with ElementTree.tostring); xmlwf is not installed"),
    "tar": ("MITIGATED", "used only by backup.sh/restore.sh as root on an archive written by backup.sh (0600, sha256 checked before extraction)"),
    "dash": ("MITIGATED", "the shell scripts run as root (provision, backup/restore, the broker's mount script) are fixed; patterns and printf arguments are not attacker-controlled"),
    "krb5": ("CONFIG_OFF", "Kerberos is only linked by sshd: GSSAPIAuthentication no (sshd -T); no KDC or kadmin installed"),
    "pam": ("NOT_USED", "pam_namespace / pam_userdb are not configured in /etc/pam.d"),
    "sudo": ("MITIGATED", "visudo is run by root on a root-owned path (fs.protected_symlinks=1); intercept mode is not configured; sudoers grants the service user only the broker"),
    "util-linux": ("NOT_USED", "the affected tools/options (chfn/chsh with readline, login -h, user mounts from fstab, nsenter --join-cgroup, X-mount.subdir) are not used: no 'user' entries in /etc/fstab, Vulnix uses unshare/setpriv only"),
    "systemd": ("NOT_USED", "journal sealing (FSS), systemd-oomd and systemd-homed are not used/installed; tmpfiles symlink issue mitigated by fs.protected_symlinks=1"),
    "dbus": ("REACHABLE_LOCAL", "local system-bus DoS by a local account: workers cannot create AF_UNIX sockets (seccomp); the service accounts can"),
    "glibc": ("NOT_USED", "the affected functions (POSIX regex, glob, wide scanf, iconv CP949/ISO-2022-CN-EXT/IBM1390, gettext LANGUAGE) get no attacker input on this host: Python uses its own re/glob/codecs, no service converts with those charsets"),
    "openssl": ("NOT_USED", "QUIC, DTLS, CMS/PKCS#7, DANE, Suite B, AES-GCM-SIV and EVP_EncodeBlock with ~INT_MAX input are not used by the Python ssl module or sshd here"),
}

O = {
    # openssh (sshd -T: password/kbd-interactive/GSSAPI auth off, no tunnel/agent/X11, compression off)
    **{c: ("CONFIG_OFF", "GSSAPIAuthentication no (sshd -T)") for c in (
        "CVE-2018-15919", "CVE-2026-106553", "CVE-2026-106555", "CVE-2026-55654", "CVE-2026-59998", "CVE-2026-60000")},
    **{c: ("CONFIG_OFF", "keyboard-interactive / challenge-response authentication off (sshd -T)") for c in ("CVE-2007-2243", "CVE-2007-2768")},
    **{c: ("CONFIG_OFF", "Compression no (sshd -T)") for c in ("CVE-2026-106582", "CVE-2026-106585")},
    **{c: ("CONFIG_OFF", "PermitTunnel no (sshd -T)") for c in ("CVE-2026-106586", "CVE-2026-59999", "CVE-2026-73283")},
    "CVE-2026-73281": ("CONFIG_OFF", "ssh-agent does not run on the server; AllowAgentForwarding no"),
    **{c: ("NOT_USED", "OpenSSH client-side (ssh/scp/sftp/ssh-keygen); the server never runs the client") for c in (
        "CVE-2019-6110", "CVE-2020-14145", "CVE-2020-15778", "CVE-2026-106552", "CVE-2026-106583", "CVE-2026-106584",
        "CVE-2026-59995", "CVE-2026-59996", "CVE-2026-60002", "CVE-2026-73282")},
    "CVE-2008-3234": ("NOT_USED", "SELinux roles: SELinux is not enabled"),
    "CVE-2016-20012": ("REACHABLE_REMOTE", "lets a remote party confirm a guessed username+public key pair (upstream: by design); keys are not secret; information only"),
    "CVE-2026-106587": ("MITIGATED", "the configuration is root-owned and uses no affected 'none' values (sshd -T reviewed)"),
    "CVE-2026-123158": ("NOT_USED", "only musl builds without PAM; Debian's sshd uses glibc and PAM, and password authentication is off"),
    "CVE-2026-59997": ("NOT_USED", "internal-sftp is not configured (Subsystem sftp /usr/lib/openssh/sftp-server, no ForceCommand)"),
    "CVE-2026-60001": ("MITIGATED", "the minimum delay protects password guessing; password authentication is off"),
    # python3.13 - the backend runtime (module use checked in aegis/)
    **{c: ("NOT_USED", "the backend does not use this module (no import in aegis/)") for c in (
        "CVE-2025-15366", "CVE-2025-15367", "CVE-2026-114583", "CVE-2026-115559", "CVE-2026-115791", "CVE-2026-124249",
        "CVE-2026-15310", "CVE-2026-18503", "CVE-2026-19445", "CVE-2026-19552", "CVE-2026-19553", "CVE-2026-19672",
        "CVE-2026-82049", "CVE-2026-87910", "CVE-2026-15806", "CVE-2026-7210")},
    "CVE-2025-12781": ("MITIGATED", "base64 accepts '+/' with urlsafe decoding: tokens are verified by HMAC over the received text, alternative encodings gain nothing"),
    "CVE-2026-103995": ("REACHABLE_REMOTE", "http.client chunk-size parsing: a hostile probed site could make a probe misread its own response body (integrity of that site's result only; probe results are untrusted data)"),
    "CVE-2026-115557": ("MITIGATED", "the denylist adds nothing beyond Debian's CA store for the backend's outbound TLS (catalog sync, ownership checks)"),
    "CVE-2026-116566": ("MITIGATED", "a diagnosis target host must equal a registered in-scope host (aegis/network.py), and every resolved address is checked against the scope CIDRs: a truncated name cannot leave the scope"),
    "CVE-2026-12003": ("NOT_USED", "in-tree build layout only"),
    "CVE-2026-12345": ("MITIGATED", "temporary directories are the service's own 0700 mkdtemp directories; a worker's processes are killed (cgroup empty) before its directory is removed"),
    "CVE-2026-15308": ("REACHABLE_REMOTE", "html.parser CPU DoS: the ownership check parses HTML fetched from the site being verified, at most 64 KiB (aegis/ownership.py); one request thread at most"),
    "CVE-2026-16052": ("MITIGATED", "the backend builds its Set-Cookie header itself; Morsel output is not used with attacker values"),
    "CVE-2026-17084": ("MITIGATED", "IDNA/stringprep only for non-ASCII hostnames, which the backend's host validation rejects"),
    "CVE-2026-3479": ("NOT_USED", "disputed (documentation); pkgutil.get_data not used on untrusted paths"),
    # openssl - the one used path
    "CVE-2026-107493": ("MITIGATED", "PEM_X509_INFO_read_bio_ex reads the root-owned CA bundle only"),
    # glibc
    **{c: ("NOT_USED", "disputed mitigation-bypass claims (upstream: not vulnerabilities)") for c in (
        "CVE-2019-1010022", "CVE-2019-1010023", "CVE-2019-1010024", "CVE-2019-1010025")},
    "CVE-2026-84243": ("MITIGATED", "needs control of a non-setuid program's environment (then the attacker already runs it); setuid programs ignore LANGUAGE"),
    # util-linux / systemd / sudo specifics are covered by the package default
    # dbus specifics
    "CVE-2026-120749": ("NR_PRIVILEGED", "needs a privileged monitoring client (root) attached"),
    "CVE-2026-128885": ("NOT_USED", "dbus-daemon uses epoll on Linux, not select()"),
    "CVE-2026-128886": ("NOT_USED", "nonce-tcp transport is not configured"),
    # shadow
    "CVE-2024-56433": ("MITIGATED", "subuid ranges matter only for user namespaces (unprivileged ones are off); worker uids are 3,000,000,000+"),
    "CVE-2007-5686": ("NOT_USED", "rPath initscripts"),
    # tar specifics
    "CVE-2005-2541": ("MITIGATED", "restore extracts Vulnix's own data directory (no setuid files) as root from a verified archive"),
    # cloud-init chain specifics stay BOOT_ONLY
}


def classify(x):
    if x["cve"] in O:
        return O[x["cve"]]
    if x["source"] in PKG:
        return PKG[x["source"]]
    return ("UNCLASSIFIED", "")


out = []
for x in rows:
    cls, reason = classify(x)
    desc = (tracker.get(x["source"], {}).get(x["cve"], {}).get("description") or "").replace("\n", " ")
    out.append({"cve": x["cve"], "package": x["source"], "installed": x["installed"], "urgency": x.get("urgency"),
                "kev": x.get("kev", False), "class": cls, "reason": reason, "summary": desc[:140]})
json.dump(out, open(C / "os-assessed.json", "w"), indent=1, ensure_ascii=False)
cnt = collections.Counter(r["class"] for r in out)
print(len(out), cnt)
missing = [r for r in out if r["class"] == "UNCLASSIFIED"]
for r in missing:
    print("UNCLASSIFIED", r["package"], r["cve"], r["summary"][:100])
sys.exit(1 if missing else 0)
