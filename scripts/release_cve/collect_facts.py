"""Run as root on the image. Facts for the residual-CVE assessment (no secrets: names,
paths and versions only). Prints JSON."""
import glob
import json
import os
import platform
import re
import subprocess


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout


rel = platform.release()
facts = {"kernel": rel, "arch": platform.machine()}
facts["sysctl"] = {k: sh("sysctl", "-n", k).strip() for k in (
    "kernel.unprivileged_userns_clone", "kernel.io_uring_disabled", "kernel.unprivileged_bpf_disabled",
    "user.max_user_namespaces", "kernel.kptr_restrict", "kernel.dmesg_restrict", "net.core.bpf_jit_harden",
    "kernel.yama.ptrace_scope", "fs.protected_symlinks")}
cfg = {}
for line in open(f"/boot/config-{rel}"):
    m = re.match(r"(CONFIG_[A-Z0-9_]+)=(.+)", line)
    if m:
        cfg[m.group(1)] = m.group(2)
facts["config"] = cfg
mods = {}
for p in glob.glob(f"/lib/modules/{rel}/**/*.ko*", recursive=True):
    mods[re.sub(r"\.ko(\.[a-z]+)?$", "", os.path.basename(p)).replace("-", "_")] = p.split(f"/lib/modules/{rel}/")[1]
facts["modules_shipped"] = mods
facts["modules_builtin"] = sorted(re.sub(r"\.ko$", "", os.path.basename(l.strip())).replace("-", "_")
                                  for l in open(f"/lib/modules/{rel}/modules.builtin"))
facts["modules_loaded"] = sorted(l.split()[0] for l in open("/proc/modules"))
facts["filesystems_mounted"] = sorted(set(sh("findmnt", "-rn", "-o", "FSTYPE").split()))
facts["listeners"] = sh("ss", "-lntupH").splitlines()
facts["blocked_module_autoload"] = sh("sh", "-c", "cat /etc/modprobe.d/*.conf 2>/dev/null | grep -E '^(install|blacklist)'").splitlines()

# package of every file mapped or executed by a running process
files = set()
procs = {}
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        comm = open(f"/proc/{pid}/comm").read().strip()
    except OSError:
        continue
    procs.setdefault(comm, exe)
    files.add(exe)
    try:
        for line in open(f"/proc/{pid}/maps"):
            parts = line.split()
            if len(parts) >= 6 and parts[5].startswith("/"):
                files.add(parts[5])
    except OSError:
        pass
facts["processes"] = procs
owner = {}
for f in sorted(files):
    out = sh("dpkg", "-S", os.path.realpath(f)) or sh("dpkg", "-S", f)
    if out:
        owner[f] = out.split(":")[0].split(",")[0].strip()
src = {}
for line in sh("dpkg-query", "-W", "-f=${binary:Package}\t${source:Package}\t${Version}\n").splitlines():
    b, s, v = line.split("\t")
    src[b.split(":")[0]] = s or b
facts["binary_to_source"] = src
facts["in_use_binary_packages"] = sorted(set(owner.values()))
facts["in_use_source_packages"] = sorted({src.get(b.split(":")[0], b) for b in owner.values()})
facts["in_use_files"] = {f: owner[f] for f in owner if not f.startswith("/opt/")}
suid = sh("find", "/", "-xdev", "-perm", "-4000", "-type", "f").split()
facts["setuid"] = {f: (sh("dpkg", "-S", f).split(":")[0] or "?") for f in suid}
facts["vulnix_python_modules"] = sh("sh", "-c", "for p in $(pgrep -f 'aegis.server'); do grep -o '/usr/lib/python3[^ ]*\\.so[^ ]*' /proc/$p/maps; done | sort -u").split()
print(json.dumps(facts))
