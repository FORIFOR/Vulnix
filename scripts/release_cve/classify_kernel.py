"""Classify every open kernel CVE of the image (img-deb-result.json) by reachability on
THIS image, with evidence from img-facts.json (config, modules, sysctl) and the worker
sandbox (aegis/workers/_sandbox_launch.py planner profile). Output: kernel-assessed.json.

Classes (first that applies):
  NA_ARCH        code for another architecture (image is arm64)
  NA_NOT_BUILT   the subsystem/driver is not built into this kernel (CONFIG not y/m, no module)
  NA_USERSPACE   a userspace tool in the kernel tree (perf, selftests) not installed
  NR_NO_DEVICE   a hardware driver that is built as a module but not loaded; loaded only when
                 the device exists (none on this host); not loadable by an unprivileged user
  NR_PRIVILEGED  reachable only with root / CAP_SYS_ADMIN / CAP_NET_ADMIN / CAP_BPF / CAP_PERFMON
                 (no unprivileged user namespaces: kernel.unprivileged_userns_clone=0; workers
                 have no capabilities; bpf disabled for unprivileged users and denied by seccomp)
  NR_DISABLED    the feature is disabled by sysctl (io_uring_disabled=2)
  NR_FS_UNUSED   a filesystem not mounted; mounting needs root
  NR_PROTO_BLOCKED a protocol module that only an unprivileged socket() could autoload; the
                 image blocks its autoload (modprobe install /bin/false) and workers may only
                 create AF_INET/AF_INET6 sockets
  REACHABLE_LOCAL reachable by local unprivileged code (incl. the local-defense worker sandbox)
  REACHABLE_REMOTE reachable by packets from the network
  MANUAL         needs reading: assigned in MANUAL below with a written reason
"""
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# WORK: the directory with img-facts.json and img-deb-result.json; CACHE: the offline CVE cache
C = Path(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else Path.cwd()
CACHE = Path(os.environ.get("VULNIX_CVE_CACHE", "")) if os.environ.get("VULNIX_CVE_CACHE") else None
facts = json.load(open(C / "img-facts.json"))
cfg = facts["config"]
loaded = set(facts["modules_loaded"])
shipped = set(facts["modules_shipped"])
builtin = set(facts["modules_builtin"])
blocked = {l.split()[1] for l in facts.get("blocked_module_autoload", []) if l.startswith("install ") and "/bin/false" in l}
tracker = json.load(open(CACHE / "debian-tracker.json"))["linux"]
rows = [x for x in json.load(open(C / "img-deb-result.json")) if x["source"].startswith("linux")]

ARCH = re.compile(r"^(x86|KVM: x86|KVM: SVM|KVM: VMX|KVM: s390|KVM: PPC|KVM: LoongArch|KVM: riscv|powerpc|s390|riscv|"
                  r"LoongArch|mips|MIPS|sparc|parisc|m68k|um|ARM|arm\b|xtensa|alpha|sh|csky|openrisc|hexagon|"
                  r"iommu/vt-d|iommu/amd|platform/x86|x86/|bpf, s390|riscv, bpf|powerpc, perf|EDAC/altera)", re.I)


def built(*syms):
    return any(cfg.get(s) in ("y", "m") for s in syms)


# subsystem prefix -> (config symbols, kind) ; kind: hw | fs | proto | priv | core | user
SUB = [
    (r"^wifi\b|^mac80211|^cfg80211", ("CONFIG_CFG80211", "CONFIG_MAC80211"), "hw"),
    (r"^Bluetooth", ("CONFIG_BT",), "hw"),
    (r"^(smb/client|cifs|smb: client)", ("CONFIG_CIFS",), "fs"),
    (r"^(ksmbd|smb/server|smb: server)", ("CONFIG_SMB_SERVER",), "fs"),
    (r"^smb\b", ("CONFIG_CIFS", "CONFIG_SMB_SERVER"), "fs"),
    (r"^netfs", ("CONFIG_NETFS_SUPPORT",), "fs"),
    (r"^btrfs", ("CONFIG_BTRFS_FS",), "fs"),
    (r"^f2fs", ("CONFIG_F2FS_FS",), "fs"),
    (r"^ntfs", ("CONFIG_NTFS3_FS", "CONFIG_NTFS_FS"), "fs"),
    (r"^xfs", ("CONFIG_XFS_FS",), "fs"),
    (r"^erofs", ("CONFIG_EROFS_FS",), "fs"),
    (r"^nfsd", ("CONFIG_NFSD",), "fs"),
    (r"^(nfs|NFS)\b", ("CONFIG_NFS_FS",), "fs"),
    (r"^ext4", ("CONFIG_EXT4_FS",), "fs"),
    (r"^ocfs2", ("CONFIG_OCFS2_FS",), "fs"),
    (r"^gfs2", ("CONFIG_GFS2_FS",), "fs"),
    (r"^(hfs|hfsplus)", ("CONFIG_HFS_FS", "CONFIG_HFSPLUS_FS"), "fs"),
    (r"^jfs", ("CONFIG_JFS_FS",), "fs"),
    (r"^udf", ("CONFIG_UDF_FS",), "fs"),
    (r"^squashfs", ("CONFIG_SQUASHFS",), "fs"),
    (r"^exfat", ("CONFIG_EXFAT_FS",), "fs"),
    (r"^nilfs2", ("CONFIG_NILFS2_FS",), "fs"),
    (r"^ceph", ("CONFIG_CEPH_FS",), "fs"),
    (r"^fuse", ("CONFIG_FUSE_FS",), "fs"),
    (r"^KVM", ("CONFIG_KVM",), "priv"),
    (r"^drm/amdgpu|^drm/amd|^accel/amdxdna", ("CONFIG_DRM_AMDGPU", "CONFIG_DRM_ACCEL_AMDXDNA"), "hw"),
    (r"^drm/v3d", ("CONFIG_DRM_V3D",), "hw"),
    (r"^drm/panthor", ("CONFIG_DRM_PANTHOR",), "hw"),
    (r"^drm/xe", ("CONFIG_DRM_XE",), "hw"),
    (r"^drm/msm", ("CONFIG_DRM_MSM",), "hw"),
    (r"^drm/vkms", ("CONFIG_DRM_VKMS",), "hw"),
    (r"^drm/nouveau", ("CONFIG_DRM_NOUVEAU",), "hw"),
    (r"^drm/vc4", ("CONFIG_DRM_VC4",), "hw"),
    (r"^drm/i915", ("CONFIG_DRM_I915",), "hw"),
    (r"^drm\b", ("CONFIG_DRM",), "hw"),
    (r"^fbdev|^fbcon", ("CONFIG_FB",), "hw"),
    (r"^(ALSA|ASoC)", ("CONFIG_SND",), "hw"),
    (r"^media", ("CONFIG_MEDIA_SUPPORT",), "hw"),
    (r"^RDMA", ("CONFIG_INFINIBAND",), "hw"),
    (r"^mptcp", ("CONFIG_MPTCP",), "proto"),
    (r"^sctp", ("CONFIG_IP_SCTP",), "proto"),
    (r"^rxrpc", ("CONFIG_AF_RXRPC",), "proto"),
    (r"^xsk", ("CONFIG_XDP_SOCKETS",), "priv"),
    (r"^vsock", ("CONFIG_VSOCKETS",), "proto"),
    (r"^8021q", ("CONFIG_VLAN_8021Q",), "priv"),
    (r"^macsec", ("CONFIG_MACSEC",), "priv"),
    (r"^bonding", ("CONFIG_BONDING",), "priv"),
    (r"^seg6", ("CONFIG_IPV6_SEG6_LWTUNNEL",), "priv"),
    (r"^ipmi", ("CONFIG_IPMI_HANDLER",), "hw"),
    (r"^i3c", ("CONFIG_I3C",), "hw"),
    (r"^cxl", ("CONFIG_CXL_BUS",), "hw"),
    (r"^mtd", ("CONFIG_MTD",), "hw"),
    (r"^tpm", ("CONFIG_TCG_TPM",), "hw"),
    (r"^iio", ("CONFIG_IIO",), "hw"),
    (r"^hwmon", ("CONFIG_HWMON",), "hw"),
    (r"^coresight", ("CONFIG_CORESIGHT",), "hw"),
    (r"^gve", ("CONFIG_GVE",), "hw"),
    (r"^iavf", ("CONFIG_IAVF",), "hw"),
    (r"^eth\b", ("CONFIG_ETHERNET",), "hw"),
    (r"^nvme", ("CONFIG_NVME_CORE",), "hw"),
    (r"^scsi", ("CONFIG_SCSI",), "hw"),
    (r"^md\b", ("CONFIG_MD",), "priv"),
    (r"^dmaengine", ("CONFIG_DMADEVICES",), "hw"),
    (r"^iommu/sva", ("CONFIG_IOMMU_SVA",), "hw"),
    (r"^gpio", ("CONFIG_GPIOLIB",), "hw"),
    (r"^phy\b", ("CONFIG_GENERIC_PHY",), "hw"),
    (r"^cpufreq", ("CONFIG_CPU_FREQ",), "priv"),
    (r"^irqchip/gic-v5", ("CONFIG_ARM_GIC_V5",), "hw"),
    (r"^serial", ("CONFIG_SERIAL_CORE",), "hw"),
    (r"^vt\b", ("CONFIG_VT",), "hw"),
    (r"^fs/resctrl", ("CONFIG_RESCTRL_FS",), "priv"),
    (r"^sched_ext", ("CONFIG_SCHED_CLASS_EXT",), "priv"),
    (r"^PCI", ("CONFIG_PCI",), "priv"),
    (r"^power\b", ("CONFIG_PM",), "hw"),
    (r"^firmware", ("CONFIG_FW_LOADER",), "hw"),
    (r"^(bpf|BPF)\b", ("CONFIG_BPF_SYSCALL",), "bpf"),
    (r"^io_uring", ("CONFIG_IO_URING",), "io_uring"),
    (r"^netfilter|^net/sched|^rtnetlink|^netlink|^drop_monitor|^neighbour|^xfrm", (), "priv"),
    (r"^perf tools|^selftests", (), "user"),
    (r"^perf/core|^perf\b", ("CONFIG_PERF_EVENTS",), "perf"),
]

# module names that implement a subsystem (to tell "built as a module, not loaded")
MOD = {"CONFIG_CFG80211": "cfg80211", "CONFIG_BT": "bluetooth", "CONFIG_CIFS": "cifs", "CONFIG_SMB_SERVER": "ksmbd",
       "CONFIG_NETFS_SUPPORT": "netfs", "CONFIG_BTRFS_FS": "btrfs", "CONFIG_F2FS_FS": "f2fs", "CONFIG_NTFS3_FS": "ntfs3",
       "CONFIG_XFS_FS": "xfs", "CONFIG_EROFS_FS": "erofs", "CONFIG_NFSD": "nfsd", "CONFIG_NFS_FS": "nfs",
       "CONFIG_KVM": "kvm", "CONFIG_DRM_AMDGPU": "amdgpu", "CONFIG_DRM_V3D": "v3d", "CONFIG_DRM_PANTHOR": "panthor",
       "CONFIG_DRM_XE": "xe", "CONFIG_DRM_MSM": "msm", "CONFIG_DRM_VKMS": "vkms", "CONFIG_DRM_NOUVEAU": "nouveau",
       "CONFIG_DRM_VC4": "vc4", "CONFIG_DRM": "drm", "CONFIG_FB": "fb", "CONFIG_SND": "snd",
       "CONFIG_MEDIA_SUPPORT": "mc", "CONFIG_INFINIBAND": "ib_core", "CONFIG_MPTCP": "mptcp", "CONFIG_IP_SCTP": "sctp",
       "CONFIG_AF_RXRPC": "rxrpc", "CONFIG_VSOCKETS": "vsock", "CONFIG_VLAN_8021Q": "8021q", "CONFIG_MACSEC": "macsec",
       "CONFIG_BONDING": "bonding", "CONFIG_IPMI_HANDLER": "ipmi_msghandler", "CONFIG_GVE": "gve", "CONFIG_IAVF": "iavf",
       "CONFIG_FUSE_FS": "fuse", "CONFIG_SQUASHFS": "squashfs", "CONFIG_UDF_FS": "udf", "CONFIG_EXFAT_FS": "exfat"}

# read one by one (description + the image's facts); class and reason
MANUAL = json.load(open(HERE / "kernel-manual.json"))


def first_line(desc):
    m = re.search(r"resolved:\s*(.+)", desc, re.S)
    return m.group(1).strip().split("\n")[0] if m else ""


def classify(cve, desc, urgency):
    if cve in MANUAL:
        return MANUAL[cve]["class"], MANUAL[cve]["reason"]
    head = first_line(desc)
    if not head:
        return "MANUAL", "pre-2024 description without a subsystem line"
    if ARCH.match(head):
        return "NA_ARCH", f"{head.split(':')[0]}: not arm64 code"
    for pat, syms, kind in SUB:
        if not re.match(pat, head):
            continue
        if kind == "user":
            return "NA_USERSPACE", "userspace tool from the kernel tree; not installed on the image"
        if syms and not built(*syms):
            return "NA_NOT_BUILT", f"{'/'.join(syms)} not set in /boot/config-{facts['kernel']}"
        mod = next((MOD[s] for s in syms if s in MOD and cfg.get(s) == "m"), None)
        if kind == "hw":
            if mod and mod not in loaded:
                return "NR_NO_DEVICE", f"module {mod} built but not loaded; no such device on this host"
            if mod is None and not any(cfg.get(s) == "y" for s in syms):
                return "NR_NO_DEVICE", "driver not loaded; no such device on this host"
            return "MANUAL", f"hardware subsystem built in or loaded ({','.join(syms)})"
        if kind == "fs":
            if mod and mod not in loaded:
                return "NR_FS_UNUSED", f"filesystem module {mod} not loaded, not mounted; mounting needs root (no unprivileged user namespaces)"
            return "MANUAL", "filesystem built in or loaded"
        if kind == "bpf":
            return "NR_PRIVILEGED", "bpf(2) needs CAP_BPF/CAP_SYS_ADMIN: kernel.unprivileged_bpf_disabled=2, no capabilities in workers, bpf denied by the worker seccomp profile"
        if kind == "io_uring":
            return "NR_DISABLED", "kernel.io_uring_disabled=2 (io_uring_setup fails for everyone); also denied by the worker seccomp filter"
        if kind == "perf":
            return "NR_PRIVILEGED", "perf_event_open denied by the worker seccomp profile; kernel.perf_event_paranoid (Debian 3) refuses unprivileged users"
        if kind == "priv":
            return "NR_PRIVILEGED", "configuring it needs CAP_NET_ADMIN/CAP_SYS_ADMIN in the initial namespace (no unprivileged user namespaces, workers have no capabilities)"
        if kind == "proto":
            if mod and mod in blocked:
                return "NR_PROTO_BLOCKED", f"module {mod} autoload blocked (install {mod} /bin/false); not loaded"
            if mod and mod not in loaded:
                return "MANUAL", f"protocol module {mod} not loaded but autoloadable by socket()"
            return "MANUAL", "protocol built in or loaded"
    return "MANUAL", f"core subsystem: {head[:80]}"


out = []
for x in rows:
    t = tracker.get(x["cve"], {})
    desc = t.get("description", "")
    cls, reason = classify(x["cve"], desc, x.get("urgency"))
    out.append({"cve": x["cve"], "package": "linux", "installed": x["installed"], "urgency": x.get("urgency"),
                "class": cls, "reason": reason, "summary": first_line(desc)[:140] or desc[:140]})
json.dump(out, open(C / "kernel-assessed.json", "w"), indent=1, ensure_ascii=False)
import collections
print(collections.Counter(r["class"] for r in out))
if "-v" in sys.argv:
    for r in out:
        if r["class"] == "MANUAL":
            print(r["cve"], "|", r["urgency"], "|", r["reason"][:60], "|", r["summary"][:150])
