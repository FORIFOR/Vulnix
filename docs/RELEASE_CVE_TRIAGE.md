# 残存 CVE の全件評価（2026-11-29）

最終候補の Debian 13 イメージ（`deploy/debian13`）と配布物について、照合で残った CVE を**すべて**分類した。1 件ずつの分類と理由は [`release-cve-residual-2026-11-29.json`](release-cve-residual-2026-11-29.json)。未分類は 0 件（分類スクリプトは未分類があると失敗する）。

- **入力:** CVE キャッシュ（2026-11-28 取得。OSV・Debian セキュリティトラッカー・CISA KEV）。外部への送信なし。
- **対象:** カーネル `6.12.118+deb13-cloud-arm64`（arm64）、イメージの Debian パッケージ、Web の SBOM（npm）、バックエンド同梱の Python パッケージ。
- **根拠（イメージ上で収集）:** カーネル設定とモジュール（同梱・読み込み済み）、sysctl、実行中プロセスが読み込むファイル（`/proc/*/maps` → パッケージ）、待ち受けポート、setuid ファイル、`sshd -T`、Worker の seccomp。バックエンドが使う標準ライブラリと外部コマンドはソースで確認した。
- **再現:** `scripts/release_cve/`（`collect_facts.py` をイメージ上で root 実行 → `match_debian.py` → `VULNIX_CVE_CACHE=<cache> classify_kernel.py <work>` / `classify_os.py <work>`）。

## この評価で行ったイメージの変更

- 使わないパッケージを削除: curl（libcurl）、wget、tcpdump、screen、vim、polkit、iptables、ping、man-db、bind9-host と依存ライブラリ（libxml2・lmdb など）。OS の残存 CVE は 364 件 → 251 件。
- 一般ユーザーが socket() だけで読み込めるプロトコルモジュール（sctp、dccp、tipc、rds、smc、l2tp、af_key、kcm、AF_ALG）の自動読み込みを禁止（`90-vulnix-modules.conf`。イメージ上で socket() が失敗することを確認）。
- MPTCP を無効化（`net.mptcp.enabled=0`）。sshd の圧縮を無効化（`Compression no`）。

## 分類の件数

| 区分 | 件数 | 内訳 |
|---|---|---|
| カーネル | 339 | NA_NOT_BUILT 99、NR_PRIVILEGED 76、NR_FS_UNUSED 44、NR_NO_DEVICE 40、NA_ARCH 29、MITIGATED 20、REACHABLE_LOCAL 13、NR_DISABLED 11、REACHABLE_REMOTE 4、NR_PROTO_BLOCKED 2、NA_USERSPACE 1 |
| OS パッケージ | 251 | NOT_USED 115、MITIGATED 57、BOOT_ONLY 33、CONFIG_OFF 19、NR_PRIVILEGED 15、UNCONFIRMED 7、REACHABLE_REMOTE 3、REACHABLE_LOCAL 2 |
| Web（npm） | 16 | NOT_REACHABLE 10、MITIGATED 4、NOT_USED 2 |
| バックエンド（PyPI、同梱 11 パッケージ） | 0 | OSV 照合で該当なし（certifi、cffi、charset-normalizer、cryptography 50.0.2、google-auth、idna、pyasn1、pyasn1_modules、pycparser、requests 2.34.2、urllib3 2.8.0）。照合器が古い版（requests 2.31.0・cryptography 41.0.0）で 26 件を検出することも確認 |

分類の意味: `NA_*` 該当コードがない（別アーキテクチャ・未ビルド・未使用）、`NR_*` このイメージでは届かない（root 権限が必要・機器がない・機能が無効・未マウント・自動読み込み禁止）、`CONFIG_OFF` 設定で無効、`NOT_USED` 使われていない、`BOOT_ONLY` 起動時の cloud-init だけ、`MITIGATED` 届きうるがこの構成では影響が成立しない（理由を記載）、`REACHABLE_*` 届く（残存リスク）、`UNCONFIRMED` 届くかどうか確認できていない（**未確認**）。

## 届く・未確認のもの（残存リスク）

| 区分 | CVE | パッケージ | 分類 | 理由 |
|---|---|---|---|---|
| カーネル | CVE-2004-0230 | linux | REACHABLE_REMOTE | TCP blind RST injection (protocol-level, all TCP stacks); RFC 5961 challenge ACKs in Linux make it impractical; availability of an SSH session at most |
| カーネル | CVE-2008-4609 | linux | REACHABLE_REMOTE | TCP connection-queue exhaustion (sockstress), generic to TCP; SSH is the only external listener; SYN cookies on by default; availability only |
| カーネル | CVE-2021-3864 | linux | REACHABLE_LOCAL | needs a setuid program that sets ruid=euid and runs attacker-chosen code; workers and the web server run with no_new_privs (setuid ignored); the backend user can run setuid sudo (only the broker allowed) |
| カーネル | CVE-2024-2193 | linux | REACHABLE_LOCAL | GhostRace (speculative race, Spectre-v1 class): local code on the same CPU; mitigation depends on the kernel/CPU vendor; Debian has no fix yet |
| カーネル | CVE-2025-40217 | linux | REACHABLE_LOCAL | pidfs ioctls on a process's own pidfds: hardening of argument validation; no known exploit |
| カーネル | CVE-2026-46017 | linux | REACHABLE_LOCAL | mm: deferred-split queue race during page migration; reachable by local code that triggers migration of its own pages (single NUMA node; no compaction triggers from workers beyond normal allocation) |
| カーネル | CVE-2026-52994 | linux | REACHABLE_LOCAL | vsock MSG_ZEROCOPY accounting: AF_VSOCK exists for Lima's guest agent; workers cannot create it (seccomp: AF_INET/AF_INET6 only); service users can. Production hosts without vsock: not present |
| カーネル | CVE-2026-98284 | linux | REACHABLE_LOCAL | netlink multicast-group realloc race: an unprivileged netlink socket can join groups; sandboxed workers cannot create netlink sockets (seccomp, verified by the probe); service users can |
| カーネル | CVE-2026-98289 | linux | REACHABLE_LOCAL | af_unix garbage collector: workers cannot create AF_UNIX sockets (seccomp); service users can |
| カーネル | CVE-2026-98393 | linux | REACHABLE_LOCAL | UDP length overflow with PMTU discovery and a 64 KiB MTU (lo): triggers a kernel WARN only (panic_on_warn=0) |
| カーネル | CVE-2026-98427 | linux | REACHABLE_REMOTE | CoDel drop loop per dequeue: the CoDel control law is shared by fq_codel, the default qdisc on eth0; traffic can lengthen the loop (CPU, availability only) |
| カーネル | CVE-2026-99643 | linux | REACHABLE_LOCAL | khugepaged lock inversion with file readahead (deadlock, DoS); anonymous THP is enabled ('always') |
| カーネル | CVE-2026-99646 | linux | REACHABLE_LOCAL | MAP_GROWSDOWN stack-growth commit-charge leak (accounting DoS) by local code |
| カーネル | CVE-2026-99652 | linux | REACHABLE_LOCAL | userfaultfd UFFDIO_MOVE vs mremap deadlock: workers cannot call userfaultfd (seccomp), /dev/userfaultfd is root-only; service users may use the syscall (user-mode faults only, vm.unprivileged_userfaultfd=0) |
| カーネル | CVE-2026-99660 | linux | REACHABLE_LOCAL | userfaultfd unregister race: same reachability as CVE-2026-99652 |
| カーネル | CVE-2026-99669 | linux | REACHABLE_LOCAL | truncate racing with PMD zap on THP: anonymous THP enabled; local data-integrity race |
| カーネル | CVE-2026-99709 | linux | REACHABLE_REMOTE | IP fragment reassembly memory is bounded only by ipfrag_high_thresh (4 MiB here) per netns: a remote sender can make the host hold that memory (DoS); fragments are reassembled before the host firewall |
| OS | CVE-2026-128987 | dbus | REACHABLE_LOCAL | local system-bus DoS by a local account: workers cannot create AF_UNIX sockets (seccomp); the service accounts can |
| OS | TEMP-1153844-83400A | dbus | REACHABLE_LOCAL | local system-bus DoS by a local account: workers cannot create AF_UNIX sockets (seccomp); the service accounts can |
| OS | CVE-2026-102010 | gcc-14 | UNCONFIRMED | libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts) |
| OS | CVE-2026-114690 | gcc-14 | UNCONFIRMED | libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts) |
| OS | CVE-2026-114691 | gcc-14 | UNCONFIRMED | libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts) |
| OS | CVE-2026-115455 | gcc-14 | UNCONFIRMED | libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts) |
| OS | CVE-2026-115456 | gcc-14 | UNCONFIRMED | libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts) |
| OS | CVE-2026-125709 | gcc-14 | UNCONFIRMED | libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts) |
| OS | CVE-2026-95619 | gcc-14 | UNCONFIRMED | libstdc++ is linked by the Node.js web server; reachable only if Node calls the affected API with external input - not confirmed (impact: crash/DoS, the unit restarts) |
| OS | CVE-2016-20012 | openssh | REACHABLE_REMOTE | lets a remote party confirm a guessed username+public key pair (upstream: by design); keys are not secret; information only |
| OS | CVE-2026-103995 | python3.13 | REACHABLE_REMOTE | http.client chunk-size parsing: a hostile probed site could make a probe misread its own response body (integrity of that site's result only; probe results are untrusted data) |
| OS | CVE-2026-15308 | python3.13 | REACHABLE_REMOTE | html.parser CPU DoS: the ownership check parses HTML fetched from the site being verified, at most 64 KiB (aegis/ownership.py); one request thread at most |

KEV（悪用が確認された脆弱性）に載る 1 件（OpenSSH CVE-2026-123158）は、musl かつ PAM なしの構成だけが対象で、Debian（glibc・PAM、パスワード認証は無効）は該当しない。

---

<!-- Copied from the offline triage of 2026-11-28. It applies unchanged to 569ca3e: web/ is
     identical to 958b600 (git diff 958b600 569ca3e -- web is empty) and the SBOM gives the
     same OSV result. The deployment image (deploy/debian13) has since set
     kernel.unprivileged_userns_clone=0 and kernel.io_uring_disabled=2, removed the old kernel,
     curl and qemu-utils, and hardened sshd (sshd -T: password, keyboard-interactive and
     GSSAPI authentication off, root login off, X11 and agent forwarding off, tunnels off;
     TCP forwarding kept for the administrator's tunnel). -->
# Vulnix 958b600 残存 CVE トリアージ（2026-11-28、オフライン）

- 入力: CVE キャッシュ（2026-11-28 取得）、`osv-958b600.json`、`deb-result.json`（trixie）、Web アーティファクト（展開先 `$S/webx`）、ソース（HEAD 1f4bb5b。958b600 からの差分は docs 1 ファイルだけ）。
- 判定の根拠: 静的な確認（ファイルの有無、呼び出し元、設定値）と、Node 26 で行ったモジュール読み込み確認（`$S/tools/loadgraph.js`。サーバー 4 モジュールを require し、読み込まれたファイルを記録）。本番の Node 22 と VM での実稼働は確かめていない（**未確認**）。
- 秘密値は表示も複製もしていない。設定は `required-server-files.json` の該当キーだけを読んだ。

## 1. Web アーティファクトの High 10 件

確認した設定（展開後のアーティファクト）: `compress:false`、`images.unoptimized:true`、`loader:default`、`remotePatterns:[]`、`output:standalone`。`compiled/ws`、`sharp`、`@img` は同梱されていない。

| CVE | パッケージ | 該当コードの有無（同梱ファイル） | 前回の緩和策は今も有効か | HTTP 入力から届くか | 判定 |
|---|---|---|---|---|---|
| CVE-2026-87776 | compression 1.7.4 | あり `next/dist/compiled/compression`。読み込みは起動時 | 有効。`router-server.js:143` は `config.compress !== false` のときだけミドルウェアを作る。設定値は false | 届かない（ミドルウェアが作られない） | 非該当（現在の設定に限る） |
| CVE-2024-21538 | cross-spawn 7.0.3 | あり。起動時に読み込まれる（呼び出し元は `cli/next-test`、`lib/helpers/install`、`lib/typescript/runTypeScriptCli`） | 該当なし（読み込まれるのは require の段階だけ。実行するのは CLI の関数だけ） | 届かない（サーバーの経路から spawn を呼ばない） | 非該当 |
| CVE-2025-71329 | image-size 1.2.1（JXL/HEIF） | あり。`server/image-optimizer/get-image-size.js` だけが使う。起動時には読み込まれない | 有効。`next-server.js:193` は `unoptimized` のとき 404 を返し、パーサーより前で止まる | 届かない | 非該当（現在の設定に限る） |
| CVE-2025-71330 | image-size 1.2.1（ICNS） | 同上 | 同上 | 届かない | 非該当（現在の設定に限る） |
| CVE-2026-67213 | nanoid 3.1.32（独自生成器でサイズ 0） | `customAlphabet`/`customRandom` は compiled nanoid と app-page runtime に定義がある | 有効。呼び出しは引数なしの `nanoid()` だけ（`base-server.js:555`、`app-render.js:1486`、runtime の `sm=()=>…nanoid()`）。独自生成器の呼び出しはない | 届かない | 非該当 |
| CVE-2026-67214 | nanoid 3.1.32（non-secure） | compiled 版には non-secure がない。トップレベルの `node_modules/nanoid` は **3.3.20（修正済み）**。postcss の `nanoid(6)` はこちらを使う | 該当なし | 届かない | 非該当（脆弱なコードが同梱されていない） |
| CVE-2026-73086 | nanoid 3.1.32（サイズ引数のオーバーフロー） | あり | 有効。リクエスト ID はヘッダー値をそのまま使うか `nanoid()` を引数なしで呼ぶ。サイズ引数にはどこからも値が流れない | 届かない | 非該当 |
| CVE-2026-33671 | picomatch 4.0.1（extglob による ReDoS） | あり。起動時に `shared/lib/match-remote-pattern.js` が読み込む | 有効。パターンは設定で固定（`localPatterns:'**'`、remote は空）。最適化ルートは 404 | 届かない（攻撃にはパターンを操れる必要がある） | 非該当 |
| CVE-2022-25883 | semver 7.3.2（範囲の ReDoS） | あり。`server/config.js` | 有効。使うのは固定の範囲 `'>=24.13.1'` だけ。standalone はスキーマ検証の前に設定を返す（config.js:1243） | 届かない | 非該当 |
| CVE-2023-54404 | zod 3.25.76（大きなコレクションでメモリを使い果たす） | あり。起動時に読み込まれる（`config-schema`、`shared/lib/zod`、`zod-validation-error`） | 有効。検証の対象は固定の next 設定だけ。MCP ツールの読み込みは dev の hot-reloader からだけ。Web ソースは zod を使っていない | 届かない | 非該当 |

注: 脆弱なバージョンは 9 件とも残っている（バージョンは上がっていない）。非該当という判定は、この固定設定と standalone で起動した場合に限る。Node 22 での実際の読み込みと、全経路を動的に確かめることはしていない（**未確認**）。

## 2. 稼働中カーネル（linux 6.12.118-1）で未修正の、隔離に関わる CVE 32 件

前提として確かめた事実:
- Worker は setpriv で権限を落とす（`--inh-caps=-all --bounding-set=-all --no-new-privs`。confinement.py:378）。さらに seccomp で unshare、setns、clone(NEWUSER)、io_uring、AF_UNIX を拒否する。planner 用の設定では bpf、mount 系、ptrace なども拒否する。
- ホスト側は userns=0（予定）と `unprivileged_bpf_disabled=2`。nft のルールは `ct state` と cgroupv2 の照合だけを使う（netfilter.py:47,53）。ct の expectation、helper、nat、fwd は使っていない。

| 分類 | 件数 |
|---|---|
| A. 何らかの userns で CAP_NET_ADMIN または CAP_SYS_ADMIN が要る（Worker は seccomp と権限の削除で、ホストの非特権ユーザーは userns=0 で阻止） | 9 |
| B. BPF プログラムを読み込む権限が要る（`unprivileged_bpf_disabled=2` のため init ns の CAP_BPF/CAP_SYS_ADMIN が必要。Worker は全 cap を削除済み） | 17 |
| C. io_uring（Worker は seccomp で拒否） | 2 |
| D. arm64 以外のアーキテクチャ | 2 |
| E. ハードウェアやモジュールがない | 1 |
| F. 古い・廃れた項目 | 1 |
| 未確認 | 0（ただし下の注を参照） |

| CVE | 対象 | 前提条件と判定 | 分類 |
|---|---|---|---|
| CVE-2019-20794 | userns 内の PID ns と FUSE によるハング | 非特権 userns が要る | A |
| CVE-2020-36694 | x_tables のルール差し替え時の UAF | 5.10 より前が対象（6.12 は対象外）。CAP_NET_ADMIN も要る | F |
| CVE-2021-3847 | overlayfs が nosuid から cap 付きファイルを複写 | overlay のマウント（userns で CAP_SYS_ADMIN）が要る。root が overlay を使う構成でないことは**未確認** | A |
| CVE-2024-56709 | io_uring の iowq 停止後の処理 | io_uring | C |
| CVE-2025-39822 | io_uring/kbuf の符号の誤り | io_uring | C |
| CVE-2026-53106 | bpf のローカルストレージ（NMI） | BPF の読み込み | B |
| CVE-2026-63858 | nf_tables のデバイス削除のフック | nft netlink に CAP_NET_ADMIN が要る | A |
| CVE-2026-64078 | x_tables の rmmod 経路 | モジュールの解除または CAP_NET_ADMIN が要る | A |
| CVE-2026-74314 | bpf の map 値の再利用 | BPF | B |
| CVE-2026-74337 | bpf の LRU ロック | BPF | B |
| CVE-2026-74354 | bpf の arena と zap_pages | BPF | B |
| CVE-2026-90211 | bpf（s390） | s390 だけ | D |
| CVE-2026-90237 | nft_ct の独自 expectation | expectation のルールを入れるのに CAP_NET_ADMIN が要る。Vulnix のルールは `ct state` だけで、expectation を作らない | A |
| CVE-2026-90317 | bpf の RCU ポインタ | BPF | B |
| CVE-2026-92518 | riscv の bpf tailcall | riscv だけ | D |
| CVE-2026-93044 | bpf の arena とインタプリタ | BPF | B |
| CVE-2026-93135 | bpf のインライン helper と JIT 無効時（ARM64 も該当） | BPF の読み込みと JIT の無効化または失敗が要る | B |
| CVE-2026-93270 | bpf の PERCPU 命令とインタプリタ | BPF | B |
| CVE-2026-98321 | nf_nat のフック登録失敗時のメモリリーク | CAP_NET_ADMIN が要り、メモリ確保の失敗も必要 | A |
| CVE-2026-98330 | cfg80211 の wiphy と netns | 無線デバイスがない（クラウド VM）。cfg80211 が読み込まれていないことは**未確認** | E |
| CVE-2026-98376 | bpf の percpu array（内側の map） | BPF | B |
| CVE-2026-98589 | bpf の pkt 引数 | BPF | B |
| CVE-2026-98599 | bpf の stack_slot | BPF | B |
| CVE-2026-98628 | bpf の検証後の書き換え（特権を持つ読み込み元） | BPF | B |
| CVE-2026-98789 | bpf の free_by_rcu_ttrace | BPF | B |
| CVE-2026-98799 | bpf の trampoline（切り離した prog） | BPF（tracing） | B |
| CVE-2026-98800 | bpf の trampoline の RCU tasks | BPF | B |
| CVE-2026-98813 | bpf の map BTF の参照 | BPF | B |
| CVE-2026-98816 | bpf の定数ブラインド（jit_harden=2） | BPF | B |
| CVE-2026-98972 | cgroup/cpuset の is_in_v2_mode | cgroup のマウントと rebind（CAP_SYS_ADMIN）が要る | A |
| CVE-2026-98983 | unshare の参照数の誤り | unshare(NEWUSER) での set_cred_ucounts の失敗経路。Worker は seccomp で、ホストは userns=0 で阻止。それ以外のフラグには CAP_SYS_ADMIN が要る | A |
| CVE-2026-99294 | nft_fwd_netdev の egress での再帰 | 設定に CAP_NET_ADMIN が要る | A |

注:
- **境界の前提**: A と B の「阻止」は、権限を持たない利用者についての話。バックエンドは `sudo -n`（パスワードなし sudo）で nft、cgroup、netns を操作する（netfilter.py:134-147、confinement.py:296）。sudoers がコマンドを制限していなければ、バックエンドを乗っ取られた時点で root と同等になり、これらのカーネル CVE は境界にならない。sudoers の内容はリポジトリになく、**未確認**。
- C（io_uring）は Worker では阻止されるが、ホストの非特権ユーザー（バックエンドのユーザー、SSH 利用者）は sysctl `kernel.io_uring_disabled` を設定しない限り使える。VM での値は**未確認**。
- 説明文の全文で照合すると、ほかに 12 件が該当する（範囲外の参考）。CVE-2026-31692（rtnetlink の peer netns の cap 確認）と CVE-2026-99709（userns や netns 内からの inet frag）は A と同じ扱い。そのほかは s390、powerpc、x86、f2fs、nfsd、nvme、wifi、bonding、sched_ext と kernfs で、個別には評価していない。
- 旧カーネル 6.12.95-1 の 4,905 件（未修正 4,566 件、open 338 件、undetermined 1 件）は、削除すれば対象外になる。

## 3. OS（カーネル以外）の open CVE

対象の 12 パッケージ（openssh、sudo、pam、systemd、util-linux、shadow、python3.13、openssl、glibc、expat、libxml2、sqlite3）で計 148 件。zlib は 0 件。curl、qemu、pyjwt は削除予定なので除いた。Debian の urgency はすべて unimportant か not yet assigned で、DSA 対象は 0 件（nodsa の多くは "Minor issue"）。KEV に載っているのは 1 件だけ。

### 問題になる・確認が要るもの

| CVE | パッケージ | 内容 | 判定 |
|---|---|---|---|
| CVE-2026-123158（**KEV**） | openssh | musl libc で PAM を使わない sshd でのパスワード認証回避 | 非該当。Debian は glibc と PAM で動く。KEV に載っていても、この環境に条件がない |
| CVE-2026-55654、-106553、-106555、-60000 | openssh | GSSAPI 認証での OOB 読み取り、資格情報の持ち越し、MaxAuthTries の不備 | GSSAPIAuthentication が有効なときだけ該当する。Debian の既定は無効。VM の sshd_config は**未確認**。`GSSAPIAuthentication no` の明示を推奨 |
| CVE-2026-60001 | openssh | 認証の最小遅延が守られない | 遠隔から届く。影響は時間差による推測の補助にとどまる。鍵認証だけにすれば影響はない（設定は**未確認**） |
| CVE-2026-106586、-73283、-59999 | openssh | authorized_keys の restrict や DisableForwarding がトンネルに効かない | トンネル（PermitTunnel）を許す設定のときだけ該当する。既定は no（設定は**未確認**） |
| CVE-2026-106585 | openssh | 展開時に最大パケット長を確かめない | 圧縮が有効なときだけ（サーバーの既定 `Compression yes` は認証後に有効になる）。認証済みの利用者による DoS に限られる。低 |
| CVE-2025-8941（undetermined） | pam | pam_namespace でのローカル権限昇格 | pam_namespace を有効にしているときだけ。Debian の既定では無効（VM の PAM 設定は**未確認**） |
| CVE-2026-82474 | sudo | ptrace 方式の intercept で execveat を確かめない | sudoers で intercept を使うときだけ。sudoers は**未確認**（2 章の注と同じ） |
| CVE-2026-76642、-78409、-78410 | util-linux | mount の X-mount.* フックや制限付き bind での昇格 | fstab に `user` 指定と X-mount.* があるときだけ。既定にはない（VM の fstab は**未確認**） |
| CVE-2026-78408 | util-linux | `nsenter --join-cgroup` の fd が引き継がれる | Vulnix は nsenter を使わない（cgroup.procs へは sh で echo して入る）。非該当 |
| CVE-2026-15059、-16742 | systemd | oomd の IPC、homed での昇格 | systemd-oomd や homed を使っているときだけ。cloud イメージでの有無は**未確認**。不要なら外す |
| CVE-2026-15308 | python3.13 | HTMLParser の CPU DoS | 届くのは ownership.py:134 だけ。本文は `resp.read(max_bytes=2048)` で切られる。影響は限られる。低 |
| CVE-2026-103995 | python3.13 | http.client が chunk を誤って解釈する | 所有確認やプローブが対象サーバーの応答を読むときに使う。相手は攻撃者自身のサーバーで、結果はトークン照合だけに使う。低 |
| CVE-2026-116566 | python3.13 | getaddrinfo が NUL で切り詰める | network.py は `target.hosts` と完全に一致するホストだけを解決する。ホスト登録で NUL を拒否しているかは**未確認** |
| CVE-2025-12781 | python3.13 | urlsafe_b64decode が `+/` も受け付ける | authz.py:148 のトークン復号で使う。署名は HMAC で確かめるので偽造はできない。同じ値を別の表記で書ける程度。低 |
| CVE-2026-15310 | python3.13 | zip の bzip/LZMA/zstd 展開時のメモリ確保 | public_catalog.py は OSV の zip（運用者が取得するもの）を読む。宣言サイズの上限はあるが、この CVE の経路を塞いでいるかは**未確認**。低 |
| CVE-2026-12345 | python3.13 | TemporaryDirectory の後片付けの競合 | 使っている箇所は複数ある。Worker（別 uid）が書き込める一時ディレクトリをバックエンドが消すかどうかは**未確認** |

### 残り（該当なし、または影響が小さい）の件数

| パッケージ | 件数 | 理由（1 行） |
|---|---|---|
| openssh | 30 件中 残り 20 | 大半はクライアント側（scp、sftp、ssh、ssh-agent、ssh-keygen）か、ユーザー名の列挙、SELinux、古い S/KEY や OPIE。サーバー側の 4 件（internal-sftp の引数、GSSAPIStrictAcceptorCheck、"none" の解釈、LZ77）は sftp、GSSAPI、圧縮の設定次第で、影響は小さい |
| sudo | 2 件中 残り 1 | visudo の古い symlink（1.6.8） |
| pam | 2 件中 残り 1 | pam_userdb（使っていない想定。**未確認**） |
| shadow | 3 | /etc/subuid の既定、古い btmp、TEMP。userns=0 では subuid を使わない |
| systemd | 6 件中 残り 4 | 封印したログ（FSS）の改ざん（未使用）と、古い symlink |
| util-linux | 6 件中 残り 2 | chfn/chsh の INPUTRC、`login -h`（SSH の経路では使わない） |
| python3.13 | 26 件中 残り 20 | 使っていないモジュール（imaplib、poplib、tarfile、csv.Sniffer、http.cookiejar、Morsel 出力、stringprep、pkgutil、ssl の sni_callback、wrap_bio、get_server_certificate、HTTPPasswordMgr、XML の解析）か、ビルドや CLI だけの項目 |
| glibc | 14 | ASLR 系（論争あり）、regex や glob でメモリ確保に失敗したとき、iconv の CP949、ISO-2022-CN-EXT、IBM1390、wscanf、LANGUAGE 環境変数。外部入力から届く経路は見つからなかった |
| openssl（Debian libssl 3.5.9） | 14 | 4 章を参照。ほかに EVP_EncodeBlock（攻撃経路なし）と DTLS（使っていない） |
| expat | 10 | Vulnix は XML を解析しない（local_defense.py は ElementTree で XML を作るだけ）。xmlwf は使わない |
| libxml2 | 20 | Python 標準ライブラリは libxml2 を使わない。lxml や python3-libxml2 はない。xmlcatalog も使わない |
| sqlite3 | 15 | 自分の DB に対してパラメータ付きの SQL を実行するだけ。FTS、R-Tree、session 拡張は使わず、外から渡された DB や SQL も扱わない。CLI の .recover も使わない |
| 範囲外の 55 パッケージ | 158 | 認証、権限、実行時の経路にない（gnutls、libpcap、elfutils など）。Debian の python3-cryptography 43、urllib3 2.3、requests 2.32 も入っている。バックエンドがこれらではなく同梱の wheel を読み込むことは**未確認** |

## 4. OpenSSL の Low 12 件（4.0.3 と 3.5.9 の両方が該当）

TLS と X.509 を使う場所: Python ssl（Debian libssl 3.5.9）は TLS クライアントだけ（所有確認とプローブ。`create_default_context(cafile=…)`）。バックエンドの HTTP サーバーは TLS なしの ThreadingHTTPServer。requests と urllib3 は Python ssl の上で動く。google-auth は ID トークンの署名を cryptography 50.0.2（OpenSSL 4.0.3 を静的リンク）で確かめる。secrets_store の暗号は HMAC-SHA256 を独自に組んだもので、OpenSSL の AEAD は使わない。

| CVE | 機能 | Vulnix が使うか | 判定 |
|---|---|---|---|
| CVE-2026-84785 | QUIC：順不同フラグメントの再構成 | QUIC を使わない（Python ssl と cryptography は QUIC を公開していない） | 非該当 |
| CVE-2026-107494 | QUIC：RETIRE_CONNECTION_ID の無制限な送信待ち | 同上 | 非該当 |
| CVE-2026-124709 | QUIC サーバー：拒否したストリームの保持 | 同上 | 非該当 |
| CVE-2026-88822 | QUIC：自動ピア検出 | 同上 | 非該当 |
| CVE-2026-95691 | QUIC クライアント：CRYPTO フレームの再送 | 同上 | 非該当 |
| CVE-2026-121482 | CMS/PKCS#7 で CRL を確かめる処理 | CMS/PKCS7 を使わず、CRL も確かめない（既定は無効） | 非該当 |
| CVE-2026-107496 | CMS_encrypt（EC の位数が 1） | CMS を使わない | 非該当 |
| CVE-2026-84786 | DANE クライアント | Python ssl と cryptography は DANE を公開していない | 非該当 |
| CVE-2026-107493 | PEM_X509_INFO_read_bio_ex に既存のスタックを渡す | cafile の読み込みは X509_LOOKUP 経由で NULL スタックを渡す。cryptography は Rust で PEM を解析する（上流の実装に基づく判断。バイナリでは**未確認**） | 非該当 |
| CVE-2026-35190 | Suite B フラグを付けた TLS 1.3 サーバー | TLS サーバーにならず、SSL_CTX_set_cert_flags も使わない | 非該当 |
| CVE-2026-88823 | AES-GCM-SIV で長さ 0 の AAD | AESGCMSIV を使わない（grep で 0 件） | 非該当 |
| CVE-2026-95692 | AES-GCM-SIV の IV 長 | 同上 | 非該当 |

## 5. 推奨する対応

1. **sudoers を最小限にする（最優先）**: バックエンドのパスワードなし sudo を、実際に使う nft、ip netns、cgroup、setpriv の固定引数だけに絞る。広すぎると、2 章の隔離の議論が成り立たない。現状は**未確認**。
2. 本番イメージで `kernel.unprivileged_userns_clone=0` を確実に設定し（予定どおり）、`kernel.io_uring_disabled=2` も加える。`unprivileged_bpf_disabled=2` は維持し、起動時に値を確かめる。
3. sshd を固める: `GSSAPIAuthentication no`、`PasswordAuthentication no`、`PermitTunnel no`、`DisableForwarding yes`（管理に必要な範囲で）。そのうえで実際の設定を `sshd -T` で記録する。
4. 削除する予定のもの（旧カーネル 6.12.95、qemu-utils、curl、python3-jwt）を実際にイメージから外し、外したことを確かめる。不要な systemd-oomd と homed も外す。
5. Web: 現在の非該当判定は `compress:false`、`images.unoptimized`、standalone の 3 つに依存する。これらの設定値をリリースゲートで検査し続ける。Next の更新で compiled の依存が修正版になったら取り込む。
6. 確かめていない項目は VM で確認する: sshd_config、PAM（pam_namespace）、fstab、cfg80211、io_uring の sysctl、Node 22 での読み込みの再確認、バックエンドがどの cryptography、urllib3、requests を読み込むか、ホスト登録で NUL を拒否するか、TemporaryDirectory を Worker と共有していないか。
7. trixie のポイントリリースで、openssh（GSSAPI 系）、openssl 3.5.10、python3.13 の修正が出たら適用する。
