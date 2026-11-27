# gozar — public-open-proxy finder, verifier, personal gateway

Finds free public configs (vless/hy2/tuic/trojan/vmess/ss) from **tiered,
pre-tested GitHub sources**, verifies them **against YOUR real targets**
through sing-box, ranks them in a persistent state, and connects you via a
local proxy or a full TUN.

Built for weak / censored lines: cheap TCP probes before every
expensive sing-box test, per-tier cascade (stop early when enough), adaptive
latency thresholds derived from *your* baseline ping.

> Older HTTP/SOCKS4/SOCKS5 "proxy list" generation was removed in fd99e6f →
> a62cfed (see git history).

## Layout

```
gozar/
├── gozar-dev               # bash launcher (ulimit, venv, exec) — `./gozar-dev <command>`
│                           # named gozar-dev because a script called `cli` collides
│                           # with pip's own entry point of the same name
├── install.sh              # installs sing-box + venv (arch-detect)
├── config.json             # user overrides (defaults live in gozar/config.py)
├── requirements.txt        # aiohttp + aiohttp-socks (vendored under vendor/)
├── completions/            # GENERATED from argparse (scripts/gen-completions.py)
│   ├── gozar.fish · gozar.bash · _gozar
├── scripts/
│   ├── gozar              # the installed command (explains a broken import)
│   ├── gozar-rescue.py    # standalone diagnosis, imports nothing from the project
│   └── gen-completions.py # rewrites completions/ from the parser
└── gozar/                  # the python package
    ├── cli.py              # CLI: argument parsing, command dispatch, cmd_* functions
    │
    ├── core_ui.py          # ⊙ shared vocabulary: OK/WARN/FAIL, say(), Ledger, wrap, table
    ├── doctor_checks.py    # ⊙ every doctor check as its own function + a registry
    ├── engines.py          # ⊙ the ONE resolver for the sing-box binary + version probe
    │
    ├── config.py           # DEFAULTS + load_config
    ├── core_sources.py     # measured/tested/bulk tiers + protocol sources
    ├── core_parser.py      # link → config dict (vless/vmess/trojan/ss/hy2/tuic/anytls)
    ├── core_runner.py      # sing-box instance(s) + real fetch + exit-IP tunnel proof
    ├── core_test.py        # cascade discover + check, adaptive thresholds
    ├── core_store.py       # state.json: upsert/score/prune + selectors + freshness
    ├── core_output.py      # best/bak/gen .txt+.json+.summary.txt + sing-box group build
    ├── core_connect.py     # urltest group connect (nodes engine)
    ├── core_live.py        # live status board for a running tunnel
    ├── core_score.py       # source scoring against one target
    ├── thresholds.py       # adaptive fast/keep ceilings from your baseline
    ├── ui_pick.py          # interactive picker — curses TUI / stdin menu fallback
    ├── doctor.py           # ⊙ the running ORDER: static checks → live checks → verdict
    ├── selfcheck.py        # ⊙ did the install land intact? launcher → interpreter → files
    ├── checker.py          # tcp_ping, udp_quic_ping, baseline, classify, exit-IP proof
    └── display.py          # ⊙ colour/bar/card paint layer (cosmetics only)
```

`⊙` marks the shared pieces. The rule is one sentence: **wording lives in
`core_ui`, decisions live in the module that owns the fact, and `cli.py` only
routes.** A command never invents its own `[WARN]` or its own exit code any more.

### The three seams, with the code

```python
# 1. one vocabulary — every command speaks it
from .core_ui import OK, WARN, FAIL, say, Ledger
ledger = Ledger()
ledger.check(OK, "python 3.13")
ledger.check(FAIL, "sing-box not found")
return ledger.summary("All checks passed.", "issue(s) found.")   # 0 or 2

# 2. doctor is a list of functions, not a 250-line one
from .doctor_checks import registry, run
run("engine", cfg)        # -> ("ok", "sing-box (gozar engines dir): … [1.14.5]")
names()                   # -> ['python', 'packages', 'engine', 'limits', 'data', 'root']

# 3. one engine resolver, one version probe
from .engines import find_binary, source_of, first_version_line
first_version_line(find_binary("sing-box"))   # -> 'sing-box version 1.14.5'
```

Both are reachable from the command line, which is how you can tell they are
real seams and not just nicer file names:

```bash
gozar doctor --list-checks      # name + title of every check
gozar doctor --only engine      # run exactly one (exit 2 when it fails)
```

## Install — three ways while the package is not on PyPI yet

| # | for whom | command |
|---|---|---|
| 1 | **just try it, one file** | `curl -LO https://github.com/amirreaper/gozar/releases/latest/download/gozar.pyz` → `chmod +x gozar.pyz` → `./gozar.pyz engine install` |
| 2 | **from git, user-wide** | `pip install --user "gozar[engine] @ git+https://github.com/amirreaper/gozar.git"` |
| 3 | **developer checkout** | `git clone https://github.com/amirreaper/gozar.git && cd gozar && bash install.sh --venv` → `./gozar-dev` |

### `gozar: ModuleNotFoundError: No module named 'gozar'` — read this once

You will see this after a successful `pip install`. It is never one problem;
it is one of four, and they need different fixes. In order of frequency:

| # | cause | how you know | fix |
|---|---|---|---|
| 1 | **user site-packages is off** for the python the launcher uses (`PYTHONNOUSERSITE=1`, or `python -s`, common in managed shells) | `python3 -c "import site;print(site.ENABLE_USER_SITE)"` → `False` | `unset PYTHONNOUSERSITE`, or install into a venv (below) |
| 2 | **two pythons**: `pip` installed into one, the script runs the other (`/usr/bin/python3` vs `/usr/local/bin/python3`) | `head -1 $(command -v gozar)` shows a python that `pip --version` does not mention | use one interpreter for both, by full path |
| 3 | **venv without `--system-site-packages`** and the package went to `--user` | `python3 -c "import sys;print(sys.prefix)"` differs from the launcher's | install *inside* the venv, no `--user` |
| 4 | a leftover **`gozar/` directory without `__init__.py`** shadows the real package | `python3 -c "import importlib.util as u;print(u.find_spec('gozar'))"` → `origin=None` | delete that directory |

Two commands settle it, and neither needs the package to import:

```bash
gozar selfcheck          # if gozar runs at all: launcher → interpreter → files
python3 scripts/gozar-rescue.py    # if it does not: standalone, imports nothing
```

The fix that avoids all four, and the one to recommend to anyone who is not
debugging:

```bash
python3 -m venv ~/.gozar
~/.gozar/bin/pip install "git+https://github.com/amirreaper/gozar.git"
~/.gozar/bin/gozar doctor
```

Since v2.1.2 the installed `gozar` command is a real script instead of a
setuptools stub, so a broken import prints those four causes and the exact
interpreter to reinstall with, then exits 2.

### Completions

```bash
# fish
cp completions/gozar.fish ~/.config/fish/completions/

# bash
source completions/gozar.bash        # or: cp to /etc/bash_completion.d/

# zsh
cp completions/_gozar ~/.zfunc/_gozar && fpath+=(~/.zfunc) && compinit
```

They are generated from `argparse`, not written by hand:

```bash
python3 scripts/gen-completions.py           # regenerate all three
python3 scripts/gen-completions.py --check   # fails if they drifted
```

> `pip install gozar` will work once the package is on PyPI. Until then it is
> **not** published, and every doc here says so on purpose — a README that
> tells you to run a command that fails is worse than a longer one.

Whichever you pick, the first command is the same check:

```bash
gozar engine status        # or ./gozar-dev engine status in a checkout
```

`gozar` (pronounced *gozar*, "the passage") tests nodes with **sing-box**, a Go
binary. It is the one thing pip cannot carry, so `gozar engine install` fetches
the official release into `~/.local/share/gozar/engines/` (~40MB, no root,
checked when you run it — never in the middle of a test).

If you already have sing-box somewhere: `export GOZAR_SINGBOX=/path/to/sing-box`.
If you want pip to carry it: `pip install sing-box-bin` (a third-party repackage
of the official binaries — convenient, and `gozar engine status` tells you which
source it picked).

**Exit codes:** `0` good · `2` cannot run (no engine, bad usage) · `3` ran, nothing
passed · `130` stopped with Ctrl+C.

## Install & prerequisites

```bash
bash install.sh              # engine only: downloads sing-box into ./engines
bash install.sh --venv       # + a local .venv with aiohttp/aiohttp-socks
./gozar-dev doctor                 # proves engine + deps + a live test
```

NixOS / anything with nix:

```bash
nix-shell -p python3 python3Packages.aiohttp python3Packages.aiohttp-socks curl
# sing-box is auto-detected from ./engines, ~/.local/bin, or PATH:
#   nix-shell -p sing-box   (or: bash install.sh pulls the release binary)
```

**sing-box compatibility:** the bot auto-detects the sing-box version and
emits the config shape it needs (`endpoints` for ≥1.13, legacy `outbounds`
form for older builds like nixpkgs-stable), with a validate-and-fallback
pass. No sudo is needed in proxy mode on any version; `--mode tun` is the
only path that wants root.

## Quick start

```bash
gozar doctor                          # env + sources + baseline + targets
gozar discover -t https://example.com/ -t https://www.gstatic.com/generate_204 -n 30
gozar run 5                           # find 5, verify, interactive picker, connect
gozar pick                            # live table: id, proto, latency, stability
                                      #   Enter=connect  d=drop  r=re-ping
                                      #   c=mass re-check + resort  f=list filter (all/fast/backup)  q=quit
gozar pick --from best                # start with only the best list visible
gozar drop 26e0e391                   # delete node by short id or list index
gozar check --drop-dead               # live re-check, purge this-round failures immediately
gozar connect                         # urltest group over best nodes (proxy on :2080)
gozar status                          # stats & current config summary
gozar list                            # best/bak/gen with short ids
gozar verify -n 10 --from all         # PROOF: did traffic really cross the node?
gozar verify --port 2080              # verify the live local proxy (connect mode)
```

### Multi-target

`-t URL` is repeatable; a node only counts as `target_ok` when **all** targets
pass (latency + real fetch + CF/poson detection). Config file equivalent:

```json
"targets": ["https://example.com/", "https://www.gstatic.com/generate_204"]
```

## How it decides (6 stages)

1. **fetch** — tier-by-tier (trusted → good → medium), stops early once enough
2. **probe** — TCP ping per candidate (400-way); QUIC/UDP protos get a real RFC 9000
   Version-Negotiation probe instead of being killed by a TCP-only check
3. **sing-box test** — real echo through the candidate, up to 6 nodes per process
4. **tunnel proof** — the public exit IP is read *through* the tunnel and compared
   with your own line IP; equal ⇒ `leak` ⇒ node rejected
5. **target check** — real fetch of *your* target(s) with full browser headers;
   CF-block/challenge filtered
6. **persist & rank** — state.json with success/fail/success-rate/avg latency and
   per-check freshness (`last_check`, `alive_now`, `last_result`), adaptive
   fast/bak thresholds from *your* baseline ping

## Architecture guarantees

- **a 2xx answer is never trusted as proof of tunneling** — exit-IP verification is on
  by default (`--strict-exit` to also reject nodes whose exit IP cannot be read)
- atomic state writes (tmp + rename) plus **incremental real-time persistence**: every
  node is written to `state.json` / `best.txt` / `bak.txt` / `gen.txt` the moment it is
  tested, and Ctrl+C saves everything found so far (second Ctrl+C force-quits)
- prune on consecutive failures / last-ok age
- unreachable sources are **named**, never fatal (filtered networks reality)
- third-party passthrough proxies intentionally excluded (mirror injection)
- CLI exit codes: 0 ok, 2 usage/no-data, 3 verification failed

## Daily workflow (3 short rituals)

```bash
gozar discover -t https://example.com/ -n 20   # 1) hunt + test (2-4 min)
gozar check                                    # 2) re-check the pool, prune dead
gozar connect                                  # 3) local proxy on your best nodes :2080
```
Pool dry (`best < 5`)? Re-hunt, or ask what your line can actually do:
```bash
gozar discover -t https://example.com/ -n 30 --hard
gozar calibrate                # measure your line, propose the ceilings
```

## Golden nodes ⭐ — the manual "might come back" pool

Good public nodes usually die within hours, but some are real keys that
revive after a few days. `gozar pick` lets you pin them:

- press `g` on any row (text menu: `g 3`) — the row shows `*` and is always
  listed FIRST in pick.
- golden nodes are NEVER auto-pruned (not by `prune_failures`, not by
  `--drop-dead`); only you remove them (`g` again or `d`).
- `gozar check` still re-tests them every round — if one revives it flows
  back into the fast tier automatically.
- `gozar status` counts them; `gozar list` marks them with `*`.

## Display & list actions (v1.3.1)

- per-run node table with latency bars and stars (★ fast, ● backup, ☓ dead)
- live progress bar line on TTY (Style C1), heartbeat when piped
- boxed summary card after every tier
- `gozar list --pin N...` / `--drop N...` / `--recheck`

## The 3 categories: best / bak / gen

Every node you can actually use lands in exactly one of three lists, written to
`data/` as `.txt` (raw links), `.json` (records) and `.summary.txt` (human table):

| list | file | what it means | glyph |
|---|---|---|---|
| **best** | `best.txt` | fast **and** opens your target(s) | ★ |
| **bak**  | `bak.txt`  | connected, opens your target(s), higher latency (or overflow of `best_n`) | ● |
| **gen**  | `gen.txt`  | connected & healthy but **did not** open your target — still fine for Telegram / general web | ◆ |

So a day when your target is unreachable everywhere does not leave you with zero
nodes: `gen.txt` still has working exits.

```bash
gozar connect                 # best (auto-falls back to bak, then gen)
gozar connect --from bak      # explicit
gozar connect --from gen      # general/Telegram pool
gozar list                    # all three lists
gozar pick                    # f cycles: usable / fast / backup / general / slow / dead
```

## Tunnel proof — a 2xx is not evidence

`echo_url` defaults to `generate_204`, whose body is **empty**. Before v1.5.0 that
meant the bot only knew "some 2xx came back" — on an interfered or transparent line
the answer can arrive **without ever crossing the node**, so dead nodes were reported
as alive and fast.

Now every run:

1. reads **your own public IP directly** (no proxy) — the proof baseline, printed as
   `Tunnel-proof baseline: your own line IP = ...`
2. reads the **exit IP through the tunnel** (`cdn-cgi/trace` gives `ip=` + country +
   colo, with 6 fallback services; IPv4 **and** IPv6)
3. if `exit IP == your own line IP` ⇒ **`leak`** ⇒ the node is rejected, marked in
   `state.json` and reported as `[LEAK] ...`

The probe runs **concurrently** with the target check, so it costs ~0 extra time.

```bash
gozar verify -n 10 --from all     # per node: TUNNELED ✓ / LEAK ✗ / UNVERIFIED ? / DEAD ✗
gozar verify --port 2080          # verify the proxy `gozar connect` is serving right now
gozar discover --strict-exit      # also reject nodes whose exit IP cannot be read
gozar discover --no-exit-proof    # turn the proof off (not recommended)
```

`UNVERIFIED ?` means the exit-IP services were unreachable through that node — it may
still work, it just could not be proven.

### "curl says 403 but the bot says it works" — both are right

Targets behind Cloudflare (example.com included) apply a **bot rule on User-Agent**.
Measured live through the *same* proxy in the *same* second:

```bash
curl -x socks5h://127.0.0.1:2080 -I https://example.com/
# HTTP/2 403 + cf-mitigated: challenge + "Just a moment..."   <- curl's own UA

curl -x socks5h://127.0.0.1:2080 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
  AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" -I https://example.com/
# HTTP/2 200 + cf-ray: ...-DFW                                <- same node, browser UA
```

Receiving that 403 *from Cloudflare's edge* is itself proof the tunnel worked.
`gozar verify --port 2080` prints both answers side by side so you never have to guess.
Also note `socks5h://` (remote DNS) vs `socks5://` (local DNS) — on a poisoned line the
latter can fail even with a perfect node.

## Check & re-check: reading the numbers

`gozar check` re-tests the pool and the display now always tells you **how fresh** each
number is:

```
Pool after check: 17 usable = 3 fast + 10 bak + 4 gen | dead=5 (5 died now, 0 revived, 0 promoted, 1 demoted)
  ☓ trojan      141.193.213.172:443 — dead (no answer)
  dead nodes left the pool; they stay in state and come back automatically if they pass a later check
```

The contract:

- every record carries `last_check`, `alive_now`, `last_result` (`ok` / `no_target` /
  `cf_challenge` / `cf_block` / `leak` / `dead` / `probe_dead`) and `last_error`
- a node that fails a check moves to `tier=dead`: it **leaves** `best/bak/gen`, the
  output files and the default picker view immediately
- dead nodes are **retried on every later check** and revive automatically when they
  pass again (`revived=N` in the summary) — the pool never shrinks permanently
- a stale latency is shown greyed with a `~` prefix (`~452ms` = last known, not current),
  and every row ends with `last:FAIL·25s (dead)` or `last:ok·2m`
- `gozar pick` → `f` → `dead` lists them so you can bulk-delete with `d`;
  `gozar list` prints a note saying how many are hidden
- `gozar status` shows `usable / dead` and how long ago the last check ran

## Version history

Every change, bug and the reason behind each decision lives in `CHANGELOG.md`; it is not duplicated here.

## Tests

The contract suite lives in `tests/test_contracts.py` (219 checks, no
network needed) and pins the decisions that are easy to undo by accident:
what "usable" means, the three pools, the shell-target verdict, Ctrl+C bounds.

```bash
python3 tests/test_contracts.py     # PASS/FAIL table, exit 1 on any FAIL
```

Live runs use a throwaway data dir, so they never touch your pool:

```bash
gozar -o /tmp/try discover -t https://example.com/ -n 5
```

## Harsh-phase flags: --open-sni & --safe-ports

Measured on a real filtered line (Oct 2026): exotic node SNIs get
TLS-reset at handshake, uncommon ports get killed, but `*.ir` plus a few
big hosts always complete TLS.

```bash
bot discover --open-sni                 # node SNI must be in today's open set
bot discover --safe-ports               # only ports 443/8443/80/2083
bot discover --cdn --open-sni --safe-ports -i links.txt   # full-shutdown combo
```

All flags are off by default — default behaviour stays broad/global.

## National-internet mode (--cdn) — Cloudflare-fronted only

During "national internet" phases almost every server dies but the
Cloudflare edge usually stays reachable (domestic services use it too).
`--cdn` keeps only nodes whose server IP sits in the official CF IPv4
ranges (15 ranges pinned in code):

```bash
bot discover --cdn
bot discover --cdn -i links.txt --domestic   # full-shutdown combo
```

## Import your own links (-i FILE) — tested first

Got a bunch of node links from a Telegram channel or a free sub? Drop them
into a file (mixed raw links, `#` comments, base64 sub blocks — all fine):

```bash
bot discover -i links.txt          # your links are tested BEFORE the tiers
bot discover -i a.txt -i b.txt     # repeatable
```

The full parser extracts every valid vless/hy2/trojan/vmess/ss/tuic/anytls
link, dedupes them, counts and drops garbage
(`3 valid links (1 skipped as garbage)`). Since they are hand-picked, they
get the real sing-box test before known nodes and before the source tiers.
Survivors land in state like everything else.

## Shutdown mode — domestic sources (--domestic)

When international internet is fully cut, GitHub sources do not load.
Add Iranian-hosted subscription URLs to `config.json`:

```json
"domestic_sources": ["https://sub.example.ir/nodes.txt"]
```

- normal mode: domestic sources are fetched FIRST (cheap if offline)
- full shutdown: `gozar discover --domestic` reads ONLY these and still hunts
  for working nodes

## Tips for harsh lines

```bash
gozar discover --probe-concurrency 200 --concurrency 6 --max-per-proto 150 -n 30
gozar loop --check-interval 1800 -n 20            # self-maintaining in background

# pacing + circuit breaker + target-based latency are ON BY DEFAULT
# (probe jitter 15ms / test jitter 50ms / breaker 25-fails backoff).
# Tune only if your line is harsher than usual:
gozar discover --pace 200        # raise pacing; set 0 to disable

# be boring about it: fewer parallel tests, longer timeouts, keep going
gozar discover --hard -n 30

# find out whether the pool or the line is the problem
gozar doctor

# rank by echo ping instead of target download time (opposite of default):
gozar discover --latency-basis echo
```

## Safe defaults (always on)

- probe/test pacing jitter (15/50ms) — avoids port-scan-looking bursts
- circuit breakers — 25 consecutive test fails → exponential backoff; 400 dead probes in a row → 20s pause
- `latency_basis=target` — ranking uses real target download time when targets are configured

Manual/confirm-only: `--drop-dead`, `--verify-ssl`.
