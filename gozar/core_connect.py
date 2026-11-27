"""Connect mode: launch sing-box using best nodes."""
from __future__ import annotations
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path

from . import core_output as out
from . import core_parser as parser
from . import core_runner as runner
from . import core_store as store

log = logging.getLogger("core.connect")


def _engine() -> Path:
    path = runner.singbox_path()
    return path


async def _prepare_nodes(recs, data_dir):
    """Nodes are used exactly as measured. The DPI frag-relay layer is gone
    (v1.9.0): it rewrote a node's server to 127.0.0.1 so sing-box dialled a
    local relay first, which narrowed real throughput and produced nodes that
    passed tests but struggled in a browser. A node that cannot carry traffic
    on its own is now simply not kept."""
    return list(recs), []


async def run_connect(data_dir: Path, mode: str = "proxy", port: int = 2080,
                      pin_index: int | None = None, source: str = "best",
                      recs=None, allow_no_target: bool = False):
    if recs is None:
        state_path = data_dir / "state.json"
        state = store.load(state_path)
        best_r = store.best(state, 200, require_target=True)
        best_ids = {store.ident(r) for r in best_r}
        bak_r = store.backup(state, 200, require_target=True, exclude=best_ids)
        gen_r = store.general(state, 200, exclude=best_ids | {store.ident(r) for r in bak_r})
        if source == "bak":
            recs = bak_r or gen_r
        elif source == "gen":
            recs = gen_r
        elif source == "all":
            recs = list(best_r) + list(bak_r) + list(gen_r)
        else:
            recs = best_r or bak_r
            if not recs and gen_r:
                # A silent fallback here was a bug report of its own: the user
                # ended up connected to a node that had NOT passed the targets
                # and saw "connected but no site opens". Ask, don't assume.
                if allow_no_target:
                    log.warning("No target-OK nodes available — falling back to "
                                "'gen' (%d alive nodes that did NOT pass the targets; "
                                "good for general use only).", len(gen_r))
                    recs = gen_r
                else:
                    log.error("No target-OK nodes available (%d 'gen' nodes exist but "
                              "they did not pass your targets).",
                              len(gen_r))
                    log.info("Options: run `gozar check` / `gozar discover`, "
                             "or connect to the gen pool explicitly with "
                             "`gozar connect --from gen` (or pass --allow-no-target).")
                    return 4
    if not recs:
        log.error("No working nodes available. Run discover first.")
        return 2

    if pin_index is not None:
        if pin_index < 0 or pin_index >= len(recs):
            log.error("Index %d out of range (0 to %d)", pin_index, len(recs) - 1)
            return 2
        recs = [recs[pin_index]]

    recs, relays = await _prepare_nodes(recs, data_dir)

    try:
        if pin_index is not None or len(recs) == 1:
            chosen = recs[0]
            cfg = parser.parse(chosen["raw"])
            if not cfg:
                log.error("Invalid config")
                return 2
            sb_cfg = {
                "log": {"level": "warn", "timestamp": True},
                "inbounds": _inbounds(mode, port),
                "outbounds": [
                    runner.build_outbound(cfg, "proxy"),
                    {"type": "direct", "tag": "direct"},
                ],
                "route": {"final": "proxy", "auto_detect_interface": True},
            }
            label = f"{cfg['type']} {chosen['server']}:{chosen['server_port']} " \
                    f"({chosen.get('latency')}ms) — {(chosen.get('tag') or '')[:40]}"
        else:
            sb_cfg = out.build_singbox_config(recs, mixed_port=port if mode != "tun" else None,
                                              tun=(mode == "tun"))
            label = f"Auto group with {len(recs)} nodes (urltest)"

        if sb_cfg is None:
            log.error("Failed to build sing-box config")
            return 2

        cfg_path = data_dir / "connect.json"
        cfg_path.write_text(json.dumps(sb_cfg, ensure_ascii=False, indent=1), encoding="utf-8")

        if mode == "tun" and os.geteuid() != 0:
            log.warning("TUN mode requires root: sudo -E gozar connect --mode tun")

        print("=" * 64)
        print(f"  Connecting: {label}")
        if mode == "proxy":
            print(f"  Local proxy: socks5://127.0.0.1:{port}  /  http://127.0.0.1:{port}")
        else:
            print("  TUN mode: all system traffic is routed through the tunnel")
        print(f"  Config: {cfg_path}")
        print("  Press Ctrl+C to stop")
        print("=" * 64)

        proc = await asyncio.create_subprocess_exec(
            str(_engine()), "run", "-c", str(cfg_path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )

        stop = asyncio.Event()

        _sigint_seen = []

        def _signal(*_):
            # First Ctrl+C: shut sing-box down politely.
            # Second Ctrl+C: stop negotiating with a stuck child process and go.
            # Without this, a sing-box that ignores SIGTERM (TUN, or a wedged
            # socket) kept the terminal captive with no way out but -9.
            if _sigint_seen:
                for rel in relays:
                    try:
                        rel.close()
                    except Exception:  # noqa: BLE001
                        pass
                try:
                    if proc.returncode is None:
                        proc.kill()
                except Exception:  # noqa: BLE001
                    pass
                os._exit(130)
            _sigint_seen.append(1)
            stop.set()
        if sys.platform != "win32":
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _signal)

        async def pump():
            assert proc.stdout is not None
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                sys.stdout.write("[sing-box] " + line.decode("utf-8", "ignore"))

        pump_task = asyncio.create_task(pump())
        wait_task = asyncio.create_task(proc.wait())
        stop_task = asyncio.create_task(stop.wait())

        done, pending = await asyncio.wait(
            {wait_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        if stop_task in done and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                # sing-box ignores SIGTERM while a TUN device is up, and then
                # `await proc.wait()` never returns: Ctrl+C looked like a hang.
                proc.kill()
        for t in pending:
            t.cancel()
        # The stdout pump is cancelled with everything else; awaiting it without
        # a bound is how the CLI sat at a dead prompt after Ctrl+C. Bound it and
        # never let a cleanup failure mask the exit.
        try:
            await asyncio.wait_for(pump_task, timeout=2)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pump_task.cancel()
        return 0
    finally:
        for rel in relays:
            try:
                rel.close()
            except Exception:  # noqa: BLE001
                pass


def _inbounds(mode, port):
    if mode == "tun":
        return [{
            "type": "tun", "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 9000, "auto_route": True, "strict_route": True,
            "stack": "system",
        }]
    return [{
        "type": "mixed", "tag": "mixed-in",
        "listen": "127.0.0.1", "listen_port": port,
    }]
