#!/usr/bin/env python3
"""Smoke: subscribe WS to demo channel, enable demo via REST, assert demo_state push."""
import asyncio
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


async def main() -> int:
    import websockets

    got_demo = asyncio.Event()
    got_nodes = asyncio.Event()
    received = []

    async def listener():
        async with websockets.connect("ws://127.0.0.1:7070/ws/live") as ws:
            await ws.send(json.dumps({
                "type": "subscribe",
                "channels": ["demo", "attack_graph"],
            }))
            try:
                async with asyncio.timeout(20):
                    while True:
                        raw = await ws.recv()
                        msg = json.loads(raw)
                        received.append(msg.get("type"))
                        if msg.get("type") == "demo_state":
                            print("WS demo_state:", json.dumps(msg.get("data")))
                            got_demo.set()
                        if msg.get("type") in ("attack_graph_full", "attack_node"):
                            got_nodes.set()
                        if got_demo.is_set() and got_nodes.is_set():
                            return
            except asyncio.TimeoutError:
                pass

    task = asyncio.create_task(listener())
    await asyncio.sleep(1.5)

    try:
        req = urllib.request.Request(
            "http://127.0.0.1:7070/api/demo/enable", method="POST", data=b""
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
            print("REST enable:", body["demo_mode"], body["hosts"], "hosts")

        await task
        print("received types:", sorted(set(received)))
        ok = got_demo.is_set()
        if not got_nodes.is_set():
            print("WARN: no attack_graph WS push observed within window (poller cadence)")
        return 0 if ok else 1
    finally:
        disable = urllib.request.Request(
            "http://127.0.0.1:7070/api/demo/disable", method="POST", data=b""
        )
        with urllib.request.urlopen(disable, timeout=30):
            pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
