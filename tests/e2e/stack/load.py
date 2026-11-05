#!/usr/bin/env python3
"""Real TCP and HTTP load. Writes per-second counts to --out as it runs, so a scenario can read any phase of it."""
import argparse
import asyncio
import json
import os
import random
import signal
import time

ap = argparse.ArgumentParser()
ap.add_argument("--host", default="203.0.113.20")
ap.add_argument("--port", type=int, default=80)
ap.add_argument("--rate", type=float, default=0, help="new connections per second")
ap.add_argument("--hold", type=int, default=0, help="connections kept open with an occasional request")
ap.add_argument("--ramp", type=float, default=2.0, help="seconds over which the held connections open")
ap.add_argument("--path", default="/page/load")
ap.add_argument("--connect-only", action="store_true", help="complete the handshake, send nothing, close")
ap.add_argument("--out", required=True)
ap.add_argument("--timeout", type=float, default=4.0)
args = ap.parse_args()

seconds = {}  # int second -> [ok, errors, slow]
state = {"held_open": 0, "held_lost": 0, "started": time.time()}
SLOW = 0.9  # a dropped SYN is retransmitted after 1 s, so this marks a request that a firewall delayed


def record(ok, took):
    row = seconds.setdefault(int(time.time()), [0, 0, 0])
    row[0 if ok else 1] += 1
    if ok and took >= SLOW:
        row[2] += 1


async def one():
    started = time.monotonic()
    writer = None
    try:
        async with asyncio.timeout(args.timeout):
            reader, writer = await asyncio.open_connection(args.host, args.port)
            if args.connect_only:
                record(True, time.monotonic() - started)
                return
            writer.write(f"GET {args.path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            head = await reader.readline()
            await reader.read()
        record(head.split()[1:2] == [b"200"], time.monotonic() - started)
    except (OSError, TimeoutError, asyncio.IncompleteReadError):
        record(False, time.monotonic() - started)
    finally:
        if writer:
            writer.close()


async def holder():
    await asyncio.sleep(random.random() * args.ramp)
    while True:
        try:
            reader, writer = await asyncio.open_connection(args.host, args.port)
            state["held_open"] += 1
            try:
                while True:
                    writer.write(f"GET {args.path} HTTP/1.1\r\nHost: t\r\n\r\n".encode())
                    await writer.drain()
                    head = await asyncio.wait_for(reader.readline(), args.timeout)
                    if not head:
                        raise ConnectionError
                    while (await asyncio.wait_for(reader.readline(), args.timeout)) not in (b"\r\n", b""):
                        pass
                    await reader.readexactly(5)  # "page\n"
                    await asyncio.sleep(25 + random.random() * 10)
            finally:
                state["held_open"] -= 1
                writer.close()
        except (OSError, TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            state["held_lost"] += 1
            await asyncio.sleep(1)


def dump():
    tmp = args.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump({**state, "seconds": seconds}, f)
    os.replace(tmp, args.out)


async def reporter():
    while True:
        dump()
        await asyncio.sleep(0.5)


async def main():
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    tasks = {asyncio.create_task(reporter())}
    tasks |= {asyncio.create_task(holder()) for _ in range(args.hold)}
    running = set()

    async def pacer():
        while args.rate:
            await asyncio.sleep(random.expovariate(args.rate))
            task = asyncio.create_task(one())
            running.add(task)
            task.add_done_callback(running.discard)

    tasks.add(asyncio.create_task(pacer()))
    await stop.wait()
    for t in tasks:
        t.cancel()
    dump()


asyncio.run(main())
