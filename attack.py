#!/usr/bin/env python3
"""
Attack injection for SDN trust experiments.
Usage: python3 attack.py <blackhole|greyhole|stop> <switch> [args]
"""
import os, subprocess, sys


def blackhole(sw):
    subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", sw,
                    "cookie=0xdead,priority=1000,actions=drop"])
    print(f"  Blackhole ACTIVE on {sw}")

def greyhole(sw, pct=50):
    r = subprocess.run(["ovs-vsctl", "list-ports", sw], capture_output=True, text=True)
    for p in r.stdout.strip().split('\n'):
        if p.strip():
            os.system(f"tc qdisc add dev {p.strip()} root netem loss {pct}%")
    print(f"  Greyhole ({pct}%) ACTIVE on {sw}")

def stop(sw):
    subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "del-flows", sw, "cookie=0xdead/-1"])
    r = subprocess.run(["ovs-vsctl", "list-ports", sw], capture_output=True, text=True)
    for p in r.stdout.strip().split('\n'):
        if p.strip():
            os.system(f"tc qdisc del dev {p.strip()} root 2>/dev/null")
    print(f"  Attacks removed from {sw}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 attack.py <blackhole|greyhole|stop> <switch> [drop_%]")
        sys.exit(1)
    act, sw = sys.argv[1], sys.argv[2]
    if act == "blackhole": blackhole(sw)
    elif act == "greyhole": greyhole(sw, int(sys.argv[3]) if len(sys.argv) > 3 else 50)
    elif act == "stop": stop(sw)
    else: print(f"Unknown: {act}")