#!/usr/bin/env python3
"""
Trust-Based SDN Topology + Attack CLI
Usage: sudo python3 topology.py [linear|diamond]

Scenarios:
  scenario1          - Normal operation (ping test)
  scenario2 [switch] - Blackhole attack (manual start/stop)
  scenario3 [switch] - Greyhole attack (manual start/stop)

Attacks:
  blackhole <switch>       - Drop all packets
  greyhole <switch> [%]    - Random packet drop (default 50%)
  stop <switch>            - Remove all attacks
  showflows <switch>       - Show flow table
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os, sys, time


def create_linear(net):
    """h1 -- s1 -- s2 -- h2"""
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    net.addLink(h1, s1); net.addLink(s1, s2); net.addLink(s2, h2)
    return [s1, s2]


def create_diamond(net):
    """h1--s1--(s2,s3)--s4--h2"""
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    net.addLink(h1, s1); net.addLink(s1, s2); net.addLink(s1, s3)
    net.addLink(s2, s4); net.addLink(s3, s4); net.addLink(s4, h2)
    return [s1, s2, s3, s4]


class TrustCLI(CLI):

    def do_blackhole(self, line):
        """blackhole <switch> - Install drop-all rule"""
        sw = line.strip()
        if not sw: info("Usage: blackhole <switch>\n"); return
        info(f"\n  BLACKHOLE on {sw}...\n")
        os.system(f"ovs-ofctl -O OpenFlow13 add-flow {sw} cookie=0xdead,priority=1000,actions=drop")
        info(f"  Attack ACTIVE on {sw}\n\n")

    def do_greyhole(self, line):
        """greyhole <switch> [%] - Random packet drop"""
        parts = line.strip().split()
        if not parts: info("Usage: greyhole <switch> [%]\n"); return
        sw, pct = parts[0], int(parts[1]) if len(parts) > 1 else 50
        info(f"\n  GREYHOLE on {sw} ({pct}% drop)...\n")
        node = self.mn.get(sw)
        if node:
            for intf in node.intfList():
                if str(intf) != 'lo':
                    node.cmd(f"tc qdisc add dev {intf} root netem loss {pct}%")
        info(f"  Attack ACTIVE on {sw}\n\n")

    def do_stop(self, line):
        """stop <switch> - Remove all attacks"""
        sw = line.strip()
        if not sw: info("Usage: stop <switch>\n"); return
        os.system(f"ovs-ofctl -O OpenFlow13 del-flows {sw} cookie=0xdead/-1")
        node = self.mn.get(sw)
        if node:
            for intf in node.intfList():
                if str(intf) != 'lo':
                    node.cmd(f"tc qdisc del dev {intf} root 2>/dev/null")
        info(f"  Attacks removed from {sw}\n\n")

    def do_showflows(self, line):
        """showflows <switch> - Show flow rules"""
        sw = line.strip()
        if sw: os.system(f"ovs-ofctl -O OpenFlow13 dump-flows {sw}")

    def do_showallflows(self, line):
        """Show flows on all switches"""
        for sw in self.mn.switches:
            info(f"\n  [{sw.name}]:\n")
            os.system(f"ovs-ofctl -O OpenFlow13 dump-flows {sw.name}")

    def do_scenario1(self, line):
        """Normal operation - verify connectivity and stable trust"""
        info("\n" + "="*60 + "\n  SCENARIO 1: Normal Operation\n" + "="*60 + "\n")
        h1 = self.mn.get('h1')
        info("  Sending 20 pings...\n")
        info(h1.cmd('ping -c 20 -i 0.5 10.0.0.2'))
        info("\n  Done. All switches should show trust ~ 1.0\n" + "="*60 + "\n\n")

    def do_scenario2(self, line):
        """Blackhole attack - manual start/stop. Usage: scenario2 [switch]"""
        target = line.strip() or 's1'
        info("\n" + "="*60 + "\n")
        info(f"  SCENARIO 2: Blackhole Attack ({target})\n")
        info("="*60 + "\n")
        info("  Steps:\n")
        info("    1. h1 ping -i 0.5 10.0.0.2 &    (start background ping)\n")
        info(f"    2. blackhole {target}             (inject attack)\n")
        info(f"    3. Watch trust decay in controller terminal\n")
        info(f"    4. stop {target}                  (remove attack)\n")
        info(f"    5. Watch trust recovery\n")
        info("="*60 + "\n\n")

    def do_scenario3(self, line):
        """Greyhole attack - manual start/stop. Usage: scenario3 [switch] [%]"""
        parts = line.strip().split()
        target = parts[0] if parts else 's1'
        pct = parts[1] if len(parts) > 1 else '50'
        info("\n" + "="*60 + "\n")
        info(f"  SCENARIO 3: Greyhole Attack ({target}, {pct}% drop)\n")
        info("="*60 + "\n")
        info("  Steps:\n")
        info("    1. h1 ping -i 0.5 10.0.0.2 &    (start background ping)\n")
        info(f"    2. greyhole {target} {pct}          (inject attack)\n")
        info(f"    3. Watch trust decay / PDR drop in controller\n")
        info(f"    4. stop {target}                  (remove attack)\n")
        info(f"    5. Watch trust recovery\n")
        info("="*60 + "\n\n")


def run():
    topo = sys.argv[1].lower() if len(sys.argv) > 1 else 'linear'
    if topo not in ['linear', 'diamond']:
        print(f"Usage: sudo python3 topology.py [linear|diamond]"); sys.exit(1)

    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    switches = create_diamond(net) if topo == 'diamond' else create_linear(net)

    net.start()
    time.sleep(3)
    net.ping([net.get('h1'), net.get('h2')], timeout='2')

    info(f"\n{'='*60}\n  Ready! ({topo}, {len(switches)} switches)\n")
    info("  scenario1 | scenario2 [sw] | scenario3 [sw] [%]\n")
    info(f"  blackhole <sw> | greyhole <sw> [%] | stop <sw>\n{'='*60}\n\n")

    TrustCLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()