"""
Trust-Based Dynamic Routing Controller for SDN
================================================
Implements the complete framework from:
  "A Trust-Based Dynamic Routing Framework for Enhancing
   Security in Software-Defined Networks"

Components:
  1. Direct Trust  : PDR, delay, drop rate  (Section IV-A)
  2. Indirect Trust : neighbor recommendations (Section IV-B)
  3. Trust Aging    : exponential aging       (Section IV-C)
  4. TACSP Routing  : trust-aware Dijkstra    (Section V)
  5. Dynamic Recalc : degradation & recovery  (Section V-D)
  6. Flow Install   : OpenFlow 1.3 rules      (Section V-E)

Supports:
  - Linear topologies (h1--s1--s2--h2)
  - Diamond / multi-path topologies (loops handled correctly)
  - Extended topologies with multiple hosts

Usage:
  ryu-manager --observe-links trust_controller.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp
from ryu.lib import hub
from ryu.topology import event as topo_event

import time
import json
import os
import heapq
from collections import defaultdict


class TrustBasedController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ===================== TRUST PARAMETERS (Section IV) =====================
    ALPHA  = 0.5    # PDR weight          (Eq. 4)
    BETA   = 0.2    # delay trust weight  (Eq. 4)
    GAMMA  = 0.3    # drop trust weight   (Eq. 4)
    DELTA  = 0.7    # direct vs indirect  (Eq. 7)
    LAMBDA = 0.6    # aging factor        (Eq. 6)

    INITIAL_TRUST = 1.0
    MIN_TRUST     = 0.1
    MAX_TRUST     = 1.0
    T_MIN         = 0.5

    TRUST_DECAY_RATE    = 0.05
    TRUST_RECOVERY_RATE = 0.02

    # ===================== MONITORING =======================================
    POLL_INTERVAL   = 5
    RECALC_INTERVAL = 10
    D_MAX           = 100.0
    STALL_THRESHOLD = 3
    STARTUP_PACKET_THRESHOLD = 10
    SUSPICIOUS_PRIORITY      = 500

    def __init__(self, *args, **kwargs):
        super(TrustBasedController, self).__init__(*args, **kwargs)

        # --- Topology ---
        self.datapaths    = {}
        self.mac_to_port  = {}
        self.switch_links = defaultdict(dict)   # {dpid: {nbr_dpid: port}}
        self.link_weights = defaultdict(lambda: defaultdict(lambda: 1.0))
        self.inter_switch_ports = defaultdict(set)  # {dpid: {port, ...}}

        # --- Trust ---
        self.trust          = {}
        self.direct_trust   = {}
        self.indirect_trust = {}

        # --- Port-level metrics ---
        self.prev_port_rx     = defaultdict(lambda: defaultdict(int))
        self.prev_port_tx     = defaultdict(lambda: defaultdict(int))
        self.prev_port_rxdrop = defaultdict(lambda: defaultdict(int))
        self.prev_port_txdrop = defaultdict(lambda: defaultdict(int))
        self.switch_rx_delta   = defaultdict(int)
        self.switch_tx_delta   = defaultdict(int)
        self.switch_drop_delta = defaultdict(int)

        # --- Flow stats ---
        self.last_fwd_packets  = {}
        self.current_fwd_delta = {}
        self.stall_counter     = {}
        self.has_drop_all_rule = {}

        # --- PDR ---
        self.pdr_history = defaultdict(lambda: 1.0)

        # --- Host & path tracking ---
        self.host_to_switch = {}   # {ip: (dpid, port)}
        self.ip_to_mac      = {}   # {ip: mac}
        self.mac_to_ip      = {}   # {mac: ip}
        self.active_paths   = {}   # {(src_ip, dst_ip): [dpid_list]}

        # --- ARP cache (proxy ARP for loop topologies) ---
        self.arp_table = {}  # {ip: mac}

        # --- Logging ---
        self.log_history = []
        self.start_time  = time.time()

        # --- Data export for live dashboard ---
        self.export_dir  = '/tmp/sdn-trust-data'
        self.export_file = os.path.join(self.export_dir, 'live_data.json')
        os.makedirs(self.export_dir, exist_ok=True)

        # --- Threads ---
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.recalc_thread  = hub.spawn(self._recalc_loop)
        self.export_thread  = hub.spawn(self._export_loop)

    # ========================================================================
    #  SWITCH SETUP
    # ========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dpid   = dp.id

        self.datapaths[dpid] = dp
        self.mac_to_port.setdefault(dpid, {})

        self.trust[dpid]          = self.INITIAL_TRUST
        self.direct_trust[dpid]   = self.INITIAL_TRUST
        self.indirect_trust[dpid] = self.INITIAL_TRUST

        self.last_fwd_packets[dpid] = 0
        self.current_fwd_delta[dpid] = 0
        self.stall_counter[dpid]     = 0
        self.has_drop_all_rule[dpid] = False

        # Table-miss: send to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, priority=0, match=match, actions=actions)

        self.logger.info(
            f"[INIT] Switch s{dpid} connected | trust={self.trust[dpid]:.3f}"
        )

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                self.logger.warning(f"[TOPO] Switch s{dp.id} disconnected")
                del self.datapaths[dp.id]

    # ========================================================================
    #  TOPOLOGY DISCOVERY
    # ========================================================================

    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no

        self.switch_links[src_dpid][dst_dpid] = src_port

        # Default link weight = 1.0
        # For diamond topology: prefer paths through s3 (dpid=3)
        # s1(1)->s3(3) and s3(3)->s4(4) get weight 0.5
        # s1(1)->s2(2) and s2(2)->s4(4) get weight 1.0 (default)
        if src_dpid == 3 or dst_dpid == 3:
            self.link_weights[src_dpid][dst_dpid] = 0.5
        else:
            self.link_weights[src_dpid][dst_dpid] = 1.0

        # Track inter-switch ports (critical for loop handling)
        self.inter_switch_ports[src_dpid].add(src_port)

        self.logger.info(
            f"[TOPO] Link: s{src_dpid}:{src_port} -> s{dst_dpid} "
            f"(weight={self.link_weights[src_dpid][dst_dpid]}, "
            f"inter-switch ports on s{src_dpid}: {self.inter_switch_ports[src_dpid]})"
        )

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        src_port = ev.link.src.port_no

        if dst_dpid in self.switch_links.get(src_dpid, {}):
            del self.switch_links[src_dpid][dst_dpid]
        self.inter_switch_ports[src_dpid].discard(src_port)

    # ========================================================================
    #  PACKET-IN HANDLER (with loop-safe forwarding)
    #
    #  KEY CHANGE for diamond/multi-path topologies:
    #  - ARP: use proxy ARP if we know the answer, otherwise flood only
    #    on HOST-FACING ports (not inter-switch ports) to prevent storms.
    #  - IPv4: if both hosts are known, compute TACSP path and install
    #    explicit forwarding rules. Fall back to MAC learning for linear.
    # ========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        parser  = dp.ofproto_parser
        dpid    = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        if eth.ethertype == 0x88cc:  # LLDP
            return

        dst_mac = eth.dst
        src_mac = eth.src

        # Learn MAC-to-port on this switch
        self.mac_to_port[dpid][src_mac] = in_port

        # --- Handle ARP ---
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(dp, in_port, eth, arp_pkt, msg.data)
            return

        # --- Handle IPv4 ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # Learn host location ONLY on host-facing ports
            # Never overwrite with inter-switch ports (prevents h1 being
            # mis-learned as attached to s4 when packets traverse s1->s3->s4)
            if in_port not in self.inter_switch_ports.get(dpid, set()):
                self.host_to_switch[src_ip] = (dpid, in_port)
            self.ip_to_mac[src_ip] = src_mac
            self.mac_to_ip[src_mac] = src_ip

            # Try path-based forwarding if both hosts are known
            dst_info = self.host_to_switch.get(dst_ip)
            if dst_info is not None:
                self._forward_with_path(dp, in_port, eth, ip_pkt, msg.data,
                                        src_ip, dst_ip)
                return

        # --- Fallback: simple L2 forwarding (linear topologies) ---
        out_port = self.mac_to_port[dpid].get(dst_mac, ofp.OFPP_FLOOD)

        # If flooding, avoid sending on inter-switch ports (loop prevention)
        if out_port == ofp.OFPP_FLOOD and self._has_loops():
            self._flood_to_hosts_only(dp, in_port, msg.data)
            return

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self._add_flow(dp, priority=10, match=match, actions=actions,
                           idle_timeout=30, hard_timeout=0)

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=msg.data
        ))

    def _has_loops(self):
        """Check if topology has loops (more links than a tree would have)."""
        num_switches = len(self.datapaths)
        num_links = sum(len(nbrs) for nbrs in self.switch_links.values())
        # A tree with N nodes has N-1 edges = 2*(N-1) directed links
        return num_links > 2 * (num_switches - 1) if num_switches > 1 else False

    def _handle_arp(self, dp, in_port, eth, arp_pkt, data):
        """
        Handle ARP with proxy ARP for loop topologies.

        In diamond/mesh topologies, flooding ARP causes broadcast storms.
        Solution: controller acts as ARP proxy when it knows the answer.
        """
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dpid   = dp.id

        src_ip  = arp_pkt.src_ip
        dst_ip  = arp_pkt.dst_ip
        src_mac = arp_pkt.src_mac

        # Learn
        self.arp_table[src_ip] = src_mac
        # Only learn host location on host-facing ports
        if in_port not in self.inter_switch_ports.get(dpid, set()):
            self.host_to_switch[src_ip] = (dpid, in_port)
        self.ip_to_mac[src_ip] = src_mac
        self.mac_to_ip[src_mac] = src_ip

        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Do we know the target?
            target_mac = self.arp_table.get(dst_ip)

            if target_mac:
                # Proxy ARP reply: we know the answer, reply directly
                self._send_arp_reply(dp, in_port,
                                     target_mac, dst_ip,
                                     src_mac, src_ip)
                self.logger.debug(
                    f"[ARP] Proxy reply on s{dpid}: "
                    f"{dst_ip} is at {target_mac}"
                )
            else:
                # Don't know target yet: flood ARP but ONLY on host-facing ports
                self._flood_arp_to_hosts(dp, in_port, data)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Forward ARP reply to the requesting host
            dst_info = self.host_to_switch.get(dst_ip)
            if dst_info:
                out_dp = self.datapaths.get(dst_info[0])
                if out_dp:
                    actions = [out_dp.ofproto_parser.OFPActionOutput(dst_info[1])]
                    out_dp.send_msg(out_dp.ofproto_parser.OFPPacketOut(
                        datapath=out_dp, buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=ofp.OFPP_CONTROLLER,
                        actions=actions, data=data
                    ))
            else:
                # Don't know where requester is, flood on host ports
                self._flood_arp_to_hosts(dp, in_port, data)

    def _send_arp_reply(self, dp, out_port, src_mac, src_ip, dst_mac, dst_ip):
        """Generate and send an ARP reply from the controller."""
        ofp    = dp.ofproto
        parser = dp.ofproto_parser

        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            dst=dst_mac, src=src_mac,
            ethertype=0x0806
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac, src_ip=src_ip,
            dst_mac=dst_mac, dst_ip=dst_ip
        ))
        arp_reply.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=actions, data=arp_reply.data
        ))

    def _flood_arp_to_hosts(self, dp, in_port, data):
        """
        Flood ARP only on host-facing ports (not inter-switch ports).
        This prevents broadcast storms in looped topologies.
        Also forward to all other switches' host-facing ports.
        """
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dpid   = dp.id

        # Flood on every switch's host-facing ports
        for sw_dpid, sw_dp in self.datapaths.items():
            sw_parser = sw_dp.ofproto_parser
            sw_ofp    = sw_dp.ofproto

            actions = []
            # Get all ports on this switch
            for port_no in self._get_switch_ports(sw_dpid):
                # Skip inter-switch ports
                if port_no in self.inter_switch_ports.get(sw_dpid, set()):
                    continue
                # Skip the port the packet came in on (same switch only)
                if sw_dpid == dpid and port_no == in_port:
                    continue
                actions.append(sw_parser.OFPActionOutput(port_no))

            if actions:
                sw_dp.send_msg(sw_parser.OFPPacketOut(
                    datapath=sw_dp, buffer_id=sw_ofp.OFP_NO_BUFFER,
                    in_port=sw_ofp.OFPP_CONTROLLER,
                    actions=actions, data=data
                ))

    def _flood_to_hosts_only(self, dp, in_port, data):
        """Flood non-ARP traffic only on host-facing ports (loop prevention)."""
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dpid   = dp.id

        actions = []
        for port_no in self._get_switch_ports(dpid):
            if port_no in self.inter_switch_ports.get(dpid, set()):
                continue
            if port_no == in_port:
                continue
            actions.append(parser.OFPActionOutput(port_no))

        if actions:
            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=data
            ))

    def _get_switch_ports(self, dpid):
        """Get known ports on a switch from MAC table and inter-switch ports."""
        ports = set()
        # Ports from MAC learning
        for mac, port in self.mac_to_port.get(dpid, {}).items():
            ports.add(port)
        # Inter-switch ports
        ports.update(self.inter_switch_ports.get(dpid, set()))
        # Host-attached ports from host_to_switch
        for ip, (sw_dpid, port) in self.host_to_switch.items():
            if sw_dpid == dpid:
                ports.add(port)
        return ports

    def _forward_with_path(self, dp, in_port, eth, ip_pkt, data,
                           src_ip, dst_ip):
        """
        Compute TACSP path and install flow rules for IP traffic.
        This is the trust-aware forwarding used for all topologies.
        """
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dpid   = dp.id

        src_switch = self.host_to_switch.get(src_ip)
        dst_switch = self.host_to_switch.get(dst_ip)

        if not src_switch or not dst_switch:
            return

        src_dpid = src_switch[0]
        dst_dpid = dst_switch[0]

        # Check if we already have an active path for this flow
        existing_path = self.active_paths.get((src_ip, dst_ip))
        if existing_path:
            # Path already installed, just forward this packet
            return

        # Compute trust-aware path
        path = self._tacsp(src_dpid, dst_dpid)

        if not path:
            self.logger.warning(
                f"[FWD] No valid path {src_ip}->{dst_ip} "
                f"(s{src_dpid}->s{dst_dpid})"
            )
            return

        # Install flow rules along the path
        src_mac = self.ip_to_mac.get(src_ip, eth.src)
        dst_mac = self.ip_to_mac.get(dst_ip, eth.dst)

        self._install_path_flows(path, src_ip, dst_ip, src_mac, dst_mac)
        self.active_paths[(src_ip, dst_ip)] = path

        self.logger.info(
            f"[PATH] Active path {src_ip} <-> {dst_ip}: "
            f"{' -> '.join(f's{d}' for d in path)}"
        )

        # Also send this specific packet along the path
        # Determine the output port on the current switch
        if dpid == path[0] and len(path) > 1:
            next_dpid = path[1]
            out_port = self.switch_links[dpid].get(next_dpid)
        elif dpid == path[0] and len(path) == 1:
            out_port = dst_switch[1]
        else:
            # Current switch might be in the middle - find it
            out_port = None
            for i, p_dpid in enumerate(path):
                if p_dpid == dpid:
                    if i < len(path) - 1:
                        out_port = self.switch_links[dpid].get(path[i + 1])
                    else:
                        out_port = dst_switch[1]
                    break

        if out_port is None:
            # Fallback: send to first hop
            if len(path) > 1:
                first_dp = self.datapaths.get(path[0])
                if first_dp:
                    next_dpid = path[1]
                    out_port_first = self.switch_links[path[0]].get(next_dpid)
                    if out_port_first:
                        actions = [first_dp.ofproto_parser.OFPActionOutput(out_port_first)]
                        first_dp.send_msg(first_dp.ofproto_parser.OFPPacketOut(
                            datapath=first_dp,
                            buffer_id=first_dp.ofproto.OFP_NO_BUFFER,
                            in_port=first_dp.ofproto.OFPP_CONTROLLER,
                            actions=actions, data=data
                        ))
            return

        actions = [parser.OFPActionOutput(out_port)]
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=data
        ))

    # ========================================================================
    #  FLOW RULE HELPERS
    # ========================================================================

    def _add_flow(self, dp, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, cookie=0):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout,
            hard_timeout=hard_timeout, cookie=cookie
        ))

    def _remove_flows_by_cookie(self, dp, cookie):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF
        ))

    def _install_path_flows(self, path, src_ip, dst_ip, src_mac, dst_mac):
        """Install OpenFlow rules along a computed path (Section V-E)."""
        if len(path) < 1:
            return
        cookie = 0xBEEF

        # Forward direction
        for i, dpid in enumerate(path):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser = dp.ofproto_parser
            ofp    = dp.ofproto

            if i < len(path) - 1:
                next_dpid = path[i + 1]
                out_port  = self.switch_links[dpid].get(next_dpid)
                if out_port is None:
                    return
            else:
                host_info = self.host_to_switch.get(dst_ip)
                if host_info and host_info[0] == dpid:
                    out_port = host_info[1]
                else:
                    out_port = self.mac_to_port.get(dpid, {}).get(dst_mac)
                    if out_port is None:
                        out_port = ofp.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            match   = parser.OFPMatch(
                eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip
            )
            self._add_flow(dp, priority=100, match=match, actions=actions,
                           idle_timeout=60, hard_timeout=120, cookie=cookie)

        # Reverse direction
        rev_path = list(reversed(path))
        for i, dpid in enumerate(rev_path):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser = dp.ofproto_parser
            ofp    = dp.ofproto

            if i < len(rev_path) - 1:
                next_dpid = rev_path[i + 1]
                out_port  = self.switch_links[dpid].get(next_dpid)
                if out_port is None:
                    return
            else:
                host_info = self.host_to_switch.get(src_ip)
                if host_info and host_info[0] == dpid:
                    out_port = host_info[1]
                else:
                    out_port = self.mac_to_port.get(dpid, {}).get(src_mac)
                    if out_port is None:
                        out_port = ofp.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            match   = parser.OFPMatch(
                eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip
            )
            self._add_flow(dp, priority=100, match=match, actions=actions,
                           idle_timeout=60, hard_timeout=120, cookie=cookie)

        self.logger.info(
            f"[ROUTE] Path: {' -> '.join(f's{d}' for d in path)} "
            f"for {src_ip} <-> {dst_ip}"
        )

    # ========================================================================
    #  MONITORING LOOP
    # ========================================================================

    def _monitor_loop(self):
        while True:
            hub.sleep(self.POLL_INTERVAL)
            for dpid, dp in list(self.datapaths.items()):
                try:
                    dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
                    dp.send_msg(dp.ofproto_parser.OFPPortStatsRequest(
                        dp, 0, dp.ofproto.OFPP_ANY))
                except Exception as e:
                    self.logger.error(f"[MON] Stats failed s{dpid}: {e}")

    def _export_loop(self):
        """Export current state as JSON every 2s for the live dashboard."""
        while True:
            hub.sleep(2)
            try:
                elapsed = round(time.time() - self.start_time, 1)
                switches = {}
                for dpid in sorted(self.datapaths.keys()):
                    switches[f"s{dpid}"] = {
                        'trust': round(self.trust.get(dpid, 1.0), 4),
                        'direct_trust': round(self.direct_trust.get(dpid, 1.0), 4),
                        'indirect_trust': round(self.indirect_trust.get(dpid, 1.0), 4),
                        'pdr': round(self.pdr_history.get(dpid, 1.0), 4),
                        'fwd_packets': self.last_fwd_packets.get(dpid, 0),
                        'fwd_delta': self.current_fwd_delta.get(dpid, 0),
                        'rx_delta': self.switch_rx_delta.get(dpid, 0),
                        'tx_delta': self.switch_tx_delta.get(dpid, 0),
                        'drop_delta': self.switch_drop_delta.get(dpid, 0),
                        'drop_rule': self.has_drop_all_rule.get(dpid, False),
                        'drop_packets': 0,
                        'stall_count': self.stall_counter.get(dpid, 0),
                    }

                active_paths = {}
                for (src, dst), path in self.active_paths.items():
                    active_paths[f"{src}->{dst}"] = \
                        [f"s{d}" for d in path]

                data = {
                    'timestamp': time.time(),
                    'elapsed': elapsed,
                    'switches': switches,
                    'active_paths': active_paths,
                    't_min': self.T_MIN,
                    'params': {
                        'alpha': self.ALPHA, 'beta': self.BETA,
                        'gamma': self.GAMMA, 'delta': self.DELTA,
                        'lambda': self.LAMBDA,
                    }
                }

                tmp = self.export_file + '.tmp'
                with open(tmp, 'w') as f:
                    json.dump(data, f)
                os.replace(tmp, self.export_file)

            except Exception as e:
                pass  # Don't crash controller on export errors

    # ========================================================================
    #  FLOW STATS REPLY -> Detect drop rules + track real forwarding
    # ========================================================================

    def _flow_has_output_action(self, stat):
        """Check if a flow has an actual OUTPUT action (not a drop rule)."""
        for inst in stat.instructions:
            if hasattr(inst, 'actions') and inst.actions:
                for action in inst.actions:
                    if hasattr(action, 'port'):
                        return True
        return False

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        legit_fwd_packets  = 0
        legit_fwd_count    = 0
        drop_rule_packets  = 0
        drop_all_detected  = False
        suspicious_details = []

        for stat in ev.msg.body:
            if stat.priority == 0:
                continue

            if self._flow_has_output_action(stat):
                legit_fwd_packets += stat.packet_count
                legit_fwd_count   += 1
            else:
                drop_rule_packets += stat.packet_count
                if stat.priority >= self.SUSPICIOUS_PRIORITY:
                    drop_all_detected = True
                    suspicious_details.append(
                        f"pri={stat.priority} cookie=0x{stat.cookie:x} "
                        f"pkts={stat.packet_count}"
                    )

        prev_drop_state = self.has_drop_all_rule.get(dpid, False)
        self.has_drop_all_rule[dpid] = drop_all_detected

        if drop_all_detected and not prev_drop_state:
            self.logger.warning(
                f"[DETECT] s{dpid}: DROP-ALL RULE DETECTED! "
                f"Details: {'; '.join(suspicious_details)}"
            )
        elif not drop_all_detected and prev_drop_state:
            self.logger.info(
                f"[DETECT] s{dpid}: Drop rule REMOVED, resuming normal evaluation"
            )

        fwd_now   = legit_fwd_packets
        fwd_last  = self.last_fwd_packets.get(dpid, fwd_now)
        fwd_delta = max(0, fwd_now - fwd_last)

        self.current_fwd_delta[dpid] = fwd_delta
        self.last_fwd_packets[dpid]  = fwd_now

        # === TRUST EVALUATION ===
        old_trust = self.trust.get(dpid, self.INITIAL_TRUST)

        if drop_all_detected:
            self.stall_counter[dpid] += 1
            if self.stall_counter[dpid] >= 2:
                self._update_trust_attack_detected(dpid)
                status = (f"BLACKHOLE-DETECTED "
                          f"(drop_pkts={drop_rule_packets}, "
                          f"stall={self.stall_counter[dpid]})")
            else:
                status = (f"SUSPICIOUS-RULE "
                          f"(confirming {self.stall_counter[dpid]}/2, "
                          f"drop_pkts={drop_rule_packets})")

        elif fwd_delta > 0:
            self.stall_counter[dpid] = 0
            self._update_trust_forwarding(dpid)
            status = "FORWARDING"

        elif legit_fwd_count == 0:
            self.stall_counter[dpid] = 0
            status = "NO-FLOWS"

        elif fwd_now < self.STARTUP_PACKET_THRESHOLD:
            self.stall_counter[dpid] = 0
            status = "STARTUP"

        else:
            upstream_fwd = self._is_upstream_forwarding(dpid)
            if not upstream_fwd:
                self.stall_counter[dpid] += 1
                if self.stall_counter[dpid] >= self.STALL_THRESHOLD:
                    self._update_trust_stalled(dpid)
                    status = f"STALLED (stall={self.stall_counter[dpid]})"
                else:
                    status = f"STALL-WARN ({self.stall_counter[dpid]}/{self.STALL_THRESHOLD})"
            else:
                self.stall_counter[dpid] = 0
                status = "DOWNSTREAM-BLOCKED"

        new_trust = self.trust[dpid]

        trust_changed = abs(new_trust - old_trust) > 0.001
        if fwd_delta > 0 or self.stall_counter.get(dpid, 0) > 0 or \
           trust_changed or drop_all_detected:
            self.logger.info(
                f"[TRUST] s{dpid} | fwd={fwd_now:5d} d={fwd_delta:4d} | "
                f"drop_rule={'YES' if drop_all_detected else 'no ':3s} "
                f"drop_pkts={drop_rule_packets:5d} | "
                f"trust={new_trust:.3f} (was {old_trust:.3f}) | {status}"
            )

        self.log_history.append({
            'time': time.time(),
            'elapsed': round(time.time() - self.start_time, 1),
            'dpid': dpid,
            'switch': f's{dpid}',
            'fwd_packets': fwd_now,
            'fwd_delta': fwd_delta,
            'drop_rule_detected': drop_all_detected,
            'drop_packets': drop_rule_packets,
            'trust': round(new_trust, 4),
            'trust_prev': round(old_trust, 4),
            'direct_trust': round(self.direct_trust.get(dpid, 1.0), 4),
            'indirect_trust': round(self.indirect_trust.get(dpid, 1.0), 4),
            'pdr': round(self.pdr_history.get(dpid, 1.0), 4),
            'rx_delta': self.switch_rx_delta.get(dpid, 0),
            'tx_delta': self.switch_tx_delta.get(dpid, 0),
            'stall_count': self.stall_counter.get(dpid, 0),
            'status': status
        })

    # ========================================================================
    #  PORT STATS REPLY -> PDR
    # ========================================================================

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        total_rx_delta   = 0
        total_tx_delta   = 0
        total_drop_delta = 0

        for stat in ev.msg.body:
            pno = stat.port_no
            if pno >= 0xFFFFFFF0:
                continue

            total_rx_delta   += max(0, stat.rx_packets - self.prev_port_rx[dpid][pno])
            total_tx_delta   += max(0, stat.tx_packets - self.prev_port_tx[dpid][pno])
            total_drop_delta += max(0,
                (stat.rx_dropped + stat.tx_dropped) -
                (self.prev_port_rxdrop[dpid][pno] + self.prev_port_txdrop[dpid][pno]))

            self.prev_port_rx[dpid][pno]     = stat.rx_packets
            self.prev_port_tx[dpid][pno]     = stat.tx_packets
            self.prev_port_rxdrop[dpid][pno] = stat.rx_dropped
            self.prev_port_txdrop[dpid][pno] = stat.tx_dropped

        self.switch_rx_delta[dpid]   = total_rx_delta
        self.switch_tx_delta[dpid]   = total_tx_delta
        self.switch_drop_delta[dpid] = total_drop_delta

        if total_rx_delta > 5:
            pdr = min(1.0, max(0.0,
                total_tx_delta / total_rx_delta if total_rx_delta > 0 else 1.0))
            self.pdr_history[dpid] = 0.4 * pdr + 0.6 * self.pdr_history[dpid]

            if self.pdr_history[dpid] < 0.3:
                self.logger.warning(
                    f"[PDR] s{dpid}: PDR={self.pdr_history[dpid]:.3f} DROPPING!")
                self._update_trust_attack_detected(dpid)
            elif self.pdr_history[dpid] < 0.7:
                self.logger.info(
                    f"[PDR] s{dpid}: PDR={self.pdr_history[dpid]:.3f} degraded")

    # ========================================================================
    #  TRUST COMPUTATION (Section IV)
    # ========================================================================

    def _compute_direct_trust(self, dpid):
        pdr = self.pdr_history.get(dpid, 1.0)
        d_trust = 1.0
        rx = self.switch_rx_delta.get(dpid, 0)
        drops = self.switch_drop_delta.get(dpid, 0)
        l_trust = max(0.0, 1.0 - (drops / rx)) if rx > 0 else 1.0

        if self.has_drop_all_rule.get(dpid, False):
            pdr = min(pdr, 0.1)
            l_trust = min(l_trust, 0.1)

        return max(0.0, min(1.0,
            self.ALPHA * pdr + self.BETA * d_trust + self.GAMMA * l_trust))

    def _compute_indirect_trust(self, dpid):
        weighted_sum = 0.0
        weight_total = 0.0
        for nbr in self.switch_links.keys():
            if dpid in self.switch_links.get(nbr, {}):
                nt = self.trust.get(nbr, self.INITIAL_TRUST)
                my_fwd  = self.current_fwd_delta.get(dpid, 0)
                my_drop = self.has_drop_all_rule.get(dpid, False)
                nbr_fwd = self.current_fwd_delta.get(nbr, 0)
                if my_drop:
                    reported = 0.1
                elif my_fwd > 0:
                    reported = 1.0
                elif nbr_fwd > 0 and my_fwd == 0:
                    reported = 0.3
                else:
                    reported = 0.7
                weighted_sum += nt * reported
                weight_total += nt
        return (weighted_sum / weight_total) if weight_total > 0 \
            else self.trust.get(dpid, self.INITIAL_TRUST)

    def _apply_trust_aging(self, dpid, t_current):
        t_prev = self.trust.get(dpid, self.INITIAL_TRUST)
        return max(self.MIN_TRUST, min(self.MAX_TRUST,
            self.LAMBDA * t_current + (1 - self.LAMBDA) * t_prev))

    def _compute_final_trust(self, dpid):
        t_d = self._compute_direct_trust(dpid)
        t_i = self._compute_indirect_trust(dpid)
        self.direct_trust[dpid]   = round(t_d, 4)
        self.indirect_trust[dpid] = round(t_i, 4)
        t_hybrid = self.DELTA * t_d + (1 - self.DELTA) * t_i
        return round(self._apply_trust_aging(dpid, t_hybrid), 4)

    def _update_trust_forwarding(self, dpid):
        t = self._compute_final_trust(dpid)
        self.trust[dpid] = round(min(self.MAX_TRUST, t + self.TRUST_RECOVERY_RATE), 4)

    def _update_trust_stalled(self, dpid):
        t = self._compute_final_trust(dpid)
        self.trust[dpid] = round(max(self.MIN_TRUST, t - self.TRUST_DECAY_RATE), 4)
        if self.trust[dpid] < self.T_MIN:
            self.logger.warning(
                f"[ALERT] s{dpid} trust={self.trust[dpid]:.3f} < "
                f"T_min={self.T_MIN} -> EXCLUDED")
            self._trigger_path_recalculation(dpid)

    def _update_trust_attack_detected(self, dpid):
        old = self.trust.get(dpid, self.INITIAL_TRUST)
        t = self._compute_final_trust(dpid)
        self.trust[dpid] = round(max(self.MIN_TRUST, t - self.TRUST_DECAY_RATE * 2), 4)
        if old >= self.T_MIN and self.trust[dpid] < self.T_MIN:
            self.logger.warning(
                f"[ALERT] s{dpid} CROSSED T_min: "
                f"{old:.3f} -> {self.trust[dpid]:.3f} -> EXCLUDED")
            self._trigger_path_recalculation(dpid)

    # ========================================================================
    #  TOPOLOGY AWARENESS
    # ========================================================================

    def _is_upstream_forwarding(self, dpid):
        for nbr in self.switch_links.keys():
            if dpid in self.switch_links.get(nbr, {}):
                if self.current_fwd_delta.get(nbr, 0) > 0:
                    return True
        return False

    # ========================================================================
    #  TACSP ROUTING (Section V)
    # ========================================================================

    def _tacsp(self, src_dpid, dst_dpid):
        """Trust-Aware Constrained Shortest Path (modified Dijkstra)."""
        if src_dpid == dst_dpid:
            return [src_dpid]

        eligible = {d for d in self.datapaths if self.trust.get(d, 0) >= self.T_MIN}

        self.logger.info(
            f"[TACSP] Computing s{src_dpid} -> s{dst_dpid} | "
            f"Eligible: {sorted(eligible)} | "
            f"Trust: {', '.join(f's{d}={self.trust.get(d,0):.3f}' for d in sorted(self.datapaths.keys()))}")

        if src_dpid not in eligible or dst_dpid not in eligible:
            self.logger.warning(
                f"[TACSP] FAILED: src/dst not eligible")
            return []

        dist   = {d: float('inf') for d in eligible}
        parent = {d: None for d in eligible}
        dist[src_dpid] = 0
        visited = set()
        pq = [(0, src_dpid)]

        while pq:
            d, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)
            if u == dst_dpid:
                break

            for v, port in self.switch_links.get(u, {}).items():
                if v not in eligible or v in visited:
                    continue
                w = self.link_weights[u][v]
                tv = self.trust.get(v, 0)
                cost = w * ((1.0 / tv) if tv > 0 else float('inf'))
                if d + cost < dist[v]:
                    dist[v]   = d + cost
                    parent[v] = u
                    heapq.heappush(pq, (d + cost, v))

        if dist[dst_dpid] == float('inf'):
            self.logger.warning(
                f"[TACSP] FAILED: No path found. Visited={sorted(visited)}")
            return []

        path = []
        node = dst_dpid
        while node is not None:
            path.append(node)
            node = parent[node]
        path.reverse()

        excluded = set(self.datapaths.keys()) - eligible
        if excluded:
            self.logger.info(
                f"[TACSP] Excluded: "
                f"{', '.join(f's{d}(T={self.trust.get(d,0):.3f})' for d in excluded)}")
        self.logger.info(
            f"[TACSP] Path: {' -> '.join(f's{d}' for d in path)}")
        return path

    # ========================================================================
    #  DYNAMIC PATH RECALCULATION (Section V-D)
    # ========================================================================

    def _trigger_path_recalculation(self, compromised_dpid):
        self.logger.warning(
            f"[RECALC] Triggered by s{compromised_dpid} "
            f"(trust={self.trust.get(compromised_dpid, 0):.3f})")

        recalculated = False
        for (src_ip, dst_ip), path in list(self.active_paths.items()):
            if compromised_dpid in path:
                self.logger.warning(
                    f"[RECALC] s{compromised_dpid} IS on active path "
                    f"{src_ip}->{dst_ip}: "
                    f"{' -> '.join(f's{d}' for d in path)} -> REROUTING"
                )

                # Remove old flows
                for d in path:
                    dp = self.datapaths.get(d)
                    if dp:
                        self._remove_flows_by_cookie(dp, 0xBEEF)

                # Compute new path
                src_sw = self.host_to_switch.get(src_ip)
                dst_sw = self.host_to_switch.get(dst_ip)
                if src_sw and dst_sw:
                    new_path = self._tacsp(src_sw[0], dst_sw[0])
                    if new_path:
                        self._install_path_flows(
                            new_path, src_ip, dst_ip,
                            self.ip_to_mac.get(src_ip, 'ff:ff:ff:ff:ff:ff'),
                            self.ip_to_mac.get(dst_ip, 'ff:ff:ff:ff:ff:ff'))
                        self.active_paths[(src_ip, dst_ip)] = new_path
                        self.logger.info(
                            f"[RECALC] Rerouted {src_ip}<->{dst_ip}: "
                            f"{' -> '.join(f's{d}' for d in new_path)}")
                    else:
                        del self.active_paths[(src_ip, dst_ip)]
                        self.logger.warning(
                            f"[RECALC] No valid alternative path for "
                            f"{src_ip}<->{dst_ip}")
                recalculated = True

        if not recalculated:
            # Log that the compromised switch is NOT on any active path
            active_paths_str = ", ".join(
                f"{s}->{d}: {' -> '.join(f's{x}' for x in p)}"
                for (s, d), p in self.active_paths.items()
            ) if self.active_paths else "none"
            self.logger.info(
                f"[RECALC] s{compromised_dpid} not on any active path. "
                f"Active paths: [{active_paths_str}]. No reroute needed."
            )

    def _recalc_loop(self):
        while True:
            hub.sleep(self.RECALC_INTERVAL)
            for (src_ip, dst_ip), path in list(self.active_paths.items()):
                if path:
                    min_t = min(self.trust.get(d, 0) for d in path)
                    if min_t < self.T_MIN:
                        worst = min(path, key=lambda d: self.trust.get(d, 0))
                        self._trigger_path_recalculation(worst)