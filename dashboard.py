#!/usr/bin/env python3
"""
Trust-Based SDN Live Monitoring Dashboard
==========================================
Reads live data exported by the Ryu controller (/tmp/sdn-trust-data/)
and generates IEEE-quality graph snapshots as PNG files.

NO GUI required — uses matplotlib Agg backend. Works inside ryu-env
or any headless environment. Just open the generated PNGs.

Output:
  monitoring/graphs/       - Auto-saved PNG snapshots
  monitoring/graphs/latest.png  - Always the most recent snapshot
  monitoring/logs/         - CSV log files with all readings

Usage:
  python3 monitoring/dashboard.py --topology linear
  python3 monitoring/dashboard.py --topology diamond --interval 10

Then open monitoring/graphs/latest.png in any image viewer:
  eog monitoring/graphs/latest.png          (GNOME, auto-refreshes)
  feh --reload 5 monitoring/graphs/latest.png
  xdg-open monitoring/graphs/latest.png
"""

import json
import os
import sys
import time
import csv
import argparse
from datetime import datetime
from collections import defaultdict

# Non-interactive backend — no tkinter/Qt/X11 needed
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


# ============================================================================
#  CONFIGURATION
# ============================================================================

DATA_FILE = '/tmp/sdn-trust-data/live_data.json'

# IEEE-quality figure settings
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'DejaVu Serif', 'serif'],
    'font.size': 9,
    'axes.titlesize': 10,
    'axes.titleweight': 'bold',
    'axes.labelsize': 9,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 7,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.facecolor': 'white',
    'axes.grid': True,
    'grid.alpha': 0.3,
    'grid.linewidth': 0.5,
    'lines.linewidth': 1.5,
    'lines.markersize': 4,
})

# Per-switch styles (distinguishable even in B&W print)
SWITCH_STYLES = {
    's1': {'color': '#0072B2', 'marker': 'o',  'ls': '-'},
    's2': {'color': '#009E73', 'marker': 's',  'ls': '--'},
    's3': {'color': '#D55E00', 'marker': '^',  'ls': '-.'},
    's4': {'color': '#CC79A7', 'marker': 'D',  'ls': ':'},
}
T_MIN_COLOR = '#CC0000'


# ============================================================================
#  DATA COLLECTOR
# ============================================================================

class DataCollector:
    """Collects time-series data from controller JSON exports."""

    def __init__(self):
        self.times = []
        self.trust_history = defaultdict(list)
        self.pdr_history = defaultdict(list)
        self.fwd_history = defaultdict(list)
        self.rx_history = defaultdict(list)
        self.tx_history = defaultdict(list)
        self.current = None
        self.switches = []
        self.events = []
        self._prev_states = {}
        self._last_mtime = 0

    def poll(self):
        """Read JSON file, return True if new data was added."""
        try:
            if not os.path.exists(DATA_FILE):
                return False
            mtime = os.path.getmtime(DATA_FILE)
            if mtime == self._last_mtime:
                return False
            self._last_mtime = mtime

            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError, OSError):
            return False

        self.current = data
        elapsed = data['elapsed']
        switches = data.get('switches', {})
        self.switches = sorted(switches.keys())

        # Skip duplicate timestamps
        if self.times and abs(elapsed - self.times[-1]) < 1.0:
            return False

        self.times.append(elapsed)

        for sw in self.switches:
            info = switches[sw]
            self.trust_history[sw].append(info['trust'])
            self.pdr_history[sw].append(info['pdr'])
            self.fwd_history[sw].append(info['fwd_packets'])
            self.rx_history[sw].append(info['rx_delta'])
            self.tx_history[sw].append(info['tx_delta'])

            # Detect events for graph annotations
            prev = self._prev_states.get(sw, {})
            t_min = data.get('t_min', 0.5)
            if info['drop_rule'] and not prev.get('drop_rule', False):
                self.events.append((elapsed, f'{sw.upper()} ATTACK'))
            elif not info['drop_rule'] and prev.get('drop_rule', False):
                self.events.append((elapsed, f'{sw.upper()} RECOVERED'))
            if info['trust'] < t_min and prev.get('trust', 1.0) >= t_min:
                self.events.append((elapsed, f'{sw.upper()} EXCLUDED'))
            self._prev_states[sw] = info.copy()

        # Pad if a switch appeared late
        for sw in self.switches:
            while len(self.trust_history[sw]) < len(self.times):
                self.trust_history[sw].insert(0, 1.0)
                self.pdr_history[sw].insert(0, 1.0)
                self.fwd_history[sw].insert(0, 0)
                self.rx_history[sw].insert(0, 0)
                self.tx_history[sw].insert(0, 0)

        return True


# ============================================================================
#  CSV LOGGER
# ============================================================================

class CSVLogger:
    """Logs all readings to CSV for IEEE paper tables."""

    COLUMNS = [
        'timestamp', 'elapsed_s', 'switch',
        'trust_score', 'direct_trust', 'indirect_trust',
        'pdr', 'fwd_packets', 'fwd_delta',
        'rx_delta', 'tx_delta', 'drop_delta',
        'drop_rule_active', 'stall_count', 'active_path'
    ]

    def __init__(self, log_dir):
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.filepath = os.path.join(log_dir, f'trust_log_{ts}.csv')
        self._file = open(self.filepath, 'w', newline='')
        self._writer = csv.DictWriter(self._file, fieldnames=self.COLUMNS)
        self._writer.writeheader()
        self._file.flush()
        self._last_elapsed = -1

    def log(self, data):
        if data is None:
            return
        elapsed = data['elapsed']
        if elapsed == self._last_elapsed:
            return
        self._last_elapsed = elapsed

        switches = data.get('switches', {})
        paths = data.get('active_paths', {})
        path_str = '; '.join(f"{k}: {' -> '.join(v)}" for k, v in paths.items())

        for sw_name in sorted(switches.keys()):
            sw = switches[sw_name]
            self._writer.writerow({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'elapsed_s': elapsed,
                'switch': sw_name,
                'trust_score': sw['trust'],
                'direct_trust': sw['direct_trust'],
                'indirect_trust': sw['indirect_trust'],
                'pdr': sw['pdr'],
                'fwd_packets': sw['fwd_packets'],
                'fwd_delta': sw['fwd_delta'],
                'rx_delta': sw['rx_delta'],
                'tx_delta': sw['tx_delta'],
                'drop_delta': sw['drop_delta'],
                'drop_rule_active': sw['drop_rule'],
                'stall_count': sw['stall_count'],
                'active_path': path_str,
            })
        self._file.flush()

    def close(self):
        self._file.close()


# ============================================================================
#  GRAPH GENERATOR
# ============================================================================

def generate_dashboard(d, topology, graph_dir, snapshot_num):
    """Generate a 4-panel IEEE-quality dashboard PNG."""
    if not d.times or not d.switches:
        return None

    elapsed = d.current['elapsed'] if d.current else d.times[-1]
    t_min = d.current.get('t_min', 0.5) if d.current else 0.5
    topo_label = 'Diamond' if topology == 'diamond' else 'Linear'

    fig = plt.figure(figsize=(10, 8.5))
    fig.patch.set_facecolor('white')

    gs = fig.add_gridspec(3, 2, height_ratios=[1.2, 0.9, 1.0],
                          hspace=0.50, wspace=0.35,
                          left=0.09, right=0.95, top=0.91, bottom=0.06)

    ax_trust   = fig.add_subplot(gs[0, :])
    ax_bar     = fig.add_subplot(gs[1, 0])
    ax_packets = fig.add_subplot(gs[1, 1])
    ax_pdr     = fig.add_subplot(gs[2, :])

    fig.suptitle(
        f'Trust-Based SDN Monitoring Dashboard  \u2014  '
        f'{topo_label} Topology  (T = {elapsed:.1f}s)',
        fontsize=12, fontweight='bold', y=0.97)

    # ---- Plot 1: Trust Score Evolution (top, full width) ----
    for sw in d.switches:
        style = SWITCH_STYLES.get(sw, {'color': 'gray', 'marker': 'x', 'ls': '-'})
        t = d.times[:len(d.trust_history[sw])]
        ax_trust.plot(t, d.trust_history[sw],
                      color=style['color'], linestyle=style['ls'],
                      marker=style['marker'],
                      markevery=max(1, len(t) // 15),
                      label=sw.upper(), zorder=3)

    ax_trust.axhline(y=t_min, color=T_MIN_COLOR, linestyle='--',
                     linewidth=1.2,
                     label=f'Trust Threshold ($T_{{min}}$={t_min})',
                     zorder=2)

    # Event annotations
    for evt_t, evt_text in d.events:
        if 'ATTACK' in evt_text:
            ax_trust.axvline(x=evt_t, color='red', alpha=0.5, linewidth=0.8)
            ax_trust.annotate(evt_text, (evt_t, 0.05), fontsize=6,
                              color='red', rotation=90,
                              ha='right', va='bottom')
        elif 'RECOVERED' in evt_text:
            ax_trust.axvline(x=evt_t, color='green', alpha=0.5, linewidth=0.8)
            ax_trust.annotate(evt_text, (evt_t, 0.05), fontsize=6,
                              color='green', rotation=90,
                              ha='right', va='bottom')

    ax_trust.set_xlim(left=max(0, d.times[0] - 2))
    ax_trust.set_ylim(-0.05, 1.15)
    ax_trust.set_xlabel('Time (seconds)')
    ax_trust.set_ylabel('Trust Score')
    ax_trust.set_title('Trust Score Evolution')
    ax_trust.legend(loc='lower left',
                    ncol=min(len(d.switches) + 1, 6),
                    framealpha=0.9, edgecolor='gray')

    # ---- Plot 2: Current Trust Status (middle-left, bar chart) ----
    trusts = [d.trust_history[sw][-1] if d.trust_history[sw] else 1.0
              for sw in d.switches]
    colors = []
    for t in trusts:
        if t >= 0.8:
            colors.append('#2ca02c')    # green = healthy
        elif t >= t_min:
            colors.append('#ff7f0e')    # orange = warning
        else:
            colors.append('#d62728')    # red = compromised

    x = np.arange(len(d.switches))
    bars = ax_bar.bar(x, trusts, color=colors, edgecolor='black',
                      linewidth=0.5, width=0.6, zorder=3)
    for bar, t in zip(bars, trusts):
        ax_bar.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.02,
                    f'{t:.2f}', ha='center', va='bottom',
                    fontsize=7, fontweight='bold')

    ax_bar.axhline(y=t_min, color=T_MIN_COLOR, linestyle='--', linewidth=1.0)
    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels([s.upper() for s in d.switches])
    ax_bar.set_ylim(0, 1.25)
    ax_bar.set_ylabel('Trust Score')
    ax_bar.set_title('Current Trust Status')

    # ---- Plot 3: Packet Statistics (middle-right, grouped bar) ----
    tx_vals = [d.tx_history[sw][-1] if d.tx_history[sw] else 0
               for sw in d.switches]
    rx_vals = [d.rx_history[sw][-1] if d.rx_history[sw] else 0
               for sw in d.switches]

    w = 0.3
    ax_packets.bar(x - w/2, tx_vals, w, color='#1f77b4',
                   edgecolor='black', linewidth=0.5,
                   label='TX', zorder=3)
    ax_packets.bar(x + w/2, rx_vals, w, color='#2ca02c',
                   edgecolor='black', linewidth=0.5,
                   label='RX', zorder=3)
    ax_packets.set_xticks(x)
    ax_packets.set_xticklabels([s.upper() for s in d.switches])
    ax_packets.set_ylabel('Packet Count (delta)')
    ax_packets.set_title('Packet Statistics')
    ax_packets.legend(loc='upper right', framealpha=0.9)

    # ---- Plot 4: PDR Evolution (bottom, full width) ----
    for sw in d.switches:
        style = SWITCH_STYLES.get(sw, {'color': 'gray', 'marker': 'x', 'ls': '-'})
        t = d.times[:len(d.pdr_history[sw])]
        ax_pdr.plot(t, d.pdr_history[sw],
                    color=style['color'], linestyle=style['ls'],
                    marker=style['marker'],
                    markevery=max(1, len(t) // 15),
                    label=sw.upper(), zorder=3)

    ax_pdr.set_xlim(left=max(0, d.times[0] - 2))
    ax_pdr.set_ylim(-0.05, 1.15)
    ax_pdr.set_xlabel('Time (seconds)')
    ax_pdr.set_ylabel('PDR')
    ax_pdr.set_title('Packet Delivery Ratio Evolution')
    ax_pdr.legend(loc='lower left',
                  ncol=min(len(d.switches), 6),
                  framealpha=0.9, edgecolor='gray')

    # ---- Save files ----
    fname = f'dashboard_t{elapsed:.0f}s_{snapshot_num:04d}.png'
    fpath = os.path.join(graph_dir, fname)
    fig.savefig(fpath, dpi=300, facecolor='white', edgecolor='none')

    # Always overwrite latest.png for easy live viewing
    latest = os.path.join(graph_dir, 'latest.png')
    fig.savefig(latest, dpi=300, facecolor='white', edgecolor='none')

    plt.close(fig)
    return fpath


# ============================================================================
#  MAIN LOOP
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Trust-Based SDN Monitoring Dashboard (no GUI needed)')
    parser.add_argument('--topology', choices=['linear', 'diamond'],
                        default='linear',
                        help='Topology type for graph title (default: linear)')
    parser.add_argument('--interval', type=int, default=15,
                        help='Snapshot interval in seconds (default: 15)')
    parser.add_argument('--graph-dir', default=None,
                        help='Graph output directory')
    parser.add_argument('--log-dir', default=None,
                        help='CSV log directory')
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    graph_dir = args.graph_dir or os.path.join(script_dir, 'graphs')
    log_dir   = args.log_dir or os.path.join(script_dir, 'logs')
    os.makedirs(graph_dir, exist_ok=True)

    collector = DataCollector()
    csv_logger = CSVLogger(log_dir)
    snapshot_num = 0
    last_save = 0

    print("=" * 65)
    print("  Trust-Based SDN Monitoring Dashboard")
    print("=" * 65)
    print(f"  Topology:       {args.topology}")
    print(f"  Reading from:   {DATA_FILE}")
    print(f"  Graphs dir:     {graph_dir}/")
    print(f"  CSV log:        {csv_logger.filepath}")
    print(f"  Save interval:  every {args.interval}s")
    print("=" * 65)
    print()
    print("  Waiting for controller data...")
    print("  (Start ryu-manager + topology if not running)")
    print()
    print("  To view graphs live, open in another terminal:")
    print(f"    xdg-open {graph_dir}/latest.png")
    print(f"    # or: eog {graph_dir}/latest.png")
    print()

    try:
        while True:
            new_data = collector.poll()

            if new_data and collector.current:
                csv_logger.log(collector.current)

                now = time.time()
                if now - last_save >= args.interval:
                    snapshot_num += 1
                    fpath = generate_dashboard(
                        collector, args.topology, graph_dir, snapshot_num)
                    last_save = now

                    if fpath:
                        elapsed = collector.current['elapsed']
                        trusts = ' | '.join(
                            f"{s.upper()}={collector.trust_history[s][-1]:.3f}"
                            for s in collector.switches
                        )
                        print(
                            f"  [{elapsed:6.0f}s] {trusts}"
                            f"  -> {os.path.basename(fpath)}")

            time.sleep(3)

    except KeyboardInterrupt:
        print("\n\n[EXIT] Dashboard stopped.")
    finally:
        csv_logger.close()
        if collector.times:
            snapshot_num += 1
            generate_dashboard(
                collector, args.topology, graph_dir, snapshot_num)
        print(f"[DONE] {snapshot_num} snapshots in {graph_dir}/")
        print(f"[DONE] CSV log: {csv_logger.filepath}")


if __name__ == '__main__':
    main()