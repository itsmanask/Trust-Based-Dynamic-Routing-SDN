# Trust-Based Dynamic Routing Framework for Secure SDN 🔐🌐

A cybersecurity and networking project focused on securing Software-Defined Networks (SDN) against insider attacks using trust-aware dynamic routing mechanisms.

The project implements a Trust-Based Dynamic Routing Framework capable of detecting and mitigating malicious OpenFlow switches behaving as blackhole and greyhole attackers in SDN environments.

## 🚀 Features

- Trust-aware SDN routing
- Blackhole attack detection
- Greyhole attack mitigation
- Dynamic secure rerouting
- Real-time trust evaluation
- Packet delivery monitoring
- Delay and packet-drop analysis
- Automatic malicious node isolation

## 🧠 Core Concepts

The framework continuously evaluates switch trustworthiness using:
- Packet Delivery Ratio (PDR)
- Packet Drop Rate
- Delay Analysis
- Indirect Neighbor Recommendations
- Time-based Trust Aging

A custom routing algorithm dynamically excludes low-trust switches and reroutes traffic through secure paths.

## ⚙️ Technologies Used

- Mininet
- Open vSwitch (OVS)
- Ryu SDN Controller
- Python
- OpenFlow Protocol

## 🌐 System Architecture

The project simulates an SDN environment consisting of:
- SDN Controller
- OpenFlow Switches
- Host Nodes
- Malicious Insider Nodes

The controller continuously monitors network behavior and updates routing decisions based on trust calculations.

## 📊 Results

- Blackhole attacks detected within approximately **10–14 seconds**
- Greyhole attacks detected within approximately **30–60 seconds**
- Maintained near **100% packet delivery** using automatic rerouting
- Achieved low operational overhead during normal operation
- Improved resilience against insider attacks in SDN data planes

## 🔍 Attack Scenarios Simulated

- Blackhole Attacks
- Greyhole Attacks
- Packet Dropping
- Selective Forwarding
- Insider Threat Scenarios

## 🛠️ Functional Modules

- Trust Evaluation Engine
- Dynamic Routing Engine
- Attack Detection System
- Traffic Monitoring Module
- Real-Time Network Analysis
- Secure Path Selection

## 👨‍💻 Development

The complete framework including:
- Trust calculation models
- Routing algorithms
- SDN topology setup
- Attack simulation
- Monitoring systems
- Experimental evaluation
- Performance analysis

was designed and implemented from scratch as part of an academic CNS project.

## 🏫 Institution

Developed at:
- Vishwakarma Institute of Information Technology (VIIT Pune)

## 🌟 Project Goal

To develop a secure and adaptive SDN framework capable of detecting insider threats and maintaining reliable communication through intelligent trust-based routing mechanisms.
