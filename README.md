# TBR-QL: Q-Learning Enhanced Trust-Based Routing for Secure UWSNs

TBR-QL is a secure routing protocol for Underwater Wireless Sensor Networks (UWSNs) that combines Trust-Based Routing (TBR) with Q-Learning to improve relay selection under malicious attacks.

Implemented and evaluated using NS-3.41 and AquaSim-NG.

## Network Architecture

![Network Topology](images/Network_Topology.png)

## Packet Header

![Packet Header](images/Packet_Header.png)

## Protocol for Relay Selection

![Workflow](images/Protocol_for_Relay_Selection.png)

## Key Features

- **Trust-Aware Secure Routing**  
  Evaluates neighboring nodes based on forwarding behavior and trust scores to avoid unreliable or malicious relays.

- **Q-Learning Based Relay Selection**  
  Uses reinforcement learning to dynamically select forwarding nodes by considering trust, residual energy, propagation delay, and depth advancement.

- **Asymmetric Reward and Punishment Mechanism**  
  Applies faster penalties for malicious behavior and slower recovery for previously untrusted nodes, improving resilience against on-off attacks.

- **Mixed On-Off Attack Model**  
  Simulates realistic underwater network threats where malicious nodes periodically switch between normal and attack states while performing multiple attack types.

- **NS-3.41 + AquaSim-NG Implementation**  
  Fully implemented and evaluated in the NS-3.41 simulator using the AquaSim-NG underwater networking framework.

## Results

### Performance Comparison of TBR vs TBR-QL at 114 bits/s

![114 bits](Result/TBR_vs_TBR-QL_Performance_under_Mixed_Attack_at_114_bits_per_sec.png)

### Performance Comparison of TBR vs TBR-QL at 228 bits/s

![228 bits](Result/TBR_vs_TBR-QL_Performance_under_Mixed_Attack_at_228_bits_per_sec.png)

### Ph-Value Vs Q-Value Convergence

![Ph Vs Q Value Convergence](Result/Convergence_Graph.png)


## Authors

- Abhishek Jain(Research paper)
- Krish Arora(Main Developer)
- Sujal Goel(Main Developer)

### Guided By

Dr. Mohit Sajwan  
Department of Information Technology  
NSUT

## Research Manuscript

📄 [Read the Research Paper](TBR-QL-Research_Paper.pdf)

Status: Unpublished Research Project
