# AI-Powered 3D Network Intrusion Detection and Threat Analysis System

## Overview

Threat3D is an AI-powered Network Intrusion Detection and Threat Analysis System designed to monitor network traffic, detect suspicious activities, analyze threats, and provide security recommendations through an interactive 3D dashboard.

The system combines signature-based detection and anomaly detection with real-time visualization, threat scoring, correlation, and simulated defense recommendations.

## Key Features

- Real-time network traffic and flow analysis
- 3D network topology visualization
- Hybrid threat detection
- Signature-based intrusion detection
- 41-feature anomaly detection using Welford's online algorithm
- Threat scoring and severity classification
- Threat correlation and multi-stage activity analysis
- Cyber attack simulation scenarios
- Traffic and flow analysis dashboard
- Detection rules and signature management
- Simulated defense recommendations
- MITRE ATT&CK technique mapping
- English and Tamil voice assistant
- Cybersecurity learning and guidance module
- Role-based access control
- Responsive interface for desktop and mobile screens

## Threat Detection

The system supports detection and analysis of:

- Normal Traffic
- Port Scan
- SYN Flood
- ICMP Flood
- Brute Force
- Web Anomaly
- Anomalous Traffic
- Multi-Stage Suspicious Activity

## Technology Stack

### Backend

- Java 17
- Spring Boot 3.3.3
- Spring Security
- Spring Data JPA / Hibernate
- H2 Database
- PostgreSQL support
- JWT Authentication
- Pcap4j
- Maven

### Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Three.js
- WebSocket / STOMP

### AI and Detection

- Welford Online Anomaly Detection
- Hybrid Threat Scoring
- Signature-Based Detection
- Threat Correlation
- MITRE ATT&CK Mapping

## System Architecture


Network Traffic
       ↓
Traffic Ingestion
       ↓
Flow Aggregation
       ↓
41-Feature Extraction
       ↓
Signature Detection
       ↓
Anomaly Detection
       ↓
Hybrid Threat Scoring
       ↓
Threat Correlation
       ↓
Severity Classification
       ↓
3D Dashboard
       ↓
Simulated Defense Recommendation


Security and Safety

Threat3D is designed for safe cybersecurity experimentation and academic demonstration.

Attack scenarios are simulated using synthetic traffic and controlled PCAP replay. The defense actions shown by the system are recommendations and simulations only. The system does not perform real network blocking or destructive actions.

User Roles

The system provides role-based access for:

ADMIN
ANALYST
STUDENT

Each role receives appropriate access to monitoring, analysis, simulation, learning, and administrative features.

Project Status

The project has been tested across its major backend and frontend components.

Backend test suite: Passed
Frontend production build: Passed
API contracts: Verified
Simulation scenarios: Verified
3D visualization: Implemented
Role-based access: Verified
Bilingual voice assistant: Implemented
Project Purpose

This project was developed as an academic cybersecurity and AI project to demonstrate how network intrusion detection, anomaly analysis, threat intelligence, visualization, and simulated defensive recommendations can be integrated into a single platform.

Author

Kavi Priya K

B.Tech Artificial Intelligence and Data Science

Repository

https://github.com/kavi-kavi208/Threat3D-NIDS
