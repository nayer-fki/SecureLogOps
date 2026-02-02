SecureLogOps 🚨

Unified Security Monitoring, Correlation & Incident Management Platform

📌 Overview

SecureLogOps is a modular, SOC-oriented platform designed to collect, normalize, correlate, and analyze logs, security alerts, and metrics in real time.
Its main goal is to detect security incidents automatically by correlating multiple data sources and presenting actionable incidents to analysts.

The platform follows microservices architecture and aligns with SOC / SIEM / SOAR best practices.

🧠 Core Concepts

SecureLogOps is built around 4 main pillars:

Data Collection – Logs, security alerts, metrics

Normalization & Enrichment – ECS-compatible structure

Correlation & Detection – Rule-based incident creation

Incident Management – Centralized investigation & response

🧩 Services Description
1️⃣ Ingest Service

Role: Entry point for logs and custom JSON events.

Accepts:

File uploads (.json, .jsonl)

HTTP log submissions

Pushes events to Redis queue

Adds metadata (source, dataset, environment)

2️⃣ Logstash

Role: Data normalization & ECS alignment.

Reads events from Redis

Normalizes structure (ECS-compatible)

Enriches logs (host, service, observer, timestamp)

Writes to Elasticsearch data streams
3️⃣ Elasticsearch (ELK)

Role: Central storage & search engine.

Stores:

Logs

Normalized events

Supports:

Kibana Discover

Dashboards

Queries for correlation

4️⃣ Security Service

Role: Security alerts abstraction layer.

Interfaces with Wazuh

Fetches:

Alerts

Agents

Severity & rules

Provides clean API for other services

📌 Prevents direct coupling between correlation engine and Wazuh.

5️⃣ Metrics Service

Role: System & application metrics provider.

Connects to Prometheus

Exposes:

CPU / Memory usage

Latency

Error rates

Used for performance & availability correlation

6️⃣ Correlation Service 🧠 (Core Intelligence)

Role: Detection & correlation engine.

Pulls data from:

Elasticsearch (logs)

Security Service (alerts)

Metrics Service (metrics)

Applies correlation rules

Creates Incidents when conditions are met

Stores incidents in MongoDB

📌 Example correlations:

SSH brute force

Privilege escalation

Service degradation

Suspicious login behavior

7️⃣ Incident Service

Role: Incident lifecycle management.

Exposes REST API for:

Listing incidents

Filtering by severity/status

Updating status (open / closed / acknowledged)

Used by dashboards & analysts


🎯 Use Cases

SOC monitoring & alert correlation

Security incident detection

Academic / PFE project (Cybersecurity & DevOps)

Training & simulation environment

Future SOAR automation integration

🧭 Future Enhancements

ML-based anomaly detection

SOAR actions (block IP, notify, ticketing)

Role-based access control

Threat intelligence integration

Visualization dashboards

👤 Author

Nayer
Cybersecurity • SOC • DevOps • Cloud
