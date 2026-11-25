# Wiz + Google SecOps + Model Armor + CodeMender — End-to-End Security Demo

> **⚠️ SANDBOX DEMO REPOSITORY ONLY:** This repository intentionally contains realistic security vulnerabilities (OS Command Injection `CWE-78`, Path Traversal `CWE-22`, SQL Injection `CWE-89`, and permissive Kubernetes/Dockerfile IaC defaults) strictly for demonstrating **Wiz Code**, **Wiz Defend**, **Google Cloud Model Armor**, **Google SecOps**, and **Google Cloud CodeMender** in an isolated lab environment. **Never deploy this application to production.**

## Unified Demo Architecture ("Code → AI → Cloud/Runtime → SOC → Auto-Fix")

```mermaid
flowchart LR
  subgraph CODE["1. Wiz Code + CodeMender (GitHub)"]
    GH["acidack/wiz-secops-ai-demo"] --> WIZCODE["Wiz Code (GitHub App + Wiz CLI)"]
    GH --> CM["Google Cloud CodeMender (WIF GitHub Actions)"]
    CM -->|Auto-Verified Fix PR| GH
  end

  subgraph GCP["2. Google Cloud (GKE + Model Armor + Vertex AI)"]
    USER["User / Attacker"] --> APP["Cymbal AI Chat App (GKE)"]
    APP --> MA["Google Cloud Model Armor (Prompt & Response Guardrails)"]
    MA --> GEM["Vertex AI Gemini"]
    SENSOR["Wiz Defend GKE Runtime Sensor"] -.-> APP
    AUDIT["GCP Org Cloud Audit Logs"] --> WIZDEF
  end

  subgraph WIZ["3. Wiz Platform (ads-test / anz-gcs-se)"]
    WIZCODE --> GRAPH["Wiz Security Graph (Code-to-Cloud)"]
    SENSOR --> WIZDEF["Wiz Defend + Wiz Blue Agent AI"]
    WIZDEF --> GRAPH
  end

  subgraph SOC["4. Google SecOps (gglxtv)"]
    MA -->|GCP_MODEL_ARMOR Logs| SIEM["SecOps SIEM (UDM)"]
    WIZDEF -->|WIZ_IO Detections & Issues| SIEM
    SIEM --> CORR["Multi-Vector YARA-L Correlation (AI + Cloud/Runtime)"]
    CORR --> SOAR["SecOps SOAR Cases + Wiz Blue Agent Playbooks + Bi-Directional Sync"]
    SOAR <-->|GraphQL API| WIZ
  end
```

## Demo Attack Vectors
1. **AI Prompt Attack (Model Armor → SecOps):** Send a prompt injection, PII exfiltration, or malicious URI in the AI Chat UI → blocked in real time by **Model Armor** (`wiz_demo_model_armor`) and logged to **Google SecOps** (`GCP_MODEL_ARMOR`).
2. **Runtime Exploit (Wiz Defend GKE Sensor → Blue Agent → SecOps):** Exploit the intentional `/api/diagnostics/ping` (`CWE-78`) command injection endpoint on the live GKE pod → **Wiz Runtime Sensor** detects suspicious runtime execution, **Wiz Blue Agent** builds the attack narrative, and the alert streams into **SecOps** (`WIZ_IO`) to correlate with the AI attack.
3. **Cloud Control-Plane Attack (Wiz Defend GCP Audit Logs → SecOps):** Create a suspicious cloud resource (e.g. firewall rule with `pentest` in the name) → caught by **Wiz Defend Cloud Events** and synced bidirectionally with **SecOps**.
4. **Autonomous Code Remediation (Wiz Code + CodeMender):** **Wiz Code** maps the code repo + IaC flaws directly to the running GKE pod; **CodeMender** (`codemender-scan.yml` & `codemender-remediate.yml`) finds, verifies, and opens an automated fix Pull Request in GitHub.
