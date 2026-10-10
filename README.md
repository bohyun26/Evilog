# Evilog

**Evilog: Evidence-Preserving Log Sanitization for LLM-based AIOps Agents**

Evilog is an evidence-preserving log sanitization technique designed to protect LLM-based AIOps agents against telemetry-based prompt injection attacks while maintaining their ability to detect application-layer attacks.

Existing defenses, such as AIOpsShield, mitigate prompt injection by masking user-controlled content in telemetry before it reaches the LLM. However, this approach may also remove critical evidence of application-layer attacks, such as SQL injection, command injection, and cross-site scripting (XSS), causing AIOps agents to miss attacks or misdiagnose their root causes.

To address this limitation, Evilog introduces a **detect-then-mask** approach. Before applying AIOpsShield's masking, Evilog analyzes user-controlled input to identify application-layer attacks. When an attack is detected, Evilog removes the original attack string and preserves its type as structured security metadata, enabling the AIOps agent to perform accurate diagnosis without directly processing untrusted input.

Our experiments demonstrate that Evilog maintains prompt injection protection while restoring application-layer attack detection capabilities across local and AWS cloud environments.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Main Components](#main-components)
- [Workflow](#workflow)
- [Supported Attack Types](#supported-attack-types)
- [Experimental Evaluation](#experimental-evaluation)
- [Latency Evaluation](LATENCY_EVALUATION.md)
- [Repository Structure](#repository-structure)
- [License](#license)
- [How to Cite](#how-to-cite)

## Overview

LLM-based AIOps agents analyze telemetry, including logs, metrics, and traces, to detect system anomalies and diagnose failures. However, because telemetry may contain externally controlled user input, it can serve as a vector for prompt injection attacks.

AIOpsShield addresses this threat by identifying and masking user-controlled telemetry fields. While effective against prompt injection, this masking process can inadvertently remove essential evidence of application-layer attacks.

Evilog extends this defense by analyzing user-controlled input before masking. Instead of exposing raw attack payloads to the AIOps agent, Evilog converts detected attack evidence into structured security metadata.

This approach enables the AIOps agent to identify attacks while maintaining protection against prompt injection.

## Installation

### Prerequisites

- Python environment
- Access to the required LLM APIs
- A configured application and telemetry collection environment
- AWS resources for cloud-based experiments (optional)

### Setup

**1. Clone the repository:**

```bash
git clone https://github.com/bohyun26/Evilog.git
cd Evilog
```

**2. Install the required dependencies:**

Configure a Python environment and install the dependencies required by the selected experiment.

**3. Configure the experimental environment:**

Set up the target application, telemetry collection, AIOpsShield, and the LLM-based diagnostic agent.

Environment-specific configuration and execution instructions will be added as the experimental artifacts are documented.

## Main Components

### 1. Attack Evidence Detector

Evilog incorporates an LLM-based security detector that analyzes user-controlled input before the masking process.

The detector:

- Inspects user-controlled fields recorded in application logs.
- Identifies evidence of application-layer attacks.
- Classifies detected attacks into predefined categories.
- Returns the detected attack type in a constrained output format.

The detector uses GPT-4o-mini in the evaluated implementation.

### 2. Security Metadata Generation

When an application-layer attack is detected, Evilog generates structured security metadata describing the detected attack type.

For example:

```text
SECURITY: SQLi detected
```

This metadata is attached to the sanitized log so that the AIOps agent can identify the attack without accessing the original attack string.

For inputs that are not classified as application-layer attacks, no security metadata is generated.

### 3. Log Sanitization

Evilog integrates with the existing AIOpsShield sanitization process.

The original user-controlled input is masked before being delivered to the LLM-based AIOps agent.

This process:

- Prevents untrusted user-controlled instructions from being directly delivered to the diagnostic agent.
- Preserves the presence and type of detected application-layer attacks.
- Maintains the original masking behavior for inputs without detected attack evidence.

### 4. Fragmented Attack Reconstruction

Evilog also supports the reconstruction of attack payloads distributed across multiple input fragments.

It:

- Buffers user-controlled inputs associated with the same session.
- Reconstructs fragmented input in its original order.
- Rechecks the reconstructed input for application-layer attacks.
- Maintains a buffer of up to 32 input fragments per session.

This mechanism enables Evilog to identify attacks even when individual fragments appear benign.

## Workflow

Evilog follows a **detect-then-mask** pipeline.

### Step 1: Telemetry Generation

A web application generates logs containing operational information and potentially user-controlled input, such as login identifiers, URL paths, and HTTP headers.

### Step 2: Attack Evidence Detection

Before sanitization, Evilog analyzes the user-controlled input to determine whether it contains evidence of an application-layer attack.

### Step 3: Security Metadata Generation

If an attack is identified, Evilog records its type as security metadata.

### Step 4: Input Masking

AIOpsShield masks the original user-controlled input, preventing malicious instructions and raw attack payloads from reaching the diagnostic agent.

### Step 5: AIOps Diagnosis

The LLM-based AIOps agent analyzes the sanitized telemetry and preserved security metadata to identify the attack and diagnose the incident.

### Comparison of Defense Approaches

| Defense | Prompt Injection Blocking | Application-Layer Attack Detection |
|---|---|---|
| No Defense | No protection | Attack evidence remains visible |
| AIOpsShield | Blocks prompt injection | May remove critical attack evidence |
| Evilog | Blocks prompt injection | Preserves detected attack information |

## Supported Attack Types

Evilog was evaluated against seven application-layer attack types:

| Attack Type | Description |
|---|---|
| SQL Injection (SQLi) | Injection of malicious SQL statements |
| Command Injection | Execution of unintended system commands |
| Cross-Site Scripting (XSS) | Injection of malicious scripts into web application content |
| Log4Shell | Exploitation of Log4j-related lookup behavior |
| NoSQL Injection | Injection targeting NoSQL database queries |
| LDAP Injection | Manipulation of LDAP queries |
| Server-Side Template Injection (SSTI) | Injection of malicious template expressions |

Attack payloads were inserted into application fields recorded in telemetry, including login identifiers, URL paths, and HTTP Referer headers.

## Experimental Evaluation

We evaluated Evilog by comparing three conditions:

1. **No Defense:** User-controlled input is delivered without sanitization.
2. **AIOpsShield:** User-controlled telemetry fields are masked.
3. **Evilog:** Application-layer attacks are detected before masking, and their types are preserved as security metadata.

### 1. Main Evaluation Results

The primary evaluation produced the following results:

| Evaluation Metric | No Defense | AIOpsShield | Evilog |
|---|---|---|---|
| Prompt Injection Blocking Rate | 0% | 100% | 100% |
| Application-Layer Attack Detection Rate | 100% | 0% | 100% |
| Detector False-Positive Rate | N/A | N/A | 0% |

These results demonstrate that Evilog maintains prompt injection protection while preserving the attack evidence required for accurate diagnosis.

The reported rates correspond to the primary experimental conditions and should not be interpreted as universal detection guarantees.

### 2. Local and Cloud Environments

Evilog was evaluated in multiple environments to examine whether the proposed defense operates consistently across different deployment settings.

**Local Environment**

- Flask-based web application
- Application-generated logs
- AIOpsShield sanitization
- Tool-using LLM-based diagnostic agent

**AWS Cloud Environment**

- Amazon Elastic Kubernetes Service (EKS)
- Amazon Elastic Container Registry (ECR)
- Fluent Bit for log collection
- Amazon CloudWatch Logs for telemetry storage

The experiments confirmed that Evilog could preserve attack information and maintain prompt injection blocking in both local and cloud environments under the evaluated conditions.

### 3. Evaluation Across Different LLMs

We further evaluated Evilog using different LLM-based diagnostic agents.

| LLM | No Defense | AIOpsShield | Evilog |
|---|---|---|---|
| GPT-4o | 89.6% | 36.1% | 97.6% |
| Gemini 2.5 Flash | 92.9% | 6.5% | 92.6% |
| Claude Sonnet | 99.6% | 55.2% | 96.8% |

The results show that Evilog improves application-layer attack detection compared with AIOpsShield across the evaluated models.

However, detection performance varies depending on the model and attack type.

### 4. Robustness Against Fragmented Attacks

To evaluate robustness against fragmented attack inputs, we divided each of the seven application-layer attack payloads using five fragmentation strategies:

- Token-based fragmentation
- Whitespace-based fragmentation
- Operator-based fragmentation
- Fixed-length fragmentation
- Random-length fragmentation

This resulted in **35 attack–fragmentation combinations**.

Evilog reconstructs fragmented inputs within the same session and re-evaluates the combined input before masking.

**Experimental Results:**

- No Defense: 32/35 combinations detected (91.4%)
- Evilog: 35/35 combinations detected (100%)
- AIOpsShield: Attack evidence was masked, preventing identification of the attack type in the evaluated fragmented cases

These results demonstrate that Evilog can recover attack evidence from fragmented inputs that may not be recognizable when analyzed individually.

### 5. Processing Overhead

We measured the additional processing time introduced by Evilog's LLM-based security detector.

| Defense | Mean Processing Time |
|---|---|
| AIOpsShield | 2.06 µs |
| Evilog | 791,647.89 µs |

Evilog introduces additional latency because it performs an LLM-based detection call before masking user-controlled input.

This represents a trade-off between processing efficiency and preserving attack information for incident diagnosis.

For detailed experimental settings, measurement procedures, and reproduction guidance, see [Latency Evaluation](LATENCY_EVALUATION.md).

## Repository Structure

```text
Evilog/
├── Evilog_Origin/
├── Experiments/
├── cloud/
├── requirements.txt
├── LATENCY_EVALUATION.md
└── README.md
```

The repository contains research artifacts and resources related to the evaluation of Evilog.

## License

Apache-2.0 license

## How to Cite

If you use Evilog or its experimental artifacts in your research, please cite our paper.

**Paper:** *Evilog: Evidence-Preserving Log Sanitization for LLM-based AIOps Agents*

```bibtex
@misc{evilog,
    title = {Evilog: Evidence-Preserving Log Sanitization for LLM-based AIOps Agents},
    author = {[Author Names]},
    year = {[Publication Year]},
    url = {[Paper URL]}
}
```
