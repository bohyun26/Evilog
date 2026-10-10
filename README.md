# Evilog

**Evilog** is a security-enhancement approach designed to preserve critical attack evidence in LLM-driven AIOps systems while maintaining defenses against telemetry-based prompt injection attacks.

Existing defenses, such as AIOpsShield, mitigate prompt injection by masking user-controlled content in telemetry before it reaches the LLM. However, this process may also remove critical evidence of application-layer attacks, potentially causing incident detection failures or incorrect diagnoses.

Evilog addresses this limitation by identifying attack evidence before the masking process. By preserving security-relevant information, Evilog enables AIOps agents to maintain diagnostic capabilities without sacrificing prompt-injection defenses.

Evilog was evaluated in both local and AWS cloud environments. Additional robustness experiments were conducted against fragmented application-layer attack payloads.

## News

- [Update with paper acceptance or release information]

## Table of Contents

- [Installation](#installation)
- [Main Components](#main-components)
- [Workflow](#workflow)
- [Experiments](#experiments)
- [License](#license)
- [How to Cite](#how-to-cite)

## Installation

### Prerequisites

- Python
- Project dependencies listed in `requirements.txt`
- Additional environment-specific requirements for local or cloud experiments

### Setup

**1. Clone the repository:**

```bash
git clone https://github.com/bohyun26/Evilog.git
cd Evilog
```

**2. Install dependencies:**

```bash
pip install -r requirements.txt
```

**3. Configure the environment:**

Configure the required AIOps services, telemetry sources, and LLM settings for the selected experiment.

Environment-specific setup and execution instructions will be documented separately.

## Main Components

### Attack Evidence Detection

Evilog analyzes user-controlled telemetry content before the masking process to identify evidence of application-layer attacks.

This component aims to:

- Inspect user-controlled input fields.
- Detect security-relevant attack patterns before masking.
- Identify attack evidence required for incident diagnosis.
- Prevent critical diagnostic information from being lost during sanitization.

### Attack Evidence Preservation

Evilog preserves detected attack evidence while allowing the existing prompt-injection defense to sanitize other user-controlled content.

This process aims to:

- Maintain compatibility with telemetry sanitization.
- Preserve information necessary for accurate incident diagnosis.
- Reduce detection failures caused by the removal of attack evidence.

### Fragmented Attack Detection

Evilog supports the detection of attack payloads distributed across multiple telemetry fragments.

The robustness evaluation considers five fragmentation strategies:

- Token-based fragmentation
- Whitespace-based fragmentation
- Operator-based fragmentation
- Fixed-length fragmentation
- Random-length fragmentation

Evilog buffers and reconstructs fragments associated with the same session and rechecks the reconstructed input for attack evidence.

### Telemetry Processing

Evilog is designed to operate before telemetry masking in the AIOps processing pipeline.

Its role is to retain relevant security evidence while limiting the exposure of untrusted user-controlled content to the LLM.

## Workflow

Evilog follows an evidence-preserving telemetry processing workflow.

### 1. Collect Telemetry

The monitored application generates telemetry containing operational information and potentially user-controlled input.

### 2. Inspect User-Controlled Content

Evilog analyzes user-controlled fields to identify application-layer attack evidence before masking occurs.

### 3. Reconstruct Fragmented Inputs

When attack-related content is distributed across multiple fragments, Evilog buffers and reconstructs the fragments within the same session.

### 4. Preserve Attack Evidence

Security-relevant evidence is retained so that it remains available for downstream incident diagnosis.

### 5. Apply Telemetry Sanitization

The prompt-injection defense sanitizes user-controlled telemetry content while preserving the identified attack evidence.

### 6. Perform AIOps Diagnosis

The processed telemetry is delivered to the LLM-driven AIOps agent for incident analysis.

This workflow aims to balance prompt-injection protection and diagnostic accuracy.

## Experiments

Evilog was evaluated to investigate the impact of telemetry sanitization on attack diagnosis and the effectiveness of evidence preservation.

### Local Environment

Experiments were conducted in a local environment to compare incident diagnosis with and without evidence preservation.

### AWS Cloud Environment

Additional experiments were conducted in an AWS cloud environment to evaluate Evilog under cloud-based operational conditions.

### Robustness Evaluation

The robustness evaluation considers seven application-layer attacks and five fragmentation strategies, resulting in 35 attack–fragmentation combinations.

Evilog reconstructs fragmented inputs using a buffer of up to 32 fragments associated with the same session.

In the reported experiments, Evilog successfully detected all 35 combinations.

### Repository Structure

```text
Evilog/
├── Experiments/
├── aiops_blindness_artifact/
├── cloud/
├── requirements.txt
└── README.md
```

The repository contains experimental artifacts and resources for local and cloud-based evaluations.

## License

[Specify the license selected by the project copyright holders.]

If Apache-2.0 is selected, add the corresponding `LICENSE` file to the repository and replace this section with:

This project is licensed under the Apache License 2.0 License. See the [LICENSE](LICENSE) file for details.

## How to Cite

If you use Evilog in your research, please cite our paper:

```bibtex
@misc{evilog2026,
    title = {[Full Paper Title]},
    author = {[Author Names]},
    year = {2026},
    url = {[Paper URL]}
}
```

The official citation information will be updated when the paper's bibliographic details are finalized.
