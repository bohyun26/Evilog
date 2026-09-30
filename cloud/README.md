# Cloud Reproduction (AWS EKS + CloudWatch Logs)

We reproduce the local setup on AWS to verify that the results observed locally also hold
in a real cloud environment.

## Architecture

```
attacker requests ──> target web app (EKS pod) ──stdout──> Fluent Bit (DaemonSet)
                                                             │
                                                             ▼
                                              CloudWatch Logs /aiops-lab/realworld
                                                             │
                              sanitization arm (no defense / AIOpsShield / Evilog)
                                                             │
                                                             ▼
                                               diagnostic agent (root-cause analysis)
```

| Component | Setting |
|---|---|
| Region | `ap-northeast-2` |
| Control plane | Amazon EKS, Kubernetes 1.33 |
| Worker nodes | node group of 2 × `t3.large`, private subnet |
| Image registry | Amazon ECR |
| Target app | `realworld-target/` (FastAPI + SQLite), dependencies and env vars baked into the image |
| Log shipping | Fluent Bit on each worker node → CloudWatch Logs |
| Log group / namespace | `/aiops-lab/realworld` / `aiops-lab` |

## Files

| Path | Role |
|---|---|
| `infra/eksctl-cluster.yaml` | EKS cluster and node group definition |
| `realworld-target/` | Target web app, its `Dockerfile`, and `k8s/` manifests (`deployment.yaml`, `fluent-bit-cloudwatch.yaml`) |
| `realworld-target/attack/payloads.json` | Injected payloads (evidence-type, steering-type, benign control) |
| `realworld-target/app/logging_config.py` | Writes user input to stdout log lines |
| `agent/log_store.py` | Agent tool that queries the CloudWatch log group |
| `proxy/` | Sanitization arms (masking proxy, defense implementations, config) |
| `experiment/curate.py` | Log curation within the agent's line budget |
| `experiment/compare_realcloud.py` | Main comparison: no defense / AIOpsShield / Evilog |
| `Dockerfile` | Image for the masking proxy (bundles the research harness) |
| `results/window_v1.json` | Captured CloudWatch window (fixture; rerun without AWS) |
| `results/compare_realcloud_n10*.json` | Reported results (n = 10 per model and arm) |

## Reproduce

### Option A: from the captured fixture (no AWS needed)

```bash
export OPENAI_API_KEY=sk-...
export RESEARCH_PATH=/path/to/harness          # directory containing detect_then_mask.py
export AIOPSSHIELD_PATH=/path/to/AIOpsShield   # not bundled, see THIRD_PARTY.md
export BUILD_MODE=empty
export MODELS=gpt-4o-2024-08-06,gpt-4.1-2025-04-14
python experiment/compare_realcloud.py \
    --fixture results/window_v1.json \
    --payloads realworld-target/attack/payloads.json \
    --budget 50
```

Pass `--payloads` explicitly: the default relative path does not point to the payload file.

### Option B: full cloud run

```bash
# 1. cluster
eksctl create cluster -f infra/eksctl-cluster.yaml

# 2. image -> ECR   (replace <ACCOUNT_ID>)
aws ecr get-login-password --region ap-northeast-2 | docker login --username AWS \
    --password-stdin <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com
docker build -t realworld-target realworld-target/
docker tag realworld-target <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com/<REPO>:latest
docker push <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com/<REPO>:latest

# 3. deploy app + log shipping
kubectl apply -f realworld-target/k8s/

# 4. send payloads, then run the comparison without --fixture
python experiment/compare_realcloud.py --payloads realworld-target/attack/payloads.json --budget 50
```

## Cost and teardown

The EKS control plane and NAT gateway are billed even with zero nodes
(about USD 3.5/day in our setup). Delete the cluster after use:

```bash
eksctl delete cluster -f infra/eksctl-cluster.yaml
```

A free-tier AWS account cannot launch `t3.large`; node group creation fails until the
account is upgraded.
