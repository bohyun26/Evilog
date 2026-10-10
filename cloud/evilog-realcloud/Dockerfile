# Bundles: your research artifact (harness/ + aiopsshield + demo_target) AND this repo,
# into one image that runs on EKS.
#
# BUILD CONTEXT = your artifact root (the folder that has harness/, demo_target/,
# requirements.txt). Copy this repo into that folder as `realcloud/` first
# (see README, "Masking proxy image"), so both trees are visible to Docker.
FROM python:3.12-slim

WORKDIR /app

# system deps (curl for healthchecks/debug)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# 1) your harness deps
COPY requirements.txt /app/harness-requirements.txt
RUN pip install --no-cache-dir -r /app/harness-requirements.txt

# 2) this repo's deps (openai, boto3)
COPY realcloud/requirements.txt /app/realcloud-requirements.txt
RUN pip install --no-cache-dir -r /app/realcloud-requirements.txt

# 3) your research code (harness = your scripts + aiopsshield package, demo_target = canary app)
COPY harness/       /app/harness/
COPY demo_target/   /app/demo_target/

# 4) this repo
COPY realcloud/     /app/realcloud/

# make both importable
ENV PYTHONPATH=/app/harness:/app/realcloud
ENV RESEARCH_PATH=/app/harness
# demo_target is in the image so canary template-building works inside the pod
ENV DEMO_TARGET_DIR=/app/demo_target

WORKDIR /app/realcloud
# default: run the masking proxy; override `command` in k8s for other entrypoints
CMD ["python", "proxy/masking_proxy.py"]
