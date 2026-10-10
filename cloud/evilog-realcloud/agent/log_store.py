"""
The store that the AGENT reads from. Position (a) guarantees only SANITIZED lines
land here. Two backends, same interface:

    append(line: str)
    read_recent(n: int) -> list[str]

Local file = Stage 0/1 (cheap). CloudWatch = Stage 2/3 ("real cloud"). Switching
backends changes nothing about the science — that's the point.
"""
import json
import time


class FileLogStore:
    def __init__(self, path):
        self.path = path

    def append(self, line):
        import os
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a") as f:
            f.write(json.dumps({"ts": time.time(), "line": line}) + "\n")

    def read_recent(self, n):
        try:
            with open(self.path) as f:
                rows = [json.loads(x) for x in f if x.strip()]
        except FileNotFoundError:
            return []
        return [r["line"] for r in rows[-n:]]


class CloudWatchLogStore:
    """Real-cloud store. Requires boto3 + AWS creds + the log group/stream to exist."""

    def __init__(self, group, stream, region):
        import boto3
        self.cw = boto3.client("logs", region_name=region)
        self.group, self.stream = group, stream
        self._ensure()

    def _ensure(self):
        for fn, kw in ((self.cw.create_log_group, {"logGroupName": self.group}),
                       (self.cw.create_log_stream,
                        {"logGroupName": self.group, "logStreamName": self.stream})):
            try:
                fn(**kw)
            except self.cw.exceptions.ResourceAlreadyExistsException:
                pass

    def append(self, line):
        self.cw.put_log_events(
            logGroupName=self.group, logStreamName=self.stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": line}],
        )

    def read_recent(self, n):
        # Mirrors how a real AIOps agent queries CloudWatch for recent logs.
        resp = self.cw.get_log_events(
            logGroupName=self.group, logStreamName=self.stream,
            limit=n, startFromHead=False,
        )
        return [e["message"] for e in resp.get("events", [])]


def build_store(cfg):
    if cfg.STORE_BACKEND == "cloudwatch":
        return CloudWatchLogStore(cfg.CW_LOG_GROUP, cfg.CW_LOG_STREAM, cfg.AWS_REGION)
    return FileLogStore(cfg.FILE_STORE_PATH)
