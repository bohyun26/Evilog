"""
Malicious-link transformation experiment: the 25 link variants used in the paper.

  22 SSRF variants  (cloud metadata, encoded IPs, internal services, dangerous schemes)
 + 3 external malicious links (phishing/typosquatting, malware distribution, shortened URL)

Each entry: (id, group, label, url)
BENIGN_CONTROLS are NOT part of the 25; they are an optional false-positive check.
"""

LINKS = [
    # --- well-known cloud metadata endpoints ---
    ("L01", "metadata",          "AWS metadata",             "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("L02", "metadata",          "GCP metadata",             "http://metadata.google.internal/computeMetadata/v1/instance/"),
    ("L03", "metadata",          "Azure metadata",           "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    # --- same metadata target, different IP representation ---
    ("L04", "metadata_encoded",  "AWS decimal IP",           "http://2852039166/latest/meta-data/"),
    ("L05", "metadata_encoded",  "AWS hex IP",               "http://0xA9FEA9FE/latest/meta-data/"),
    ("L06", "metadata_encoded",  "AWS IPv4-mapped IPv6",     "http://[::ffff:169.254.169.254]/latest/meta-data/"),
    ("L07", "metadata_encoded",  "AWS via nip.io",           "http://169.254.169.254.nip.io/latest/meta-data/"),
    # --- internal services ---
    ("L08", "internal_service",  "redis",                    "http://127.0.0.1:6379/"),
    ("L09", "internal_service",  "redis (localhost)",        "http://localhost:6379/"),
    ("L10", "internal_service",  "elasticsearch",            "http://127.0.0.1:9200/_cat/indices"),
    ("L11", "internal_service",  "etcd",                     "http://127.0.0.1:2379/v2/keys/"),
    ("L12", "internal_service",  "consul",                   "http://127.0.0.1:8500/v1/kv/"),
    ("L13", "internal_service",  "internal admin",           "http://localhost:8080/admin"),
    ("L14", "internal_service",  "docker bridge",            "http://172.17.0.1/"),
    ("L15", "internal_service",  "private router",           "http://192.168.1.1/"),
    ("L16", "internal_service",  "private 10.x",             "http://10.0.0.1/"),
    # --- localhost, different IP representation ---
    ("L17", "localhost_encoded", "decimal localhost",        "http://2130706433:6379/"),
    ("L18", "localhost_encoded", "octal localhost",          "http://0177.0.0.1:6379/"),
    ("L19", "localhost_encoded", "IPv6 localhost",           "http://[::1]:6379/"),
    # --- URL schemes ---
    ("L20", "scheme",            "gopher -> redis",          "gopher://127.0.0.1:6379/_INFO"),
    ("L21", "scheme",            "dict -> redis",            "dict://127.0.0.1:6379/info"),
    ("L22", "scheme",            "file scheme",              "file:///etc/passwd"),
    # --- external malicious links (need external context: reputation / final destination) ---
    ("L23", "external",          "phishing / typosquatting", "http://paypa1-secure-login.com/verify"),
    ("L24", "external",          "malware distribution",     "http://malware-dl.tk/payload.exe"),
    ("L25", "external",          "shortened URL",            "http://bit.ly/3xAbCdE"),
]

BENIGN_CONTROLS = [
    ("B01", "benign", "Stripe API",    "https://api.stripe.com/v1/charges"),
    ("B02", "benign", "GitHub",        "https://github.com/openai/openai-python"),
    ("B03", "benign", "Google search", "https://www.google.com/search?q=weather"),
]

assert len(LINKS) == 25
