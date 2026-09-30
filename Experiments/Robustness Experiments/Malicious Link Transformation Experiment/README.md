# Malicious Link Transformation Experiment (SSRF)

Evaluates how Evilog's security detector handles an application-layer attack outside the
seven representative types: **SSRF**, expressed in 25 transformed link forms.

## Files

| File | Role |
|---|---|
| `links.py` | The 25 link variants (22 SSRF + 3 external malicious links) and 3 benign controls |
| `detector.py` | Evilog's LLM security detector (attack-precedence prompt, `gpt-4o-mini`, temperature 0) |
| `static_resolver.py` | Static detector added to Evilog: URL structure, destination address, URL scheme |
| `run_ssrf_eval.py` | Main experiment: Evilog vs Evilog + static detector on the 25 links |
| `limitations/defenses_compare.py` | Blacklist / normalization / static resolver / allowlist on the same links |
| `limitations/reputation_vt.py` | Adding URL reputation (VirusTotal) for the 3 external links |

## The 25 links

| Group | Count | Examples |
|---|---|---|
| Cloud metadata | 3 | AWS / GCP / Azure metadata endpoints |
| Metadata, encoded IP | 4 | decimal `2852039166`, hex `0xA9FEA9FE`, IPv4-mapped IPv6, `nip.io` |
| Internal services | 9 | redis, elasticsearch, etcd, consul, admin, docker bridge, private ranges |
| Localhost, encoded IP | 3 | decimal `2130706433`, octal `0177.0.0.1`, `[::1]` |
| URL schemes | 3 | `gopher://`, `dict://`, `file://` |
| External malicious | 3 | phishing/typosquatting, malware distribution, shortened URL |

## Static detector

`static_resolver.py` never resolves DNS or fetches the URL. A link is flagged as SSRF if
its scheme is dangerous (`gopher`, `dict`, `file`, `ftp`, `ldap`), or if its host, after
normalization to a canonical IP (decimal / hex / octal / IPv4-mapped IPv6 / IP embedded in
a hostname), falls in a loopback, private, link-local, reserved or unspecified range.

## Run

```bash
pip install -r ../requirements.txt
export OPENAI_API_KEY=sk-...          # Windows cmd: set OPENAI_API_KEY=sk-...

python run_ssrf_eval.py --controls    # main result, saved to results/
python run_ssrf_eval.py --repeat 5    # 5 detector calls per link, majority vote
python run_ssrf_eval.py --static-only # static detector only, no API key needed

python limitations/defenses_compare.py   # no API key needed
python limitations/reputation_vt.py      # optional: VT_API_KEY
```

`DET_PROMPT=v1` switches the LLM detector to the original detect-then-mask prompt
(without the attack-precedence rule); the default `v2` is the one used by Evilog.

## Expected result

- The static detector flags 22/25 (deterministic; checkable with `--static-only`).
- With the static detector, Evilog detects 22/25 (88%). The three misses are the external
  links (phishing/typosquatting, malware distribution, shortened URL), whose maliciousness
  depends on the final destination after redirection or the reputation of an external URL.
- The LLM-only column varies slightly between runs; use `--repeat` to report stability.
