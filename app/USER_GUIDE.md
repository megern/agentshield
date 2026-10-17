# AgentShield user guide — 0.3.0

AgentShield reviews an agent configuration and pasted instructions using eight explainable rules. It shows matched evidence, risk weights and specific remediation suggestions so an engineer can identify permission gaps before enabling tools. It does not execute the agent or enforce permissions.

## Workflow

1. Select the tools the agent actually has. Add other tool names if needed.
2. Set confirmation, sandbox and context-secret flags to match the implemented safeguards.
3. Add domains only if an allowlist is actually enforced by your agent.
4. Paste untrusted text and choose **Scan configuration**.
5. Read each finding, its evidence and the suggested action. Export the current configuration or the report.

**Load synthetic risky agent** fills an intentionally unsafe example. It is synthetic test input, not a real incident. An imported or edited setup is labeled as user input with unverified provenance. Results are cleared when inputs change. A response to a request whose inputs changed while it ran is discarded.

Import configuration JSON with `prompt`, `tools`, `allowed_domains`, `confirmation_required`, `sandboxed`, and `secrets_in_context`. The import control rejects unsupported fields and invalid field types; the API schema is authoritative for limits.

## Methods and interpretation

The four text rules match instruction-override language, credential-exfiltration language, destructive command patterns and system-role delimiters. The four configuration rules identify unconfirmed side effects, unsandboxed shell access, unrestricted network configuration and secrets in context. Scores sum fixed weights: medium=10, high=25, critical=40, capped at 100. **The score is not a probability, exploitability measure or certification.** A score of zero means only that none of these rules matched.

Findings include stable rule codes, severity, a short explanation and matched evidence. Tool-name and domain lists are trimmed/lowercased. Unknown tools have no tool-specific rule. Domain allowlists are self-reported, not inspected or validated as DNS names. False positives occur when quoted examples mention dangerous language; paraphrased or multilingual attacks can be missed.

## Limits and next actions

Prompt limit 100000 characters, at most 100 tool entries and 100 domains; HTTP body limit 2 MiB. No AST parsing, dependency vulnerability scanning, live agent probes or sandbox verification is performed by the application. CI dependency scanning applies to this repository, not your uploaded agent. Remediation must be applied to the real tool executor and verified independently.

## Troubleshooting

- No findings on a suspicious prompt: rules are narrow lexical checks. Test the complete agent and do not infer safety from this output.
- Import rejected: provide strings for prompt/tool/domain entries and JSON booleans for safeguard flags. Remove fields not in the documented schema.
- A network finding persists: supply an allowlist only after implementing it; this app does not create it.
- Export contains credentials: the app does not redact matched text. Remove secrets before sharing and rotate exposed credentials if necessary.

## Run locally

Docker (recommended):

```sh
docker compose up --build
```

Open http://localhost:8000. The interface, API reference at `/docs`, and user guide at `/guide` are served by the same app. The host port binds to localhost. Change only the host side of `8000:8000` if another app uses that port. The container runs as a non-root user with a read-only filesystem.

Python 3.12 or later:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Tests and release gates

```sh
python -m pytest -q
node --test tools/test_ui.mjs
python -m bandit -q -r app
python -m pip_audit -r requirements.txt
```

Node 22 is used for browser-independent CSV/export logic tests; it is not needed to serve the application. Python tests include actual core calculations, validation failures and in-process HTTP integration. They do not establish Docker deployment or browser interaction success. Fresh 0.3.0 evidence belongs in `evidence/improvements-0.3/`. `evidence/rebuild/` records the earlier 0.2.0 rebuild; it does not validate this version. CI includes locked dependency installation, test/security gates, image scanning and secret scanning. Branch protection and release publication remain separate operator actions; no publication success is claimed by this README.

MIT licensed. No paid service or new model download is required. Data is processed by this app server when you run an analysis. Inputs/results are not automatically saved by this application. JSON exports may contain the original input and sensitive values; inspect them before sharing. There is no authentication or rate limiter. Keep the localhost binding or supply access controls before exposing the server.

## Compare a configuration change (0.3.0)

Use **Use current setup as baseline**, then edit the active configuration and select **Compare current setup to baseline**. Alternatively import a baseline from an exported configuration JSON or a single-scan report's `input` object. Baseline import does not replace the active form. Exporting the comparison report includes both original configurations, their scores, and the complete rule-level differences.

The API is `POST /compare` with `{ "before": { ...configuration... }, "after": { ...configuration... } }`. The original `POST /analyze` remains available. `introduced` and `resolved` contain findings whose rule code exists only after/before respectively. `persistent` contains both versions of each finding with the same code, so evidence can change without the finding being considered resolved. Risk delta is **after minus before** using the existing capped score. Two capped scores can produce zero delta despite changed findings. This is a heuristic change review, not an enforcement test or proof of safety. Prompt and list bounds apply independently to both configurations, with the existing 2 MiB HTTP bound.

The baseline remains selected until replaced. Input/baseline changes invalidate the current comparison report. Stale file reads and delayed analysis responses cannot replace a newer setup. An imported comparison report itself is not a baseline configuration; use its `input.before` or `input.after` as a standalone configuration file.
