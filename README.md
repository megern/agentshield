# AgentShield

Version 0.3.0 · CPU local tool · MIT

AgentShield reviews an agent configuration and pasted instructions using eight explainable rules. It shows matched evidence, risk weights and specific remediation suggestions so an engineer can identify permission gaps before enabling tools. It does not execute the agent or enforce permissions.

## Try the interface

1. Select the tools the agent actually has. Add other tool names if needed.
2. Set confirmation, sandbox and context-secret flags to match the implemented safeguards.
3. Add domains only if an allowlist is actually enforced by your agent.
4. Paste untrusted text and choose **Scan configuration**.
5. Read each finding, its evidence and the suggested action. Export the current configuration or the report.

**Load synthetic risky agent** fills an intentionally unsafe example. It is synthetic test input, not a real incident. An imported or edited setup is labeled as user input with unverified provenance. Results are cleared when inputs change. A response to a request whose inputs changed while it ran is discarded.

Import configuration JSON with `prompt`, `tools`, `allowed_domains`, `confirmation_required`, `sandboxed`, and `secrets_in_context`. The import control rejects unsupported fields and invalid field types; the API schema is authoritative for limits.

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

## Methods and operating details

Read [the complete user guide](docs/USER_GUIDE.md) for calculations, input schemas, limitations and troubleshooting. The same guide is served at `/guide`. The API and browser use the same tested computation path.

API example using explicitly synthetic data:

```sh
curl --fail-with-body http://localhost:8000/analyze -H 'Content-Type: application/json' --data-binary @examples/synthetic.json
```

## Compare a configuration change (0.3.0)

Use **Use current setup as baseline**, then edit the active configuration and select **Compare current setup to baseline**. Alternatively import a baseline from an exported configuration JSON or a single-scan report's `input` object. Baseline import does not replace the active form. Exporting the comparison report includes both original configurations, their scores, and the complete rule-level differences.

The API is `POST /compare` with `{ "before": { ...configuration... }, "after": { ...configuration... } }`. The original `POST /analyze` remains available. `introduced` and `resolved` contain findings whose rule code exists only after/before respectively. `persistent` contains both versions of each finding with the same code, so evidence can change without the finding being considered resolved. Risk delta is **after minus before** using the existing capped score. Two capped scores can produce zero delta despite changed findings. This is a heuristic change review, not an enforcement test or proof of safety. Prompt and list bounds apply independently to both configurations, with the existing 2 MiB HTTP bound.

The baseline remains selected until replaced. Input/baseline changes invalidate the current comparison report. Stale file reads and delayed analysis responses cannot replace a newer setup. An imported comparison report itself is not a baseline configuration; use its `input.before` or `input.after` as a standalone configuration file.
