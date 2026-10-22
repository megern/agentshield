# AgentShield user guide — 0.4.0

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

Node 22 is used for browser-independent CSV/export logic tests; it is not needed to serve the application. Python tests include actual core calculations, validation failures and in-process HTTP integration. They do not establish Docker deployment or browser interaction success. Fresh 0.4.0 evidence belongs in `evidence/improvements-0.4/`. `evidence/rebuild/` records the earlier 0.2.0 rebuild; it does not validate this version. CI includes locked dependency installation, test/security gates, image scanning and secret scanning. Branch protection and release publication remain separate operator actions; no publication success is claimed by this README.

MIT licensed. No paid service or new model download is required. Data is processed by this app server when you run an analysis. Inputs/results are not automatically saved by this application. JSON exports may contain the original input and sensitive values; inspect them before sharing. Optional shared-key API access and per-process compute admission are available; see docs/OPERATIONS.md in the repository. These are not user accounts, distributed quotas or HTTPS. Keep the default localhost binding unless you supply the additional hosting controls.

## Compare a configuration change (0.4.0)

Use **Use current setup as baseline**, then edit the active configuration and select **Compare current setup to baseline**. Alternatively import a baseline from an exported configuration JSON or a single-scan report's `input` object. Baseline import does not replace the active form. Exporting the comparison report includes both original configurations, their scores, and the complete rule-level differences.

The API is `POST /compare` with `{ "before": { ...configuration... }, "after": { ...configuration... } }`. The original `POST /analyze` remains available. `introduced` and `resolved` contain findings whose rule code exists only after/before respectively. `persistent` contains both versions of each finding with the same code, so evidence can change without the finding being considered resolved. Risk delta is **after minus before** using the existing capped score. Two capped scores can produce zero delta despite changed findings. This is a heuristic change review, not an enforcement test or proof of safety. Prompt and list bounds apply independently to both configurations, with the existing 2 MiB HTTP bound.

The baseline remains selected until replaced. Input/baseline changes invalidate the current comparison report. Stale file reads and delayed analysis responses cannot replace a newer setup. An imported comparison report itself is not a baseline configuration; use its `input.before` or `input.after` as a standalone configuration file.

## Audit execution evidence (0.4)

The new trace workspace imports a policy plus an ordered event array, edits the allowed tools/domains and confirmation requirement, and runs `POST /trace/audit`. **Load synthetic trace** intentionally contains an approved allowed call and a second call with no matching approval to a disallowed host. The trace is invented demonstration evidence. Reports include every call's policy findings and can be exported with the exact input.

Request shape: see `examples/synthetic-trace.json`. Every event has a unique `event_id`, an `action` of `approve` or `call`, and a `call_id`. A call additionally has `tool` and optional absolute HTTP(S) `url`. Event/call identifiers use 1–100 ASCII letters/digits or `_ . : -`, starting with a letter/digit. Call IDs must be unique among calls; approvals must name an existing exact call ID, at most once. Unknown approval targets, duplicate calls/events, unsupported actions/fields and malformed URLs are rejected with HTTP 422. A `confirmed:true` property cannot substitute for an approval event.

Array order is authoritative. An approval authorizes only its exact call ID and must appear **before** that call. It is not a reusable token and a later approval cannot retroactively authorize a call. With `confirmation_required:false`, prior approval is not required. Allowed tool names are explicit and case-sensitive. Disallowed tools produce `TOOL_NOT_ALLOWED`; missing approval produces `MISSING_PRIOR_APPROVAL`.

Hosts are IDNA-normalized, lowercased and stripped of a trailing dot, then compared exactly. An allowlist entry does not implicitly authorize subdomains or lookalikes. `http`/`browser` calls require a URL; other tools with a supplied URL are also checked. Missing network target and disallowed host produce typed findings. Custom tool behavior is not inferred: if its URL is omitted the scanner cannot inspect its network behavior. Ports are not restricted. Wildcards, URL credentials, invalid hosts and non-HTTP schemes are rejected. No DNS resolution, redirects, tool arguments, actual approvals or executor enforcement are verified.

At most 500 events; each call has at most 3 policy findings and bounded IDs/host fields. No tool runs, no network request is made from a trace, and a passing report is not a security certification or evidence that omitted actions did not occur. Input/report exports can contain URLs and sensitive evidence; review before sharing.
