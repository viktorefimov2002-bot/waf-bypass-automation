# WAF security-log correlation workflow

This workflow connects a replayed `nemesida/waf-bypass` case to WAF security telemetry without fuzzy matching on URI or payload.

## Source-of-truth model

`verify` and the WAF security log answer different questions:

- replay HTTP response tells us what the client observed and whether the known origin signature was seen;
- security telemetry joined by `test_id` tells us what the WAF actually decided, which rules matched, and how much score accumulated.

The replay layer must not infer a WAF decision from an absent `Server` header.

For the current environment the origin is recognized by:

```text
Server: nginx/1.24.0 (Ubuntu)
```

A blocked response normally has no `Server` header. That absence is recorded only as `NO_ORIGIN_SIGNATURE`; it is not treated as proof that the WAF blocked the request.

## Identifiers

The tool uses three identifiers:

- `case_id` — stable identity of the imported request variant;
- `replay_run_id` — unique identity of one `verify`/`recheck` invocation;
- `test_id` — unique identity of one concrete HTTP replay.

During real replay the tool adds:

```text
waf-fp-test-id: <test_id>
```

The primary correlation is exact:

```text
verified.jsonl.test_id == security_log.test_id
```

If available, `x-waf-request-id` may be exported as `x_waf_request_id`, `waf_request_id`, or `request_id`. It is secondary evidence, not the primary join key.

## 1. Import and verify

```bash
python waf_bypass_tool.py import \
  --report waf-bypass.json \
  --groups groups.txt \
  --taxonomy config/taxonomy.json \
  --output work/imported.jsonl
```

```bash
python waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output work/verified.jsonl
```

Each replay record contains `case_id`, `replay_run_id`, `test_id`, `correlation_header`, and `correlation_sent`.

Real replay also records cURL connection evidence:

```text
remote_ip
local_ip
url_effective
```

These values help diagnose DNS, proxy, IPv4/IPv6 and routing differences.

### Replay route verdicts

Current route evidence:

- `ORIGIN_CONFIRMED` — response `Server` contains `nginx` or `Ubuntu`;
- `NO_ORIGIN_SIGNATURE` — no `Server` header was present;
- `ROUTE_OTHER` — a different non-empty `Server` value was observed;
- `ROUTE_UNCONFIRMED` — replay itself failed before a usable response was obtained.

There is intentionally no `WAF_CONFIRMED` route inferred from response headers.

### Replay final verdicts

- `BYPASS_CONFIRMED` — non-blocking response and the origin signature is present;
- `BYPASS_UNCONFIRMED` — non-blocking response without the known origin signature;
- `HTTP_BLOCK_OBSERVED` — a configured block HTTP code was observed, but response headers do not prove who produced it;
- `ORIGIN_BLOCK_RESPONSE` — a configured block HTTP code was returned together with the known origin signature;
- `CHECK_ERROR` — cURL failed or no usable HTTP status was obtained;
- `DRY_RUN` — request was not sent.

`BLOCKED_BY_WAF` is retained only as a legacy value for previously generated artifacts. New replay runs do not emit it.

## 2. Export matching WAF security logs

JSONEachRow/JSONL is the recommended exchange format.

### Minimum fields for deterministic coverage diagnosis

```text
test_id
rule_details
runtime_anomaly_threshold
anomaly_score
runtime_blocking_mode
verdict
decision_source
```

Strongly recommended context:

```text
client_status
origin_status
phase_terminated
request_host
request_uri_redacted
method
path_template
content_type_detected
x_waf_request_id
```

Optional fallback telemetry:

```text
rule_numbers
scores
vendors
```

`rule_details` is the primary source for rule ID, score and vendor. The three arrays above are used only as fallback.

Prefer selecting rows by `test_id` or a `replay_run_id` prefix, not by `client_status`. Filtering permanently on `client_status != 403` would discard successfully fixed cases during later validation.

## 3. Correlate replay and security log

```bash
python waf_bypass_tool.py correlate-logs \
  --replay work/verified.jsonl \
  --security-log work/security-log.jsonl \
  --output work/observations.jsonl
```

Correlation statuses:

- `MATCHED` — exactly one row matched the `test_id`;
- `LOG_NOT_FOUND` — no matching row exists;
- `MISSING_REPLAY_TEST_ID` — legacy replay record has no correlation ID;
- `MULTIPLE_LOG_MATCHES` — duplicate `test_id` rows exist and no match is selected silently.

## 4. Diagnose observations

```bash
python waf_bypass_tool.py diagnose \
  --input work/observations.jsonl \
  --output work/diagnosed.jsonl
```

Security-log verdict is authoritative for WAF behavior.

Current diagnoses:

- `BLOCKED` — security telemetry confirms WAF block;
- `BLOCKED_OTHER_SOURCE` — request was blocked but `RuleEngine` is not a decision source;
- `WOULD_BLOCK` — threshold was reached or `ShadowWouldBlock` was reported without enforced block;
- `SCORING_GAP` — rules matched but accumulated score stayed below threshold;
- `DETECTION_GAP` — no rule contributed score;
- `ROUTE_MISMATCH` — retained for legacy replay artifacts;
- `LOG_NOT_FOUND` — no unique telemetry row exists;
- `CHECK_ERROR` — replay failed;
- `NEEDS_REVIEW` — replay/security telemetry is ambiguous or contradictory.

Examples:

```text
HTTP 403 + no Server + security verdict Block
    -> BLOCKED

HTTP 403 + no Server + security verdict Allow + score 0
    -> DETECTION_GAP
    (the HTTP block came from somewhere else; WAF did not detect it)

HTTP 200 + nginx + security verdict Allow + score 5 / threshold 7
    -> SCORING_GAP

HTTP 200 + nginx + security verdict Block
    -> NEEDS_REVIEW
    (origin evidence contradicts WAF Block telemetry)
```

## 5. validate-fix semantics

New replay results no longer mark a case `FIXED` solely because a block-like HTTP status was observed.

For new artifacts:

```text
HTTP_BLOCK_OBSERVED  -> NEEDS_REVIEW until security telemetry is correlated
ORIGIN_BLOCK_RESPONSE -> NEEDS_REVIEW
BYPASS_CONFIRMED     -> STILL_BYPASSED
CHECK_ERROR          -> ERROR
```

Legacy `BLOCKED_BY_WAF` remains readable as `FIXED` for backward compatibility, but new runs do not generate that verdict.

The intended authoritative post-fix flow is therefore:

```text
validate/replay
    -> correlate-logs
    -> diagnose
```

A case is confirmed blocked by the WAF only when the joined security log says `Block`.

## 6. Export neutral evidence to waf-rule-engineering

```bash
python waf_bypass_tool.py export-corpus \
  --input work/diagnosed.jsonl \
  --output-dir work/rule-engineering-corpus
```

Default export includes:

```text
DETECTION_GAP
SCORING_GAP
```

The handoff remains evidence rather than automatic YAML generation. `waf-rule-engineering` stays the source of truth for DSL-specific rules and tests.
