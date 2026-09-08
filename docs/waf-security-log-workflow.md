# WAF security-log correlation workflow

This workflow connects a replayed `nemesida/waf-bypass` case to WAF security telemetry without fuzzy matching on URI or payload.

## Identifiers

The tool uses three identifiers:

- `case_id` — stable identity of the imported request variant. It is derived from `payload_path`, `variant`, and the original cURL hash.
- `replay_run_id` — unique identity of one `verify`/`recheck` invocation.
- `test_id` — unique identity of one HTTP replay observation.

During real replay the tool adds this header without changing the stored original cURL:

```text
waf-fp-test-id: <test_id>
```

The WAF security log exposes that header as `test_id`, so the primary join is exact:

```text
verified.jsonl.test_id == security_log.test_id
```

If available, a WAF-generated `x-waf-request-id` can be exported as `x_waf_request_id`, `waf_request_id`, or `request_id`. It is stored as a secondary WAF-side identifier, not used as the primary join key.

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

Each replay record now contains `case_id`, `replay_run_id`, `test_id`, `correlation_header`, and `correlation_sent`.

## 2. Export matching WAF security logs

JSONEachRow/JSONL is the recommended exchange format. A typical ClickHouse export should contain these fields when available:

```text
test_id
rule_details
rule_numbers
scores
vendors
request_host
client_status
origin_status
runtime_anomaly_threshold
anomaly_score
runtime_blocking_mode
request_uri_redacted
phase_terminated
verdict
decision_source
content_type_detected
method
path_template
x_waf_request_id
```

Prefer filtering the export to the relevant replay IDs or `wba-...` test IDs. Extra rows are allowed and are reported as orphan security-log rows.

The parser accepts:

- JSONEachRow / JSONL;
- a JSON array of row objects;
- a JSON object containing a `rows`, `data`, or `result` array.

`rule_details` is the primary rule telemetry source. Both native JSON arrays and ClickHouse-style string representations such as the following are accepted:

```text
[('1019',7,'baseline-handwritten'),('941210',5,'crs4')]
```

If `rule_details` is absent or cannot produce rule objects, the tool falls back to the index-correlated `rule_numbers`, `scores`, and `vendors` arrays.

## 3. Correlate replay and security log

```bash
python waf_bypass_tool.py correlate-logs \
  --replay work/verified.jsonl \
  --security-log work/security-log.jsonl \
  --output work/observations.jsonl
```

Correlation statuses:

- `MATCHED` — exactly one security-log row matched the `test_id`;
- `LOG_NOT_FOUND` — replay has a `test_id`, but no log row was found;
- `MISSING_REPLAY_TEST_ID` — legacy replay record has no correlation ID;
- `MULTIPLE_LOG_MATCHES` — more than one security-log row has the same `test_id`; no row is selected silently.

A matched observation contains normalized `security_log.matched_rules` objects:

```json
{
  "rule_id": "2084",
  "score": 5,
  "vendor": "baseline-handwritten"
}
```

## 4. Diagnose observations

```bash
python waf_bypass_tool.py diagnose \
  --input work/observations.jsonl \
  --output work/diagnosed.jsonl
```

Current diagnoses:

- `BLOCKED` — WAF security telemetry confirms a block by the rule-engine path;
- `BLOCKED_OTHER_SOURCE` — blocked, but `RuleEngine` is not a reported decision source;
- `WOULD_BLOCK` — threshold was reached or WAF explicitly returned `ShadowWouldBlock`, but policy/mode did not enforce the block;
- `SCORING_GAP` — one or more rules detected the request, but accumulated score remained below threshold;
- `DETECTION_GAP` — anomaly score is zero and no matched rules exist;
- `ROUTE_MISMATCH` — replay routing result is inconsistent;
- `LOG_NOT_FOUND` — no unique telemetry row was available;
- `CHECK_ERROR` — replay failed;
- `NEEDS_REVIEW` — telemetry is ambiguous, incomplete, duplicated, or internally inconsistent.

The command prints aggregate counts and counts by attack category and writes the diagnosis plus a human-readable `diagnosis_reason` back into each JSONL record.

## Intended handoff to waf-rule-engineering

The diagnosed corpus is evidence, not an automatic rule generator. In particular:

- `DETECTION_GAP` cases are candidates for new/expanded detection primitives;
- `SCORING_GAP` cases should first trigger scoring/combination review rather than blind regex expansion;
- `WOULD_BLOCK` cases usually indicate policy/mode behavior rather than missing detection;
- `BLOCKED_OTHER_SOURCE` should not be counted as successful coverage by the YAML ruleset without further review;
- `NEEDS_REVIEW` must not be automatically converted into rule changes.

A later export layer can convert selected diagnosed cases into the inline/regression test format used by `waf-rule-engineering` while preserving `case_id` as the cross-project stable identity.
