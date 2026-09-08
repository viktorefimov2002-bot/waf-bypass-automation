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

JSONEachRow/JSONL is the recommended exchange format.

### Field contract

Minimum fields required for deterministic coverage diagnosis:

```text
test_id
rule_details
runtime_anomaly_threshold
anomaly_score
runtime_blocking_mode
verdict
decision_source
```

Strongly recommended context fields:

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

Optional/redundant fields:

```text
rule_numbers
scores
vendors
```

`rule_details` is the primary source for rule ID, score and vendor. `rule_numbers`, `scores`, and `vendors` are only fallback telemetry and may be omitted if `rule_details` is reliable.

Extra fields are harmless. Unknown keys in security-log rows are ignored by the current normalizer, so it is safer to export a slightly wider row than to aggressively prune useful context.

### Which rows to export

The preferred selection key is `test_id`, not HTTP status.

For initial bypass analysis, `verified.jsonl` already contains only the replay cases you decided to analyze. Export security-log rows for those `test_id` values, or for the relevant `replay_run_id`/`wba-...` ID prefix. This still yields only the bypass test population while avoiding assumptions about `client_status`, origin responses, monitor/shadow modes, or non-standard block codes.

Do not make `client_status != 403` the permanent correlation contract. That filter is acceptable as a temporary convenience for the first bypass-only analysis, but it breaks the later `validate-fix` workflow because successfully fixed cases are expected to become blocked. The stable contract is always:

```text
replay test_id -> security-log test_id
```

Extra security-log rows are allowed and are reported as orphan rows.

The parser accepts:

- JSONEachRow / JSONL;
- a JSON array of row objects;
- a JSON object containing a `rows`, `data`, or `result` array.

`rule_details` accepts both native JSON arrays and ClickHouse-style string representations such as:

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

## 5. Export a neutral corpus for waf-rule-engineering

The automation project deliberately does not generate YAML rules or DSL-specific inline tests. Instead it emits a neutral evidence corpus that `waf-rule-engineering` can consume using its own DSL documentation and rule-design methodology.

By default only the two actionable rule-engineering classes are exported:

```bash
python waf_bypass_tool.py export-corpus \
  --input work/diagnosed.jsonl \
  --output-dir work/rule-engineering-corpus
```

Default diagnoses:

```text
DETECTION_GAP
SCORING_GAP
```

To export another class explicitly, repeat `--diagnosis`:

```bash
python waf_bypass_tool.py export-corpus \
  --input work/diagnosed.jsonl \
  --diagnosis DETECTION_GAP \
  --diagnosis SCORING_GAP \
  --diagnosis BLOCKED \
  --output-dir work/rule-engineering-corpus
```

Output:

```text
cases.jsonl
manifest.json
detection-gap.jsonl
scoring-gap.jsonl
...additional selected diagnosis files
```

Each handoff case preserves:

- stable `case_id` and concrete replay `test_id`;
- source payload file/category/group/variant;
- raw and normalized payload plus normalization trace;
- exact stored cURL and request metadata;
- replay HTTP/routing result;
- WAF threshold, anomaly score, verdict, mode and matched-rule evidence;
- diagnosis and recommended workstream.

Examples of recommended workstreams:

```text
DETECTION_GAP -> detection-design
SCORING_GAP   -> scoring-review
BLOCKED       -> regression-reference
WOULD_BLOCK   -> policy-review
```

The manifest explicitly records that automatic rule generation is disabled.

## Intended handoff to waf-rule-engineering

The diagnosed/exported corpus is evidence, not an automatic rule generator. In particular:

- `DETECTION_GAP` cases are candidates for new/expanded detection primitives and corresponding regression tests;
- `SCORING_GAP` cases should first trigger scoring/combination review rather than blind regex expansion;
- `WOULD_BLOCK` cases usually indicate policy/mode behavior rather than missing detection;
- `BLOCKED` cases are useful as positive regression references after a fix;
- `BLOCKED_OTHER_SOURCE` should not be counted as successful coverage by the YAML ruleset without further review;
- `NEEDS_REVIEW` must not be automatically converted into rule changes.

`case_id` is the cross-project identity. Once a case is represented as a YAML inline/regression test inside `waf-rule-engineering`, that identity should be preserved in test metadata or comments so later replay results can be compared back to the original evidence.
