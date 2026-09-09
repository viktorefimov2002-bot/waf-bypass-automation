# waf-bypass automation

CLI-инструмент для обработки JSON-отчётов `nemesida-waf/waf-bypass`, повторной проверки найденных bypass, корреляции replay с WAF security log и подготовки нейтрального evidence corpus для `waf-rule-engineering`.

Инструмент не должен автоматически менять YAML-правила или повышать score. Источник истины для DSL-specific rule design остаётся в `waf-rule-engineering`.

## Требования

- Python 3.11+
- установленный `curl`
- зависимости из `requirements.txt`

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Запуск из корня проекта:

```bash
python waf_bypass_tool.py --help
```

## Основной рабочий процесс

### 1. Импорт

```bash
python waf_bypass_tool.py import \
  --report waf-bypass.json \
  --groups groups.txt \
  --taxonomy config/taxonomy.json \
  --output work/imported.jsonl
```

Каждый вариант запроса сохраняется отдельной JSONL-записью. `case_id` стабилен для одного импортированного request variant.

### 2. Replay / verify

```bash
python waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output work/verified.jsonl
```

Без `--execute` выполняется dry-run.

При реальном replay утилита:

- запускает `curl` через `subprocess`, `shell=False`;
- добавляет `x-waf-fp-test-id: <test_id>`;
- автоматически добавляет `--globoff`, чтобы payload с буквальными `[`/`]` не ломал cURL URL parsing;
- не следует redirects;
- запрещает опасные/неизвестные cURL options и чтение локальных `@file`;
- сохраняет `remote_ip`, `local_ip`, `url_effective`.

Чтобы повторить только ранее упавшие replay:

```bash
python waf_bypass_tool.py verify \
  --input work/verified.jsonl \
  --only-verdict CHECK_ERROR \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output work/retried-check-errors.jsonl
```

`--only-verdict` можно повторять для нескольких prior verdict values.

### Replay response semantics

Response headers используются только как HTTP/route evidence.

- `Server: nginx/...Ubuntu` → `ORIGIN_CONFIRMED`;
- пустой `Server` → `NO_ORIGIN_SIGNATURE`;
- никакого `WAF_CONFIRMED` по заголовкам нет.

Новые replay verdicts:

- `BYPASS_CONFIRMED`;
- `BYPASS_UNCONFIRMED`;
- `HTTP_BLOCK_OBSERVED`;
- `ORIGIN_BLOCK_RESPONSE`;
- `CHECK_ERROR`;
- `DRY_RUN`.

`BLOCKED_BY_WAF` читается только для обратной совместимости со старыми артефактами. Факт WAF block подтверждается security log.

### 3. Correlate security log

```bash
python waf_bypass_tool.py correlate-logs \
  --replay work/verified.jsonl \
  --security-log work/security-log.jsonl \
  --output work/observations.jsonl
```

Primary join:

```text
verified.test_id == security_log.test_id
```

Не используется fuzzy correlation по URI/payload/status.

### 4. Diagnose

```bash
python waf_bypass_tool.py diagnose \
  --input work/observations.jsonl \
  --output work/diagnosed.jsonl
```

Security log является источником истины для WAF decision.

Основные diagnosis classes:

- `BLOCKED`;
- `BLOCKED_OTHER_SOURCE`;
- `WOULD_BLOCK`;
- `SCORING_GAP`;
- `DETECTION_GAP`;
- `LOG_NOT_FOUND`;
- `CHECK_ERROR`;
- `NEEDS_REVIEW`.

`SCORING_GAP` — coarse observation-level label: сам по себе он не означает, что score найденного rule надо повышать.

### 5. Analyze related variants

Перед изменением YAML rules/scoring запускается сравнительный анализ:

```bash
python waf_bypass_tool.py analyze-gaps \
  --input work/diagnosed.jsonl \
  --output-dir work/gap-analysis
```

Кластеризация идёт по `payload_path`, поэтому ARGS/BODY/COOKIE/HEADER и разные encoding одного logical payload рассматриваются вместе.

Основные flags:

- `NORMALIZATION_GAP_CANDIDATE`;
- `TARGET_GAP_CANDIDATE`;
- `PARTIAL_DETECTION_CANDIDATE`;
- `SCORING_REVIEW_CANDIDATE`;
- `PURE_DETECTION_GAP`;
- `REPLAY_ERROR_PRESENT`.

Важно: normalization/target/scoring labels являются **candidate evidence**, а не автоматическим root-cause verdict. Для настоящего scoring-only gap требуется rule metadata, подтверждающая релевантность matched rule конкретному attack primitive.

Output:

```text
work/gap-analysis/
  clusters.jsonl
  cases.jsonl
  manifest.json
  normalization-gap-candidates.jsonl
  target-gap-candidates.jsonl
  pure-detection-gap-clusters.jsonl
  partial-detection-candidates.jsonl
  scoring-review-candidates.jsonl
  replay-error-clusters.jsonl
```

### 6. Handoff в waf-rule-engineering

После `analyze-gaps` рекомендуется экспортировать enriched cases:

```bash
python waf_bypass_tool.py export-corpus \
  --input work/gap-analysis/cases.jsonl \
  --output-dir work/rule-engineering-corpus
```

Default export содержит `DETECTION_GAP` и `SCORING_GAP`, но если `gap_analysis` присутствует, его `primary_workstream` имеет приоритет над coarse diagnosis. Например `SCORING_GAP` может корректно уйти как `normalization-review`, а не `scoring-review`.

Automatic YAML generation и automatic score increase отключены политикой handoff.

### 7. Повторная проверка после rule changes

После ручного rule engineering и deployment повторяется тот же evidence cycle:

```text
verify/replay
  -> correlate-logs
  -> diagnose
  -> analyze-gaps
  -> diff by case_id
```

Новый `HTTP_BLOCK_OBSERVED` не считается автоматически `FIXED`. Подтверждённый WAF block — только security-log `verdict=Block`.

## Дополнительные команды

Создание компактного XLSX:

```bash
python waf_bypass_tool.py report \
  --input work/verified.jsonl \
  --output work/verified.xlsx
```

Diff двух запусков:

```bash
python waf_bypass_tool.py diff \
  --before work/before.jsonl \
  --after work/after.jsonl \
  --output-jsonl work/diff.jsonl \
  --output-xlsx work/diff.xlsx
```

Legacy `suggest-rules`, `refine-rules` и `validate-fix` остаются доступными для обратной совместимости, но основной интеграционный путь с `waf-rule-engineering` — через correlated/diagnosed/gap-analyzed evidence corpus.

Подробная модель telemetry/correlation описана в `docs/waf-security-log-workflow.md`.
