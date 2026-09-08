# waf-bypass automation

CLI-инструмент для нормализации результатов `nemesida-waf/waf-bypass`, безопасного replay запросов, корреляции с WAF security logs и подготовки нейтрального evidence corpus для `waf-rule-engineering`.

Основной принцип текущей архитектуры:

```text
scanner corpus
    -> import
    -> verify/replay
    -> correlate-logs
    -> diagnose
    -> export-corpus
    -> waf-rule-engineering
```

`waf-bypass-automation` отвечает за запросы, replay, telemetry correlation и diagnosis. YAML DSL и финальная логика WAF-правил остаются зоной ответственности `waf-rule-engineering`.

## Требования

- Python 3.11+
- `curl`
- зависимости из `requirements.txt`

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Запуск:

```bash
python waf_bypass_tool.py --help
```

## 1. Import

```bash
python waf_bypass_tool.py import \
  --report waf-bypass.json \
  --groups groups.txt \
  --taxonomy config/taxonomy.json \
  --output work/imported.jsonl
```

Импортируются `BYPASSED` и `cURL.BYPASSED`. Каждый вариант запроса становится отдельной JSONL-записью.

Для каждого testcase формируется стабильный `case_id`, который сохраняется между повторными replay одного и того же варианта.

## 2. Verify / replay

Реальная отправка запросов выполняется только с `--execute`:

```bash
python waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --timeout 15 \
  --delay 0.2 \
  --output work/verified.jsonl \
  --report-xlsx work/verified.xlsx
```

Без `--execute` выполняется dry-run, и запросы не отправляются.

`recheck` сохранён как deprecated alias команды `verify`.

### Correlation ID

Каждый реальный replay получает:

- `replay_run_id` — ID всего запуска;
- `test_id` — ID конкретного HTTP-запроса.

Во время выполнения cURL добавляется:

```text
waf-fp-test-id: <test_id>
```

Исходный cURL в corpus при этом не переписывается.

### Безопасность replay

- `subprocess` используется с `shell=False`;
- локальные `@file` запрещены;
- неизвестные cURL options блокируются;
- redirects запрещены;
- требуется точный `--allow-host` при `--execute`;
- исходные URL, методы, headers и body не переписываются, кроме runtime correlation header.

## HTTP response semantics

Response headers используются только как клиентское/маршрутное наблюдение. Они больше не считаются источником истины о решении WAF.

Для текущего стенда origin определяется по:

```text
Server: nginx/1.24.0 (Ubuntu)
```

Маршрутные статусы:

| Наблюдение | `route_verdict` |
|---|---|
| `Server` содержит `nginx` или `Ubuntu` | `ORIGIN_CONFIRMED` |
| `Server` отсутствует | `NO_ORIGIN_SIGNATURE` |
| присутствует другой `Server` | `ROUTE_OTHER` |
| replay завершился ошибкой | `ROUTE_UNCONFIRMED` |

Важно: отсутствие `Server` **не означает автоматически**, что запрос заблокировал WAF.

Итоговые replay verdicts:

| HTTP/маршрут | `final_verdict` |
|---|---|
| non-block code + origin signature | `BYPASS_CONFIRMED` |
| non-block code без origin signature | `BYPASS_UNCONFIRMED` |
| block code без origin signature | `HTTP_BLOCK_OBSERVED` |
| block code + origin signature | `ORIGIN_BLOCK_RESPONSE` |
| ошибка cURL / нет HTTP status | `CHECK_ERROR` |
| запуск без `--execute` | `DRY_RUN` |

`BLOCKED_BY_WAF` больше не создаётся новыми replay. Значение поддерживается только для чтения старых артефактов.

Коды блокировки берутся из `BLOCK-CODE` исходного отчёта и не обязаны быть равны 403.

### Route diagnostics

В real replay дополнительно сохраняются:

```text
remote_ip
local_ip
url_effective
```

Это позволяет быстро отличать проблемы replay от DNS/proxy/IPv4/IPv6/маршрутизации.

## 3. Security-log correlation

Security log является источником истины для WAF decision.

Рекомендуемый набор полей:

```text
test_id
rule_details
runtime_anomaly_threshold
anomaly_score
runtime_blocking_mode
verdict
decision_source
client_status
origin_status
phase_terminated
request_host
request_uri_redacted
method
path_template
content_type_detected
```

Опционально:

```text
rule_numbers
scores
vendors
x_waf_request_id
```

Рекомендуется экспортировать ClickHouse данные в JSONEachRow/JSONL и выбирать строки по `test_id` или `replay_run_id`, а не по HTTP-коду.

Корреляция:

```bash
python waf_bypass_tool.py correlate-logs \
  --replay work/verified.jsonl \
  --security-log work/security-log.jsonl \
  --output work/observations.jsonl
```

Primary join:

```text
verified.jsonl.test_id == security_log.test_id
```

Поддерживаемые correlation statuses:

- `MATCHED`
- `LOG_NOT_FOUND`
- `MISSING_REPLAY_TEST_ID`
- `MULTIPLE_LOG_MATCHES`

Duplicate `test_id` не разрешаются автоматически.

## 4. Diagnosis

```bash
python waf_bypass_tool.py diagnose \
  --input work/observations.jsonl \
  --output work/diagnosed.jsonl
```

Основные diagnosis classes:

- `BLOCKED` — security log подтверждает WAF block;
- `BLOCKED_OTHER_SOURCE` — block есть, но `RuleEngine` не является decision source;
- `WOULD_BLOCK` — threshold достигнут, но policy/mode не применил block;
- `SCORING_GAP` — детекторы сработали, но score ниже threshold;
- `DETECTION_GAP` — anomaly score = 0 и matched rules отсутствуют;
- `LOG_NOT_FOUND`;
- `CHECK_ERROR`;
- `NEEDS_REVIEW`.

Примеры:

```text
HTTP 403 + Server отсутствует + security verdict Block
    -> BLOCKED

HTTP 403 + Server отсутствует + security verdict Allow + anomaly_score 0
    -> DETECTION_GAP

HTTP 200 + nginx + anomaly_score 5 / threshold 7
    -> SCORING_GAP

HTTP 200 + nginx + security verdict Block
    -> NEEDS_REVIEW
```

То есть HTTP 403 сам по себе больше не считается доказательством успешной блокировки WAF.

## 5. Export corpus to waf-rule-engineering

```bash
python waf_bypass_tool.py export-corpus \
  --input work/diagnosed.jsonl \
  --output-dir work/rule-engineering-corpus
```

По умолчанию экспортируются:

```text
DETECTION_GAP
SCORING_GAP
```

Corpus сохраняет:

- `case_id` / `test_id`;
- payload и normalization evidence;
- request/cURL;
- replay response;
- WAF score, threshold, verdict и matched rules;
- diagnosis;
- recommended workstream.

Автоматическая генерация YAML rules отключена архитектурно: evidence передаётся в `waf-rule-engineering`, где используются актуальная DSL-документация, scoring policy и regression tests.

## 6. validate-fix

Legacy workflow `validate-fix` остаётся доступен:

```bash
python waf_bypass_tool.py validate-fix \
  --before work/verified.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output-jsonl work/fix-validation.jsonl \
  --output-xlsx work/fix-validation.xlsx
```

Новая семантика:

```text
BYPASS_CONFIRMED      -> STILL_BYPASSED
HTTP_BLOCK_OBSERVED    -> NEEDS_REVIEW
ORIGIN_BLOCK_RESPONSE  -> NEEDS_REVIEW
CHECK_ERROR            -> ERROR
```

Старый `BLOCKED_BY_WAF` по-прежнему читается как `FIXED` для обратной совместимости, но новые replay его не создают.

Для достоверной проверки исправления рекомендуется:

```text
validate/replay
    -> correlate-logs
    -> diagnose
```

и считать исправление подтверждённым WAF только при security-log verdict `Block`.

## Legacy SecLang helpers

Команды `suggest-rules` и `refine-rules` сохранены для обратной совместимости с ранними версиями проекта, но не являются целевой архитектурой интеграции с `waf-rule-engineering`.

## Подробная документация

Полный контракт security-log correlation и replay semantics находится в:

```text
docs/waf-security-log-workflow.md
```
