# waf-bypass automation

CLI-инструмент для обработки JSON-отчётов `nemesida-waf/waf-bypass`, повторной проверки найденных bypass, подготовки кандидатов SecLang/CRS-правил и контроля их покрытия после внедрения.

Инструмент не подключает правила к WAF автоматически. Генерируемые правила являются кандидатами для ручного review, проверки совместимости, тестирования ложных срабатываний и последующего контролируемого развёртывания.

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

## Полный рабочий процесс

### 1. Импорт отчёта сканера

```bash
python waf_bypass_tool.py import \
  --report waf-bypass.json \
  --groups groups.txt \
  --taxonomy config/taxonomy.json \
  --output work/imported.jsonl
```

Импортируются записи из разделов `BYPASSED` и `cURL.BYPASSED`.

Каждый вариант запроса сохраняется отдельной JSONL-записью. Устойчивый ключ записи:

```text
payload_path::variant
```

Примеры классификации:

```text
XSS/25.json  -> XSS  -> группа 85
SQLi/7.json  -> SQLi -> группа 81
UWA/4.json   -> UWA  -> группа 86
```

`config/overrides.json` для стандартного процесса не требуется. Параметр `--overrides` оставлен как fallback для неизвестных категорий и обратной совместимости.

### 2. Первичная проверка импортированных запросов

Рекомендуемая команда — `verify`:

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

Команда `recheck` пока поддерживается, но является deprecated-алиасом `verify`:

```bash
python waf_bypass_tool.py recheck \
  --input work/imported.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --timeout 15 \
  --delay 0.2 \
  --output work/verified.jsonl \
  --report-xlsx work/verified.xlsx
```

Проверка только одной группы:

```bash
python waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --group 85 \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output work/verified-xss.jsonl \
  --report-xlsx work/verified-xss.xlsx
```

Тестовый запуск первых пяти запросов:

```bash
python waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --limit 5 \
  --timeout 5 \
  --delay 0 \
  --output work/verified-test.jsonl \
  --report-xlsx work/verified-test.xlsx
```

Без `--execute` выполняется dry-run: запросы не отправляются.

При реальном выполнении обязателен точный `--allow-host`. Он проверяет host в исходном URL, но не переписывает DNS, IP назначения или маршрут запроса.

#### Защита replay

- shell не используется;
- cURL запускается через `subprocess` с `shell=False`;
- чтение локальных файлов через `@file` запрещено;
- неизвестные параметры cURL блокируются;
- `-L/--location` запрещены;
- redirects не отслеживаются (`--max-redirs 0`);
- исходные URL, методы, заголовки и тела запросов не переписываются.

#### Параметры verify/recheck

- `--group ID` — только одна группа;
- `--limit N` — ограничить число запросов;
- `--timeout SEC` — максимальное время одного cURL, по умолчанию 15 секунд;
- `--delay SEC` — пауза между запросами, по умолчанию 0.2 секунды;
- `--report-xlsx PATH` — дополнительно создать компактный XLSX.

### Вердикты проверки

Для текущего стенда маршрут определяется по HTTP-коду и заголовку `Server`:

| HTTP-код | `Server` | Итог |
|---|---|---|
| код из `BLOCK-CODE` | `pingora` | `BLOCKED_BY_WAF` |
| не блокирующий код | `nginx` или `Ubuntu` | `BYPASS_CONFIRMED` |
| не блокирующий код | `pingora` | `BYPASS_UNCONFIRMED` |
| блокирующий код с origin или неизвестным маршрутом | другое значение | `ROUTE_MISMATCH` |
| timeout, ошибка cURL или отсутствие кода | — | `CHECK_ERROR` |

Коды блокировки берутся из поля `BLOCK-CODE` исходного отчёта, а не всегда считаются равными `403`.

Важно: заголовок `Server` является стендоспецифичным индикатором. Если WAF сохраняет заголовок origin или используется несколько нод, маршрут следует дополнительно подтверждать по WAF access/security logs и фактическому `remote_ip`.

Компактный XLSX содержит:

- `Summary` — общие счётчики;
- `Groups` — статистику по группам;
- `Results` — подробные результаты запросов.

### 3. Генерация кандидатов SecLang

```bash
rm -rf work/rules

python waf_bypass_tool.py suggest-rules \
  --input work/verified.jsonl \
  --id-start 999000 \
  --output-dir work/rules
```

Обрабатываются подтверждённые bypass-записи. Генератор выполняет извлечение и нормализацию payload, классификацию exploit primitive и объединение совместимых случаев.

Основные выходные файлы:

- `candidate-rules.conf` — кандидаты SecLang;
- `coverage.csv` — соответствие подтверждённых bypass конкретным правилам;
- `coverage.jsonl` — тот же индекс в JSONL;
- `skipped.csv`/`skipped.jsonl` — записи, для которых кандидат не был создан;
- `manifest.json` — rule ID, primitive, target, pattern, transforms и статистика покрытия.

Правила могут объединять несколько совместимых зон, например:

```apache
SecRule ARGS|REQUEST_COOKIES "@rx ..." \
    "id:999000,phase:2,deny,status:403,..."
```

#### Проверки перед загрузкой правил

Проверить отсутствие legacy-несовместимого класса для backslash:

```bash
grep -nF '[\\]' work/rules/candidate-rules.conf
```

Команда не должна вернуть результатов.

Проверить отсутствие текстовых regex escapes вида `\uXXXX`:

```bash
grep -nE '\\u[0-9a-fA-F]{4,8}' work/rules/candidate-rules.conf
```

Команда также не должна вернуть результатов.

Каждый кандидат требует ручной проверки:

1. синтаксиса SecLang и загрузки текущим converter/loader;
2. поддержки targets, operators, regex и transformations текущим data plane;
3. покрытия положительных запросов из `coverage.csv`;
4. ложных срабатываний на легитимном трафике;
5. производительности тяжёлых цепочек декодирования;
6. корректности диапазона Rule ID.

Не разворачивайте весь файл сразу без предварительного review и тестового режима логирования/anomaly scoring.

### 4. Проверка после внедрения правил

После ручного review, загрузки и развёртывания правил запускается `validate-fix`.

Чтобы повторить только запросы, для которых созданы кандидаты правил, обязательно передавайте `coverage.csv`:

```bash
python waf_bypass_tool.py validate-fix \
  --before work/verified.jsonl \
  --coverage work/rules/coverage.csv \
  --manifest work/rules/manifest.json \
  --execute \
  --allow-host jutcy.glazapp.com \
  --timeout 15 \
  --delay 0.2 \
  --output-jsonl work/fix-validation.jsonl \
  --output-xlsx work/fix-validation.xlsx
```

Тест первых пяти покрытых запросов:

```bash
python waf_bypass_tool.py validate-fix \
  --before work/verified.jsonl \
  --coverage work/rules/coverage.csv \
  --manifest work/rules/manifest.json \
  --execute \
  --allow-host jutcy.glazapp.com \
  --limit 5 \
  --timeout 5 \
  --delay 0 \
  --output-jsonl work/fix-validation-test.jsonl \
  --output-xlsx work/fix-validation-test.xlsx
```

Только одна группа:

```bash
python waf_bypass_tool.py validate-fix \
  --before work/verified.jsonl \
  --coverage work/rules/coverage.csv \
  --manifest work/rules/manifest.json \
  --group 85 \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output-jsonl work/xss-fix-validation.jsonl \
  --output-xlsx work/xss-fix-validation.xlsx
```

Перед replay команда показывает число подтверждённых, покрытых и пропущенных запросов. Во время выполнения отображается прогресс по каждому запросу.

Промежуточные файлы:

- `fix-validation.eligible.jsonl` — запросы, выбранные по `coverage.csv`;
- `fix-validation.replayed.jsonl` — сырые результаты replay, дописываемые после каждого запроса;
- `fix-validation.jsonl` — итоговое сопоставление с rule metadata;
- `fix-validation.xlsx` — итоговый отчёт.

Наблюдение за результатами в другом терминале:

```bash
tail -f work/fix-validation.replayed.jsonl
```

Статусы:

- `FIXED` — запрос теперь блокируется WAF;
- `STILL_BYPASSED` — bypass подтверждается повторно;
- `NEEDS_REVIEW` — маршрут или ответ неоднозначен;
- `ERROR` — replay завершился ошибкой.

Без `--coverage` команда сохраняет совместимое поведение и повторяет все ранее подтверждённые bypass. Для стандартной проверки исправлений это не рекомендуется.

### 5. Уточнение правил для оставшихся bypass

Если после `validate-fix` остались записи `STILL_BYPASSED`:

```bash
python waf_bypass_tool.py refine-rules \
  --validation work/fix-validation.jsonl \
  --manifest work/rules/manifest.json \
  --coverage work/rules/coverage.csv \
  --output-dir work/refined-rules
```

Результат также является набором кандидатов для ручного review, а не готовым автоматическим обновлением WAF.

## Диагностика replay

### Посмотреть фактический cURL

```bash
head -n 1 work/fix-validation.eligible.jsonl | jq -r '.curl'
```

### Посмотреть результат первого запроса

```bash
head -n 1 work/fix-validation.replayed.jsonl | jq '{
  payload_path,
  variant,
  http_code,
  server_header,
  route_verdict,
  final_verdict,
  duration_ms,
  curl_exit_code,
  stderr
}'
```

### Проверить DNS и маршрут

```bash
getent ahosts jutcy.glazapp.com
```

```bash
curl -vkso /dev/null \
  -w $'\nhttp=%{http_code}\nremote_ip=%{remote_ip}\nlocal_ip=%{local_ip}\nurl=%{url_effective}\n' \
  https://jutcy.glazapp.com/
```

### Проверить используемый curl

```bash
type -a curl
which curl
python - <<'PY'
import shutil
print(shutil.which('curl'))
PY
```

### Проверить proxy

```bash
env | grep -iE '^(http|https|all|no)_proxy='
```

Если ручной cURL виден на WAF, а replay нет, сравните точный URL, `remote_ip`, IPv4/IPv6, proxy, `/etc/hosts`, алиасы shell и WAF-ноду, логи которой вы просматриваете.

## Дополнительные команды

### Создание XLSX из JSONL

```bash
python waf_bypass_tool.py report \
  --input work/verified.jsonl \
  --output work/verified.xlsx
```

### Универсальный diff двух запусков

```bash
python waf_bypass_tool.py diff \
  --before work/before.jsonl \
  --after work/after.jsonl \
  --output-jsonl work/diff.jsonl \
  --output-xlsx work/diff.xlsx
```

Для стандартной проверки внедрённых правил используйте `validate-fix`, а не `diff`.

## Рекомендуемая последовательность команд

```bash
python waf_bypass_tool.py import \
  --report waf-bypass.json \
  --groups groups.txt \
  --taxonomy config/taxonomy.json \
  --output work/imported.jsonl

python waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output work/verified.jsonl \
  --report-xlsx work/verified.xlsx

rm -rf work/rules
python waf_bypass_tool.py suggest-rules \
  --input work/verified.jsonl \
  --id-start 999000 \
  --output-dir work/rules

# Ручной review, проверка converter/loader и развёртывание правил.

python waf_bypass_tool.py validate-fix \
  --before work/verified.jsonl \
  --coverage work/rules/coverage.csv \
  --manifest work/rules/manifest.json \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output-jsonl work/fix-validation.jsonl \
  --output-xlsx work/fix-validation.xlsx
```

## Тесты

```bash
python -m unittest discover -s tests -v
```

Тесты не выполняют реальные сетевые запросы.
