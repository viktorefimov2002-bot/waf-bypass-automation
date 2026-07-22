# waf-bypass automation

CLI-инструмент для обработки JSON-отчётов `nemesida-waf/waf-bypass`, повторной проверки найденных bypass и подготовки кандидатов SecLang-правил.

Инструмент не подключает правила к WAF автоматически. Создание, проверка и развёртывание правил остаются ручным этапом.

## Требования

- Python 3.11+
- установленный `curl`
- `openpyxl`

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Запуск из каталога проекта:

```bash
python3 waf_bypass_tool.py --help
```

## Рабочий процесс

### 1. Импорт JSON-отчёта

```bash
python3 waf_bypass_tool.py import \
  --report waf-bypass.json \
  --groups groups.txt \
  --taxonomy config/taxonomy.json \
  --output work/imported.jsonl
```

Импортируются только разделы `BYPASSED` и `cURL.BYPASSED`.

Каждый вариант запроса сохраняется отдельной JSONL-записью. Устойчивый ключ:

```text
payload_path::variant
```

Классификация выполняется по категории каталога, например:

```text
XSS/25.json  -> XSS  -> группа 85
SQLi/7.json  -> SQLi -> группа 81
UWA/4.json   -> UWA  -> группа 86
```

`config/overrides.json` больше не требуется для стандартного процесса. Параметр `--overrides` оставлен только для обратной совместимости и неизвестных категорий.

### 2. Подтверждение bypass

Проверка всех импортированных вариантов:

```bash
python3 waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output work/verified.jsonl \
  --report-xlsx work/verified.xlsx
```

Проверка одной группы:

```bash
python3 waf_bypass_tool.py verify \
  --input work/imported.jsonl \
  --group 85 \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output work/verified-xss.jsonl \
  --report-xlsx work/verified-xss.xlsx
```

Без `--execute` команда работает в dry-run и не отправляет запросы.

При реальном запуске обязателен точный `--allow-host`.

Защита replay:

- shell не используется;
- чтение локальных файлов через cURL запрещено;
- неизвестные параметры cURL блокируются;
- `-L/--location` запрещены;
- redirect не отслеживаются (`--max-redirs 0`);
- исходные URL, метод, заголовки и тело запроса не переписываются.

### Вердикты

Для текущего стенда:

| HTTP-код | `Server` | Итог |
|---|---|---|
| код из `BLOCK-CODE` | `pingora` | `BLOCKED_BY_WAF` |
| не блокирующий код | `nginx` или `Ubuntu` | `BYPASS_CONFIRMED` |
| не блокирующий код | `pingora` | `BYPASS_UNCONFIRMED` |
| блокирующий код с origin или неизвестным маршрутом | любое другое значение | `ROUTE_MISMATCH` |
| timeout, ошибка cURL или отсутствие кода | — | `CHECK_ERROR` |

Коды блокировки берутся из поля `BLOCK-CODE` исходного JSON, а не считаются всегда равными `403`.

Компактный XLSX содержит только три листа:

- `Summary` — общие счётчики по verdict;
- `Groups` — состояние каждой представленной группы;
- `Results` — подробные результаты запросов.

### 3. Генерация кандидатов SecLang

```bash
python3 waf_bypass_tool.py suggest-rules \
  --input work/verified.jsonl \
  --id-start 990000 \
  --output-dir work/rules
```

Обрабатываются только записи с `BYPASS_CONFIRMED`.

Выходные файлы:

- `candidate-rules.conf` — кандидаты SecLang;
- `coverage.csv` — соответствие каждого bypass правилу;
- `manifest.json` — параметры правил и статистика покрытия.

Генератор пытается объединять несколько bypass одним правилом, если совпадают:

- группа;
- семейство атаки;
- exploit primitive;
- регулярное выражение;
- цепочка transformations.

Разные совместимые зоны могут объединяться в один target, например:

```apache
SecRule ARGS|REQUEST_COOKIES "@rx ..." \
    "id:990000,..."
```

Каждый кандидат требует ручной проверки:

1. синтаксиса SecLang;
2. поддержки targets и transformations текущим движком;
3. покрытия всех положительных cURL из `coverage.csv`;
4. ложных срабатываний на легитимном трафике;
5. корректности диапазона Rule ID.

### 4. Проверка после внедрения правил

После ручного добавления и развёртывания правил:

```bash
python3 waf_bypass_tool.py validate-fix \
  --before work/verified.jsonl \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output-jsonl work/fix-validation.jsonl \
  --output-xlsx work/fix-validation.xlsx
```

Только для одной группы:

```bash
python3 waf_bypass_tool.py validate-fix \
  --before work/verified.jsonl \
  --group 85 \
  --execute \
  --allow-host jutcy.glazapp.com \
  --output-jsonl work/xss-fix-validation.jsonl \
  --output-xlsx work/xss-fix-validation.xlsx
```

Команда повторяет только запросы, которые до внедрения правил имели `BYPASS_CONFIRMED`.

Статусы:

- `FIXED` — теперь запрос блокируется WAF;
- `STILL_BYPASSED` — bypass подтверждается повторно;
- `NEEDS_REVIEW` — маршрут или ответ неоднозначен;
- `ERROR` — запрос не удалось проверить.

## Дополнительные команды

### Отдельное создание компактного XLSX

```bash
python3 waf_bypass_tool.py report \
  --input work/verified.jsonl \
  --output work/verified.xlsx
```

### Универсальный diff

`diff` оставлен для произвольного сравнения двух verification-run. Для стандартной проверки исправлений рекомендуется `validate-fix`.

```bash
python3 waf_bypass_tool.py diff \
  --before work/before.jsonl \
  --after work/after.jsonl \
  --output-jsonl work/diff.jsonl \
  --output-xlsx work/diff.xlsx
```

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

Тесты не выполняют сетевые запросы.
