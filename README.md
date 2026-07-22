# waf-bypass automation

CLI-инструмент для обработки отчётов `nemesida/waf-bypass` без использования go-ftw, логов WAF или внешней телеметрии.

Инструмент выполняет пять задач:

1. импортирует `BYPASSED` и `cURL.BYPASSED` из JSON;
2. нормализует варианты и классифицирует их по группам;
3. безопасно повторяет выбранные cURL и проверяет HTTP-код/`Server`;
4. сравнивает прогоны до и после исправления;
5. предлагает кандидаты SecLang для подтверждённых origin bypass и строит матрицу покрытия.

Сгенерированные правила никогда не подключаются к WAF автоматически.

## Требования

- Python 3.11+
- установленный `curl`
- `openpyxl`

Установка:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Также инструмент можно запускать прямо из каталога проекта:

```bash
python3 waf_bypass_tool.py --help
```

## 1. Импорт

```bash
python3 waf_bypass_tool.py import \
  --report /path/to/waf-bypass.json \
  --groups /path/to/groups.txt \
  --taxonomy config/taxonomy.json \
  --overrides config/overrides.json \
  --output work/normalized.jsonl
```

Единица результата — вариант запроса. Устойчивый ключ:

```text
payload_path::variant
```

Для каждой записи сохраняются исходный cURL, его SHA-256, зона, кодировка, HTTP-код, группа, извлечённый payload и безопасно нормализованное представление. Декодированный payload остаётся данными и никогда не выполняется.

`config/overrides.json` содержит согласованную классификацию текущего отчёта. Приоритет:

1. override по точному пути payload;
2. default-группа категории;
3. `NO_GROUP` с ручной проверкой.

Группа `85 — Межсайтовый скриптинг (XSS)` является локальным расширением. Импорт завершится ошибкой, если будущий `groups.txt` займёт ID 85.

## 2. XLSX-отчёт

```bash
python3 waf_bypass_tool.py report \
  --input work/normalized.jsonl \
  --groups /path/to/groups.txt \
  --taxonomy config/taxonomy.json \
  --output work/classification.xlsx
```

Листы: `Summary`, `Payload mapping`, `Bypass variants`, `Group summary`.

## 3. Dry-run повторной проверки

Для группы XSS:

```bash
python3 waf_bypass_tool.py recheck \
  --input work/normalized.jsonl \
  --group 85 \
  --output work/xss-dry-run.jsonl
```

Dry-run ничего не отправляет в сеть. Он проверяет выборку, cURL и целевой host.

## 4. Выполнение cURL

Выполняйте только на ресурсе, для которого у вас есть разрешение:

```bash
python3 waf_bypass_tool.py recheck \
  --input work/normalized.jsonl \
  --group 85 \
  --allow-host waf-test.example.internal \
  --limit 20 \
  --timeout 15 \
  --delay 0.5 \
  --execute \
  --output work/xss-recheck.jsonl
```

Защита выполнения:

- без `--execute` запросы не отправляются;
- при `--execute` обязателен точный `--allow-host`;
- shell не используется (`shell=False`);
- метод, URL, заголовки и тело исходного запроса не меняются;
- добавляются только параметры получения response headers, HTTP-кода и ограничения времени;
- конфликтующие output-параметры исходного cURL приводят к ошибке конкретной записи.

Матрица вердиктов:

| HTTP | Server | Результат |
|---|---|---|
| 403 | pingora | `BLOCKED_WAF` |
| 403 | другое/пусто | `BLOCKED_ROUTE_MISMATCH` |
| не 403 | nginx/Ubuntu | `BYPASS_ORIGIN_CONFIRMED` |
| не 403 | pingora | `BYPASS_WAF_CONTRACT_MISMATCH` |
| не 403 | другое/пусто | `BYPASS_ROUTE_UNCONFIRMED` |

## 5. Кандидаты SecLang

Правила предлагаются только для записей с итогом `BYPASS_ORIGIN_CONFIRMED`:

```bash
python3 waf_bypass_tool.py suggest-rules \
  --input work/xss-recheck.jsonl \
  --id-start 990000 \
  --output-dir work/xss-rule-candidates
```

Выход:

- `candidate-rules.conf` — кандидаты SecLang;
- `coverage.csv` — соответствие каждого bypass-варианта кандидату;
- `manifest.json` — параметры, число покрытых вариантов и предупреждения.

Алгоритм объединяет варианты по группе, target, кодировке и exploit primitive. Если безопасно обобщить сигнатуру не удалось, создаётся узкий `narrow_fallback`.

Перед использованием каждого правила обязательны:

1. проверка поддерживаемых target, operator и transforms в текущем движке;
2. запуск всех положительных cURL из `coverage.csv`;
3. FP-тестирование на легитимном трафике;
4. назначение ID из зарезервированного диапазона;
5. повторный `recheck` после развёртывания;
6. ручное ревью узких fallback-правил.

Особое предупреждение выводится для transforms на collection targets (`ARGS`, `REQUEST_COOKIES`, `REQUEST_HEADERS`), поскольку конкретная реализация Pingora может поддерживать их не полностью.

## 6. Сравнение прогонов

```bash
python3 waf_bypass_tool.py diff \
  --before work/xss-recheck-before.jsonl \
  --after work/xss-recheck-after.jsonl \
  --output-jsonl work/xss-diff.jsonl \
  --output-xlsx work/xss-diff.xlsx
```

Статусы: `FIXED`, `PERSISTENT`, `REGRESSION`, `NEW`, `REMOVED`, `CHANGED`, `ERROR`.

## Рекомендуемый рабочий цикл

1. `import` нового отчёта.
2. `report` и ручная проверка классификации.
3. `recheck` сначала без `--execute`.
4. Ограниченный `recheck --execute` для одной группы.
5. Отбор только `BYPASS_ORIGIN_CONFIRMED`.
6. `suggest-rules` и ручное ревью предложений.
7. Проверка FP и развёртывание одобренных правил.
8. Повторный `recheck` теми же cURL.
9. `diff` до/после.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

Тесты не выполняют сетевые запросы.
