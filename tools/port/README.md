# Инструменты порта 1.0 US → 3.0

Все скрипты запускаются из корня репозитория. Адреса exe заданы в начале
`consolidate.py` (`EXE10`, `EXE30`, `FUNCS10`, `FUNCS30`).

## Быстрый цикл

```powershell
# 1. свести все матчеры в docs/port/mapping.csv
uv run --with capstone --with pefile --python 3.12 python tools/port/consolidate.py

# 2. перенести confirmed в src/client/shared/game/version/Addresses.cpp
uv run --python 3.12 python tools/port/gen_addresses.py --apply

# 3. проверить таблицу против обоих exe
uv run --with capstone --with pefile --python 3.12 python tools/port/validate_mapping.py

# 4. сборка и форматирование
uv run --python 3.12 python tools/build.py client
uv run --python 3.12 python tools/fsd_check.py
```

## Главные файлы

| Файл | Назначение |
|---|---|
| `consolidate.py` | собирает seeds из всех источников, переводит каждый адрес инвентаря, пишет `mapping.csv` и `mapping_high.csv` |
| `gen_addresses.py` | генерирует блок `kEntries` в `Addresses.cpp`; `--apply` пишет файл |
| `validate_mapping.py` | проверяет, что `confirmed`-адреса лежат в правильных секциях 3.0 и что функции начинаются с начала функции |

## Матчеры (пишут во временную папку)

| Файл | Выход | Идея |
|---|---|---|
| `match_functions.py` | `function_matches.csv` | нормализованные токены инструкций, difflib |
| `match_ghidra.py` | `function_matches_ghidra.csv` | то же по функциям Ghidra + разворачивание thunk'ов |
| `propagate_ghidra.py` | `propagated_ghidra.csv` | seeds по графу вызовов |
| `pattern_scan.py` | `pattern_scan.csv` | маскированные байтовые паттерны прологов |
| `local_scan.py` | `local_scan.csv` | локальные окна вокруг известных пар |
| `build_mapping.py`, `map_data.py` | `data_matches.csv` | сопоставление глобальных переменных по операндам |

## Ручные пары

`docs/port/manual_seeds.csv` — формат `v10,v30,комментарий`. Пары проверены дизассемблером
(тело функции, пролог, ссылки на данные, вызовы) или точным совпадением Ghidra VT. Они имеют
приоритет над автоматическими seeds; при расхождении в `sources` пишется `conflict-manual`.

`consolidate.py` принимает ручную пару для любого адреса внутри образа (функция, тело без
собственной функции в Ghidra, патч-сайт, глобальная переменная).

## Правила качества

- `confirmed` — минимум два независимых сигнала или ручная проверка.
- Конфликтующие источники никогда не дают `confirmed` без ручной пары.
- Data-адрес переводится только по **точной** абсолютной ссылке (`base == target`); окно
  `target - base <= 0x10` давало ложные голоса и убрано.
- Thunk-совпадения проверяются по телу-цели.
- В `Addresses.cpp` попадают только `confirmed`.
