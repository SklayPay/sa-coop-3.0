# Порт SA:COOP на GTA SA 3.0 — контрольная точка

Эта ветка — рабочая копия порта. Ветка `main` не тронута, поэтому всегда можно вернуться к
исходному состоянию.

## Состояние

Порт доведён до стадии «таблица адресов и трансляция готовы, 3.0 ещё выключена». Мод по-прежнему
работает только на 1.0 US; на 3.0 он распознаёт версию и выключается с понятным сообщением.
Это сделано намеренно: 3.0 нельзя включать, пока не закрыты оставшиеся адреса и не пройдены
runtime-тесты.

## Что сделано

- Определение версии `gta_sa.exe` — `src/client/shared/game/version/GameVersion.cpp`.
- Единая таблица адресов: `src/client/shared/game/version/Addresses.cpp` (326 записей).
- Трансляция адресов: `game::version::Resolve` / `ResolveAddress`.
- `game::Ref`, `game::Call`, `game::CallMethod`, `game::CallStd`, `Ref10`, `Call10`, `Ptr10`
  переводят адрес 1.0 через таблицу; на 1.0 US это тождественная операция.
- `mem::Write/Nop/Jump/Ret/Hook/RedirectCall/Check` переводят адрес через `Resolve`; если
  записи нет, патч не применяется и пишется ошибка в лог (а не порча памяти).
- `Core.cpp` использует `game::version::Get()` и гейт версии.
- 3.0 определяется, но `IsSupported()` возвращает `true` только для 1.0 US.

## Проверенные бинарники

| Версия | Файл | Размер | SHA-256 | Сигнатура |
|---|---|---|---|---|
| 1.0 US | `C:\Users\Pc\Desktop\wibeProjects\GTA 1.0 US\gta_sa.exe` | `14 383 616` | `A559AA772FD136379155EFA71F00C47AAD34BBFEAE6196B0FE1047D0645CBD26` | `0x82457C == 0x94BF` |
| 3.0 | `C:\Users\Pc\Desktop\wibeProjects\Grand Theft Auto San Andreas\gta-sa.exe` | `5 689 344` | `1A775C0BDB7D68A7DE377E684D4FA536C6B78773CF3DCAC490460C4ED614224E` | `0x85EC4A == 0x94BF` |

`testapp.exe` в папке 3.0 — зашифрованная Steam-обёртка; для анализа и запуска нужен `gta-sa.exe`.
Для 1.0 в анализе используется destub-копия `gta_sa_analysis.exe`.

## Покрытие таблицы

`docs/port/mapping.csv`, 507 уникальных адресов из инвентаря (адреса, встречающиеся только в
комментариях, исключены на этапе `inventory.ps1`):

| Состояние | Всего | func | data | code |
|---|---|---|---|---|
| `confirmed` | 316 | 129 | 136 | 51 |
| `single` | 147 | 115 | 24 | 8 |
| `missing` | 44 | — | — | — |

Итого сопоставлено 463 из 507 (91,3 %); подтверждено — 316 (62,3 %).
В `Addresses.cpp` попадают только `confirmed`.

Что означает состояние:

- `confirmed` — адрес переведён и подтверждён минимум двумя независимыми сигналами, либо
  ручной проверкой дизассемблером (ручные пары имеют приоритет);
- `single` — перевод есть, но подтверждён одним сигналом; в таблицу не попадает;
- `missing` — перевода нет.

Сигналы, добавленные последними:

- **ссылочная сверка пары** (`xref-ver`, `tools/port/verify_xref.py`): все вызываемые функции
  и глобальные переменные 1.0-тела, для которых уже есть подтверждённая пара, должны
  встретиться в 3.0-теле как их же аналоги. Компиляторы у сборок разные, поэтому совпадение
  набора ссылок не может быть следствием раскладки инструкций. Нужно ≥3 «заякоренных» вызова
  (совпадение ≥0.7) или ≥3 глобальных переменных (≥0.6); пара отбрасывается, если другое
  предложение Version Tracking даёт такой же результат. На 507 адресах правило даёт 47
  подтверждений; доля ложных срабатываний на случайных парах — 0.05 %;
- **одинаковая дельта от подтверждённых соседей** (`delta-nb`, внутри `consolidate.py`):
  глобальные переменные одной структуры или массива сдвигаются между сборками одинаково.
  Адрес подтверждается, если ≥2 подтверждённых соседа в окне ±0x400 имеют ту же дельту и она
  строго преобладает. Повышаются только строки, у которых уже есть кандидат, — итог всегда
  опирается на два сигнала.

## Проверенные соответствия 1.0 → 3.0

Базовые пары, на которых калибровались матчеры:

| 1.0 | 3.0 | Функция |
|---|---|---|
| `0x4D3990` | `0x4DE2F0` | `CAnimManager::GetAnimationBlockIndex` |
| `0x563280` | `0x57D370` | `CWorld::Remove` |
| `0x5A82C0` | `0x5BDFE0` | `CClothes::RebuildPlayer` |
| `0x601110` | `0x620E70` | `CPedIntelligence::GetTaskJetPack` |
| `0x6190A0` | `0x63AB90` | `C_PcSave::GenerateGameFilename` |
| `0x734A40` | `0x7671B0` | `CAnimManager::GetAnimHierarchyFromSkinClump` |
| `0x743C60` | `0x77D940` | `CWeaponInfo::GetWeaponInfo` |
| `0x7F0990` | `0x82A950` | `RwFrameGetLTM` |

Важно: `0x734A40` имеет ложное байтовое совпадение с `0x83D2D0`. Правильный адрес — `0x7671B0`.

Контрольная проверка: ссылочная сверка независимо воспроизвела известную пару
`0x5A82C0 → 0x5BDFE0` (`CClothes::RebuildPlayer`) и подтвердила patch-сайты по их целевым
вызовам, например `0x644A1A → 0x66B342` — это `call 0x441390` в 1.0 против `call 0x444D70`
в 3.0, то есть подтверждённая пара `CGameLogic::IsCoopGameGoingOn`.

Семантически проверенные пары игровой логики:

| 1.0 | 3.0 | Функция |
|---|---|---|
| `0x441390` | `0x444D70` | `CGameLogic::IsCoopGameGoingOn` |
| `0x442020` | `0x445C10` | `CGameLogic::IsPlayerUse2PlayerControls` |
| `0x441E10` | `0x4459D0` | `CGameLogic::IsPlayerAllowedToGoInThisDirection` |
| `0x54FF60` | `0x5680C0` | `GetPedRef` |
| `0x54FF90` | `0x601920` | `GetPed` |
| `0x54FFC0` | `0x568120` | `GetVehicleRef` |
| `0x54FFF0` | `0x71F250` | `GetVehicle` |
| `0x550020` | `0x568180` | `GetObjectRef` |
| `0x550050` | `0x5BB1D0` | `GetObject` |
| `0x7468E0` | `0x780720` | `IsAlreadyRunning` (VT: точное совпадение инструкций 1.000) |

## Инструменты

Все инструменты порта лежат в `tools/port` и воспроизводимы:

| Файл | Назначение |
|---|---|
| `consolidate.py` | главный сборщик: seeds из всех матчеров + ручные пары, перевод адресов, `mapping.csv` |
| `match_functions.py` | матчер по последовательностям инструкций (нормализованные токены) |
| `match_ghidra.py` | матчер по функциям Ghidra с проверкой thunk-обёрток |
| `propagate_ghidra.py` | распространение seeds по графу вызовов |
| `pattern_scan.py` | поиск по маскированным байтовым паттернам |
| `local_scan.py` | локальные окна вокруг патч-сайтов |
| `build_mapping.py`, `map_data.py` | сборка/инференс данных |
| `gen_addresses.py` | генерация `Addresses.cpp` только из `confirmed` |
| `validate_mapping.py` | структурная проверка таблицы против обоих exe |
| `verify_xref.py` | независимая перепроверка пары по множествам вызываемых функций и глобальных переменных; пишет `xref_verified.csv` |
| `check_exe.py` | проверка версии exe по сигнатурам |
| `inventory.ps1` | инвентарь адресов |

Ручные проверенные пары — `docs/port/manual_seeds.csv` (формат `v10,v30,почему`). Они имеют
приоритет над автоматическими seeds; конфликты фиксируются в колонке `sources`.

Формат `mapping.csv`: `v10,v30,state,kind,function10,function30,sources,refs,first,name`.

## Как воспроизвести

```powershell
uv run --with capstone --with pefile --python 3.12 python tools/port/consolidate.py
uv run --with capstone --with pefile --python 3.12 python tools/port/verify_xref.py
uv run --with capstone --with pefile --python 3.12 python tools/port/consolidate.py
uv run --python 3.12 python tools/port/gen_addresses.py --apply
uv run --with capstone --with pefile --python 3.12 python tools/port/validate_mapping.py
uv run --python 3.12 python tools/build.py client
uv run --python 3.12 python tools/fsd_check.py
```

`verify_xref.py` стоит между двумя прогонами `consolidate.py`: он читает подтверждённые пары
из `mapping.csv`, а второй прогон учитывает `xref_verified.csv` как самостоятельный источник.

## Следующие шаги

1. Закрыть 44 `missing` адреса. Основные группы: Hoodlum-трамполины (`0x44CBC0`, `0x4648E0`,
   `0x49B010` и др., `E9 rel32` в `0x156xxxx`/`0x157xxxx`), функции без вызывающих —
   vtable-методы (`0x6A3440`, `0x6C4550`, `0x6CAC10`, `0x4B0C00`, `0x4B4E80`, `0x60EA90`),
   а также патч-сайты внутри крупных функций (`Missions.cpp` — 11 адресов).
2. Перевести оставшиеся `single` (147: 115 функций, 24 данные, 8 patch-сайтов) в `confirmed`
   или отбросить: сейчас они не попадают в таблицу, поэтому соответствующие места на 3.0 не
   пропатчатся. У большинства функций нет ни одного подтверждённого вызываемого соседа,
   поэтому ссылочная сверка для них молчит; нужен обратный сигнал — совпадение набора
   вызывающих.
3. Проверить ABI и смещения структур (`CPed`, `CVehicle`, `CPad`, `CPlayerInfo`, пулы, камера):
   на 3.0 часть layout'ов сдвинута (например, `CTimer`).
4. Прогнать регрессию 1.0 US и только затем включать 3.0 в `IsSupported()`.

## Ограничения

- `Resolve` при отсутствии записи возвращает 0, а `Ref/Call/mem::*` fallback'ятся на адрес 1.0.
  Это безопасно только пока 3.0 выключена; после включения любой `missing` адрес — ошибка.
- Полного PDB/symbol map для 3.0 нет; внешних таблиц адресов 3.0 не найдено.
- `opencode.exe` в корне — посторонний файл, в репозиторий не входит.

## Команды

```powershell
# сборка клиента
uv run --python 3.12 python tools/build.py client

# проверка форматирования
uv run --python 3.12 python tools/fsd_check.py

# инвентарь адресов
powershell -ExecutionPolicy Bypass -File tools/port/inventory.ps1

# проверка exe
uv run --python 3.12 python tools/port/check_exe.py "C:\path\to\gta_sa.exe"
```

## Как продолжить

1. Переключиться на ветку: `git switch port/gtasa-3.0`.
2. Открыть этот файл и `docs/port/GTA_SA_3.0.md`.
3. Проверить, что оба exe лежат по путям выше (или обновить пути в `tools/port/consolidate.py`).
4. Продолжить с раздела «Следующие шаги».

Форк для продолжения: `https://github.com/SklayPay/sa-coop-3.0.git`.
