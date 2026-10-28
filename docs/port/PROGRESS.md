# Порт SA:COOP на GTA SA 3.0 — контрольная точка

Эта ветка — рабочая копия порта. Ветка `main` не тронута, поэтому всегда можно вернуться к
исходному состоянию.

## Что уже сделано

- Определение версии `gta_sa.exe` вынесено в `src/client/shared/game/version/GameVersion.cpp`.
- Единая таблица адресов и сигнатур: `src/client/shared/game/version/Addresses.cpp`.
- `Core.cpp` больше не проверяет адрес `0x82457C` напрямую, а использует `game::version::Get()`.
- Для 1.0 US поведение сохранено: `game::version::Is1_0US()` возвращает адреса без изменений.
- 3.0 определяется, но **намеренно выключена**: `IsSupported()` возвращает `true` только для 1.0 US.
  При запуске на 3.0 мод показывает понятное сообщение и не устанавливает хуки.
- Добавлены `game::Ref10` и `game::Call10` — помощники для постепенного перевода кода на таблицу.
- Собраны инструменты:
  - `tools/port/inventory.ps1` — считает покрытие адресов;
  - `tools/port/check_exe.py` — проверяет версию exe по сигнатурам;
  - `docs/port/addresses.csv` — инвентарь 552 уникальных адресов;
  - `docs/port/GTA_SA_3.0.md` — описание порта и ограничений.

## Проверенные бинарники

| Версия | Путь | Размер | SHA-256 | Сигнатура |
|---|---|---|---|---|
| 1.0 US | `C:\Users\Pc\Desktop\wibeProjects\GTA 1.0 US\gta_sa.exe` | `14 383 616` | `A559AA772FD136379155EFA71F00C47AAD34BBFEAE6196B0FE1047D0645CBD26` | `0x82457C == 0x94BF` |
| 3.0 | `C:\Users\Pc\Desktop\wibeProjects\Grand Theft Auto San Andreas\gta-sa.exe` | `5 689 344` | `1A775C0BDB7D68A7DE377E684D4FA536C6B78773CF3DCAC490460C4ED614224E` | `0x85EC4A == 0x94BF` |

`testapp.exe` в папке 3.0 — зашифрованная Steam-обёртка, для анализа и запуска нужен `gta-sa.exe`.

## Проверенные соответствия 1.0 → 3.0

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

## Текущее покрытие

Последний запуск инвентаря:

- 793 ссылки в коде;
- 552 уникальных адреса;
- 9 покрыто;
- 543 отсутствует.

Из 552 адресов:

- около 386 — код в первом `.text` (1.0 `0x401000–0x857000`);
- около 160 — `.data`;
- 6 — `.rdata`;
- адреса выше `0xC98000` инвентарём отбрасываются.

## Инструменты анализа (временные, вне репозитория)

- Radare2: `C:\Users\Pc\AppData\Local\Temp\radare2\radare2-6.2.4-w64\bin\radare2.exe`
- Списки функций:
  - 1.0: `C:\Users\Pc\AppData\Local\Temp\funcs10.json` (20 979 функций);
  - 3.0: `C:\Users\Pc\AppData\Local\Temp\funcs30.json` (12 808 функций).
- Результаты простого матчера:
  - `C:\Users\Pc\AppData\Local\Temp\fuzzy_matches.csv`;
  - `C:\Users\Pc\AppData\Local\Temp\silentpatch_triples.csv`.
- Ghidra: скачана в `C:\Users\Pc\AppData\Local\Temp\ghidra.zip` (около 560 МБ), ещё не распакована.
- SilentPatch: `C:\Users\Pc\AppData\Local\Temp\SilentPatch`.
- WidescreenFixesPack: `C:\Users\Pc\AppData\Local\Temp\WFP2`.
- open.mp: `C:\Users\Pc\AppData\Local\Temp\openmp`.

## Следующие шаги

1. Распаковать Ghidra и/или использовать Radare2 для точных границ функций.
2. Сопоставить функции 1.0 и 3.0 с учётом границ функций и графа вызовов.
3. Заполнить `Addresses.cpp` проверенными адресами `v30`.
4. Перевести `mem::Hook`/`mem::Write`/`RedirectCall` и `game::Call`/`game::Ref` на
   `game::version::Resolve`.
5. Проверить смещения структур (`CPed`, `CVehicle`, `CPad`, `CPlayerInfo`, пулы, камера).
6. Собрать и прогнать 1.0 US — регрессия должна остаться нулевой.
7. Включить 3.0 в `IsSupported()` только после прохождения runtime-тестов.

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
3. Проверить, что оба exe лежат по путям выше (или обновить пути).
4. Продолжить с раздела «Следующие шаги».

Все изменения этой контрольной точки закоммичены в ветку `port/gtasa-3.0`.
