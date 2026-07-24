---
title: "{{TITLE}}"
created: {{CREATED}}
tags:
  - report
  - monitoring
  - field-test
  - apple
  - icloud
  - censorship
  - dpi
  - timeline
---

# {{HEADING}}

**Дата составления:** {{CREATED}}
**Оператор:** Hermes Agent
**Источник данных:**
- Исторические агрегированные отчёты агента `field-monitor`:
  `~/.local/share/field-monitor/report-YYYY-MM-DDTHH:MM:SSZ.md`.
- Верхние таблицы (текущий опрос, OK/SLOW) и кумулятивная секция `## Anomalies`
  (HTTPS_FAIL / HIGH_LATENCY — сигнатура блока / замедления).
- Сырые логи `probe.log` с 12 vantage points.

**Точек замера:** 12 (все РФ-VPS).

> **Кросс-проверка:** независимые медиа опубликовали сообщения о блокировке
> Apple 20 июля. Замеры field-monitor за 19–21.07 зафиксировали активный блок
> (RST, code 0, ~8 с таймаут). Данные агента предшествуют внешней публикации.

---

## 1. Как читать сырые данные

Агент пишет на каждом сервере `probe.log`. Строка измерения по цели:

```
target,apple,184.24.145.53,30,200,132,open,16,-,-
       ^1   ^2    ^3          ^4 ^5  ^6 ^7  ^8 ^9 ^10
```

| # | Поле | Значение |
|---|------|----------|
| 1 | `target` | литерал |
| 2 | target name | `apple`, `github`, `github-api`, `icloud`, `google`, `google-dns` |
| 3 | DNS IP цели | резолвится локально на сервере |
| 4 | DNS latency, мс | |
| 5 | HTTPS code | `200` = ответ получен; `0` = соединение сброшено (RST) |
| 6 | HTTPS latency, мс | при сбросе соединения ~8000 (таймаут TLS-handshake) |
| 7 | TCP | `open` / `closed` |
| 8 | TCP latency, мс | |
| 9 | ICMP | `ok` / `-` |
| 10 | ICMP latency, мс | |

**Признак сброса соединения (DPI / TCP-RST) в данных:**

```
| SPB | SPB | github | Some(0) | Some(8011) | open | HTTPS_FAIL |
```

- `HTTPS = Some(0)` — нет HTTP-ответа, соединение сброшено;
- `Latency = Some(8011)` — таймаут на уровне TLS (~8 с);
- `TCP = open` (порт отвечает) или `closed` (порт недоступен).

> **Про кумулятивность.** `report-*.md` (поле `Anomalies`) суммирует
> всю историю `probe.log` на серверах, а не только последний час.
> Счётчик `Anomalies` растёт и не равен числу событий за час. Для оценки текущего
> состояния используется хвост `probe.log` (последняя строка по каждой цели), а не
> итоговый счётчик. В таймлайне ниже используется факт наличия блока в часе
> и переходы CLEAR ↔ BLOCKED, а не дельта счётчика.

### Поля всех таблиц отчёта

**Таблица аномалий (из `report-*.md`):** колонки
`IP | label | target | HTTPS code | HTTPS latency | TCP | status`.
- `IP` — адрес сервера (vantage point);
- `label` — метка сервера (см. раздел 2.1);
- `target` — проверяемая цель: `apple`, `github`, `github-api`, `icloud`,
  `google` / `google-dns`;
- `HTTPS code` — `Some(0)` = соединение сброшено (RST), ответа нет; `200` = ответ получен;
- `HTTPS latency` — задержка HTTPS, мс (`Some(8011)` ≈ 8 с, таймаут TLS-handshake);
- `TCP` — результат TCP-щупа порта 443: `open` = порт отвечает (SYN-ACK),
  `closed` = порт недоступен (RST/таймаут);
- `status` — `HTTPS_FAIL` (цель заблокирована) / `OK`.

**Таблица по серверу (из `report-*.md`):** колонки
`target | DNS IP | HTTPS code | HTTPS latency | DNS latency | TCP | ICMP | status`.
- `DNS IP` — IP цели, резолвится локально на сервере;
- `DNS latency` — задержка DNS, мс;
- `ICMP` — результат ICMP-эхо: `-` = не измерялось, иначе latency мс.

**Таблица таймлайна (раздел 2):** колонки
`Generated (UTC) | vps | apple OK | icloud OK | Статус / интерпретация`.
- `Generated (UTC)` — время генерации агрегированного отчёта;
- `vps` — число vantage points, собранных в этом прогоне;
- `apple OK` / `icloud OK` — число строк с `OK` по цели в верхних таблицах;
- `Статус / интерпретация` — наличие блока в часе (CLEAR / SLOW / BLOCKED).

---

## 2. Почасовой таймлайн (UTC)

{{TIMELINE_TABLE}}

Пустые часы (нет данных, состояние неизвестно):

```
{{EMPTY_HOURS}}
```

Причина пустых часов: {{EMPTY_REASON}}

### 2.1 География блокировок: серверы и регионы РФ

**Таблица серверов:**

| Сервер (label) | Регион | Оператор ДЦ | IP |
|---|---|---|---|
{{SERVER_TABLE}}

**Распределение apple HTTPS_FAIL (кумулятивно, из `report-*.md`):**

| Сервер (vantage point) | HTTPS_FAIL | HIGH_LATENCY |
|---|---:|---:|
{{APPLE_FAIL_TABLE}}

> **Оговорка:** кумулятивные HTTPS_FAIL относятся к окну массовой блокировки
> (19–21.07). В текущем окне (см. раздел 2) apple виден как OK на большинстве точек.

**Распределение icloud HTTPS_FAIL (кумулятивно):**

| Сервер (vantage point) | HTTPS_FAIL | HIGH_LATENCY |
|---|---:|---:|
{{ICLOUD_FAIL_TABLE}}

**Наблюдения по географии:**
{{GEO_NOTES}}

---

## 3. Сырые данные

### 3.1. Пример заблокированной цели (из `report-*.md`, аномалии)

```
{{RAW_BLOCKED_EXAMPLE}}
```

### 3.2. Пример цели без блока (из `report-*.md`, таблица по серверу)

```
{{RAW_OK_EXAMPLE}}
```

### 3.3. Сырьё последних строк `probe.log` (текущее состояние)

```
{{RAW_TAIL_EXAMPLE}}
```

---

## 4. Текущее состояние (на момент {{CURRENT_TS}})

{{CURRENT_STATE}}

---

## 5. Факты

{{FACTS}}

---

## 6. Открытые вопросы

{{OPEN_QUESTIONS}}

Связанные заметки:
- [[20260721-apple-blocking-timeline]] — таймлайн блокировки apple 19–21.07
- [[field-monitor-data-extraction]] — скилл извлечения датасета
