#!/usr/bin/env python3
"""
gen_report.py — generate an Apple-blocking report from field-monitor CSV dumps.

Inputs (from ~/.local/share/field-monitor/):
  - apple-availability-YYYY_MM_DD_DD_snapshots.csv  (upper tables, per hour)
  - apple-availability-YYYY_MM_DD_DD_anomalies.csv  (cumulative Anomalies)

The script fills templates/apple-report-template.md (placeholder substitution)
and writes the finished report to stdout (redirect to a .md file).

Usage:
  python3 gen_report.py \
    --snapshots apple-availability-22_23_snapshots.csv \
    --anomalies apple-availability-22_23_anomalies.csv \
    --title "Отчёт: доступность Apple (22–23 июля 2026)" \
    --created 2026-07-24 \
    --current-ts "23.07 23:09Z" \
    --empty-reason "watchdog перезагрузки коллектора altkde 22.07 вечером" \
    > 20260722-23-apple-availability.md

The server/region/DC map is embedded (kept in sync with deploy.sh HOSTS).
"""
import argparse, csv, collections, os, sys

# server label -> (region, DC, IP-redacted)
SERVERS = {
    "ruvds-x7yuy":       ("Владивосток", "RUVDS", "[REDACTED]"),
    "EKB":               ("Екатеринбург", "отдельный ДЦ", "[REDACTED]"),
    "ruvds-8vi23":       ("Екатеринбург", "RUVDS", "[REDACTED]"),
    "ruvds-klh99":       ("Казань", "RUVDS", "[REDACTED]"),
    "MOW-vladimir":      ("Москва", "отдельный ДЦ", "[REDACTED]"),
    "bm-server-1779046186914": ("Москва", "отдельный ДЦ", "[REDACTED]"),
    "ruvds-8drd7":       ("Санкт-Петербург", "RUVDS", "[REDACTED]"),
    "omsk.org":          ("Омск", "отдельный ДЦ", "[REDACTED]"),
    "PERM-home":         ("Пермь", "отдельный ДЦ", "[REDACTED]"),
    "SPB":               ("Санкт-Петербург", "отдельный ДЦ", "[REDACTED]"),
    "VPN-DvaPuka-SPB2":  ("Санкт-Петербург", "тот же ДЦ, что SPB (relay)", "[REDACTED]"),
    "ruvds-ow0uq":       ("Новосибирск", "RUVDS", "[REDACTED]"),
}

EMPTY_HOURS_DEFAULT = {
    "2026-07-22": ["01","02","03","04","05","06","07","08","09","10","11","12","13","14","15","18","23"],
    "2026-07-23": ["03","04","05","06","07","08","09","10"],
}


def build_timeline(snap_rows):
    """Group snapshots by (day,hour): vps count, apple OK, icloud OK, status."""
    agg = collections.defaultdict(lambda: {"servers": set(), "apple_ok": 0, "apple_slow": 0,
                                            "icloud_ok": 0, "icloud_slow": 0})
    for r in snap_rows:
        key = (r["day"], r["hour"])
        agg[key]["servers"].add(r["server"])
        if r["target"] == "apple":
            if r["status"] == "OK":
                agg[key]["apple_ok"] += 1
            elif r["status"] == "SLOW":
                agg[key]["apple_slow"] += 1
        if r["target"] == "icloud":
            if r["status"] == "OK":
                agg[key]["icloud_ok"] += 1
            elif r["status"] == "SLOW":
                agg[key]["icloud_slow"] += 1

    lines = ["| Generated (UTC) | vps | apple OK | icloud OK | Статус / интерпретация |",
             "|-----------------|----:|---------:|----------:|------------------------|"]
    for (day, hour), d in sorted(agg.items()):
        vps = len(d["servers"])
        blocked = d["apple_slow"] > 0 or d["icloud_slow"] > 0
        status = "SLOW" if blocked else "CLEAR"
        note = "CLEAR" if not blocked else "SLOW (единичные замедления, не блок)"
        lines.append(f"| {day[5:]} {hour}:00 | {vps} | {d['apple_ok']} | {d['icloud_ok']} | {note} |")
    return "\n".join(lines)


def build_server_table():
    lines = []
    for label, (region, dc, ip) in SERVERS.items():
        lines.append(f"| {label} | {region} | {dc} | {ip} |")
    return "\n".join(lines)


def build_fail_tables(anom_rows):
    apple = collections.Counter()
    apple_hl = collections.Counter()
    icloud = collections.Counter()
    icloud_hl = collections.Counter()
    for r in anom_rows:
        t = r.get("target")
        an = r.get("anomaly", "")
        srv = r.get("server", "")
        if t == "apple" and "FAIL" in an:
            apple[srv] += 1
        if t == "apple" and "LATENCY" in an:
            apple_hl[srv] += 1
        if t == "icloud" and "FAIL" in an:
            icloud[srv] += 1
        if t == "icloud" and "LATENCY" in an:
            icloud_hl[srv] += 1
    a_lines = [f"| {s} | {c} | {apple_hl.get(s,0)} |" for s, c in apple.most_common()]
    i_lines = [f"| {s} | {c} | {icloud_hl.get(s,0)} |" for s, c in icloud.most_common()]
    return "\n".join(a_lines), "\n".join(i_lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshots", required=True)
    ap.add_argument("--anomalies", required=True)
    ap.add_argument("--template", default=os.path.join(os.path.dirname(__file__), "templates/apple-report-template.md"))
    ap.add_argument("--title", required=True)
    ap.add_argument("--created", required=True)
    ap.add_argument("--heading", required=True)
    ap.add_argument("--current-ts", required=True)
    ap.add_argument("--empty-reason", default="пропуск сбора на коллекторе")
    ap.add_argument("--empty-hours", default=None, help="optional JSON dict day->[hours]")
    ap.add_argument("--facts", required=True, help="path to a text file, one FACT per line")
    ap.add_argument("--open-questions", required=True, help="path to a text file, one question per line")
    ap.add_argument("--geo-notes", default="Блок apple в окно 19–21.07 — повсеместный. К текущему окну основная блокировка снята.")
    ap.add_argument("--current-state", required=True)
    ap.add_argument("--raw-blocked", default="| SPB | SPB | github | Some(0) | Some(8011) | open | HTTPS_FAIL |")
    ap.add_argument("--raw-ok", default="| apple | 184.24.145.53 | 200 | 132 ms | 30 ms | open | - | OK   |")
    ap.add_argument("--raw-tail", default="(fill from probe.log tail)")
    args = ap.parse_args()

    snap_rows = list(csv.DictReader(open(args.snapshots)))
    anom_rows = list(csv.DictReader(open(args.anomalies)))

    empty = EMPTY_HOURS_DEFAULT
    if args.empty_hours:
        import json
        empty = json.loads(args.empty_hours)
    empty_txt = "\n".join(f"{d[5:]} {h}:00" for d, hs in empty.items() for h in hs)

    apple_fail_tbl, icloud_fail_tbl = build_fail_tables(anom_rows)

    facts = "\n".join(f"{i}. {l}" for i, l in enumerate(open(args.facts).read().splitlines() if open(args.facts).read().strip() else [], 1)) \
        or "\n".join(f"{i}. {l.rstrip()}" for i, l in enumerate(open(args.facts).read().splitlines(), 1))
    oq = "\n".join(f"- [ ] {l.rstrip()}" for l in open(args.open_questions).read().splitlines() if l.strip())

    tpl = open(args.template).read()
    out = (tpl
           .replace("{{TITLE}}", args.title)
           .replace("{{CREATED}}", args.created)
           .replace("{{HEADING}}", args.heading)
           .replace("{{TIMELINE_TABLE}}", build_timeline(snap_rows))
           .replace("{{EMPTY_HOURS}}", empty_txt)
           .replace("{{EMPTY_REASON}}", args.empty_reason)
           .replace("{{SERVER_TABLE}}", build_server_table())
           .replace("{{APPLE_FAIL_TABLE}}", apple_fail_tbl)
           .replace("{{ICLOUD_FAIL_TABLE}}", icloud_fail_tbl)
           .replace("{{GEO_NOTES}}", args.geo_notes)
           .replace("{{RAW_BLOCKED_EXAMPLE}}", args.raw_blocked)
           .replace("{{RAW_OK_EXAMPLE}}", args.raw_ok)
           .replace("{{RAW_TAIL_EXAMPLE}}", args.raw_tail)
           .replace("{{CURRENT_TS}}", args.current_ts)
           .replace("{{CURRENT_STATE}}", args.current_state)
           .replace("{{FACTS}}", facts)
           .replace("{{OPEN_QUESTIONS}}", oq))

    sys.stdout.write(out)


if __name__ == "__main__":
    main()
