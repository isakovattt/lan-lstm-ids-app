#!/usr/bin/env python3
"""Перенос данных из старого SQLite server.db в PostgreSQL.

Перед запуском задайте IDS_DATABASE_URL, если используется не стандартная строка:
export IDS_DATABASE_URL='postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db'
python migrate_sqlite_to_postgres.py
"""

import json
import os
import sqlite3
from pathlib import Path

import psycopg

DATABASE_URL = os.environ.get(
    "IDS_DATABASE_URL",
    "postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db",
)
SQLITE_PATH = Path(os.environ.get("IDS_SQLITE_PATH", "server.db"))

TABLES = [
    "devices",
    "results",
    "incidents",
    "packets",
    "packet_reviews",
    "normal_feature_ranges",
]


def ensure_schema(pg):
    c = pg.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS devices
                 (mac TEXT PRIMARY KEY, status TEXT, device_name TEXT,
                  first_seen TEXT, last_seen TEXT, note TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS results
                 (id SERIAL PRIMARY KEY, timestamp TEXT,
                  anomaly_prob DOUBLE PRECISION, is_anomaly INTEGER, message TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS incidents
                 (id SERIAL PRIMARY KEY, timestamp TEXT, data TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS packets
                 (id SERIAL PRIMARY KEY, incident_id INTEGER,
                  packet_index INTEGER, data TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS packet_reviews
                 (incident_id INTEGER, packet_index INTEGER, reviewed_at TEXT,
                  operator TEXT, model_label TEXT, operator_label TEXT,
                  final_label TEXT, overrode_model INTEGER, comment TEXT,
                  packet_data TEXT,
                  PRIMARY KEY (incident_id, packet_index))""")
    c.execute("""CREATE TABLE IF NOT EXISTS normal_feature_ranges
                 (feature TEXT PRIMARY KEY, normal_min DOUBLE PRECISION, normal_max DOUBLE PRECISION,
                  allowed_values TEXT, normal_note TEXT, recommendation TEXT,
                  updated_at TEXT)""")
    pg.commit()


def sqlite_columns(src, table):
    return [row[1] for row in src.execute(f"PRAGMA table_info({table})").fetchall()]


def table_exists(src, table):
    row = src.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return bool(row)


def insert_rows(pg, table, columns, rows):
    if not rows:
        return 0
    placeholders = ",".join(["%s"] * len(columns))
    col_sql = ", ".join(columns)
    if table == "devices":
        conflict = " ON CONFLICT (mac) DO NOTHING"
    elif table == "packet_reviews":
        conflict = " ON CONFLICT (incident_id, packet_index) DO NOTHING"
    elif table == "normal_feature_ranges":
        conflict = " ON CONFLICT (feature) DO NOTHING"
    elif "id" in columns:
        conflict = " ON CONFLICT (id) DO NOTHING"
    else:
        conflict = ""
    sql = f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders}){conflict}"
    with pg.cursor() as c:
        c.executemany(sql, rows)
    return len(rows)


def reset_sequences(pg):
    with pg.cursor() as c:
        for table in ["results", "incidents", "packets"]:
            c.execute(
                "SELECT setval(pg_get_serial_sequence(%s, 'id'), COALESCE((SELECT MAX(id) FROM " + table + "), 1), true)",
                (table,),
            )


def main():
    if not SQLITE_PATH.exists():
        raise SystemExit(f"SQLite-файл не найден: {SQLITE_PATH}")

    src = sqlite3.connect(SQLITE_PATH)
    pg = psycopg.connect(DATABASE_URL)
    ensure_schema(pg)

    copied = {}
    for table in TABLES:
        if not table_exists(src, table):
            copied[table] = 0
            continue
        columns = sqlite_columns(src, table)
        rows = src.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall()
        copied[table] = insert_rows(pg, table, columns, rows)

    reset_sequences(pg)
    pg.commit()
    pg.close()
    src.close()

    print("✅ Перенос SQLite → PostgreSQL завершён")
    print(json.dumps(copied, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
