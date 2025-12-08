import os
import sqlite3
import json
from datetime import datetime

DB_FILE = "white_fatalis.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Findings table
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    tool TEXT,
                    vulnerability TEXT,
                    details TEXT,
                    severity TEXT,
                    timestamp TEXT
                )''')

    # Knowledge table (for learning)
    c.execute('''CREATE TABLE IF NOT EXISTS knowledge (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT,
                    content TEXT,
                    source TEXT,
                    timestamp TEXT
                )''')

    # Missions/Tasks table
    c.execute('''CREATE TABLE IF NOT EXISTS missions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    goal TEXT,
                    status TEXT,
                    plan TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )''')

    conn.commit()
    conn.close()

def add_finding(target, tool, vulnerability, details, severity="INFO"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO findings (target, tool, vulnerability, details, severity, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (target, tool, vulnerability, json.dumps(details), severity, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_findings(target=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if target:
        c.execute("SELECT * FROM findings WHERE target = ?", (target,))
    else:
        c.execute("SELECT * FROM findings")
    rows = c.fetchall()
    conn.close()
    return rows

def log_knowledge(topic, content, source="System"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO knowledge (topic, content, source, timestamp) VALUES (?, ?, ?, ?)",
              (topic, json.dumps(content), source, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def create_mission(target, goal):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO missions (target, goal, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
              (target, goal, "PENDING", datetime.now().isoformat(), datetime.now().isoformat()))
    mission_id = c.lastrowid
    conn.commit()
    conn.close()
    return mission_id

def update_mission(mission_id, status=None, plan=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if status:
        c.execute("UPDATE missions SET status = ?, updated_at = ? WHERE id = ?", (status, datetime.now().isoformat(), mission_id))
    if plan:
         c.execute("UPDATE missions SET plan = ?, updated_at = ? WHERE id = ?", (json.dumps(plan), datetime.now().isoformat(), mission_id))
    conn.commit()
    conn.close()

def get_mission(mission_id):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM missions WHERE id = ?", (mission_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None
