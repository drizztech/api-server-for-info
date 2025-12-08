import sqlite3
import json
import logging
from datetime import datetime

DB_FILE = "white_fatalis.db"
logger = logging.getLogger("KnowledgeBase")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Enable FTS5 extension if available (standard in most Python SQLite builds)
    try:
        c.execute('''CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_index USING fts5(topic, content, source)''')
    except sqlite3.OperationalError:
        logger.warning("FTS5 not supported. Fallback to standard table for knowledge.")
        c.execute('''CREATE TABLE IF NOT EXISTS knowledge_index (topic TEXT, content TEXT, source TEXT)''')

    # Findings (Specific vulnerabilities found)
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    tool TEXT,
                    vulnerability TEXT,
                    details TEXT,
                    severity TEXT,
                    timestamp TEXT
                )''')

    # Lessons (Generalized rules learned)
    c.execute('''CREATE TABLE IF NOT EXISTS lessons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trigger_keywords TEXT,
                    lesson_text TEXT,
                    confidence FLOAT,
                    created_at TEXT
                )''')

    # Missions/Tasks
    c.execute('''CREATE TABLE IF NOT EXISTS missions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    goal TEXT,
                    status TEXT,
                    plan TEXT,
                    context TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )''')

    conn.commit()
    conn.close()

def log_knowledge(topic, content, source="System"):
    """
    Manually logs a piece of knowledge to the index.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO knowledge_index (topic, content, source) VALUES (?, ?, ?)",
              (topic, json.dumps(content) if isinstance(content, (dict, list)) else content, source))
    conn.commit()
    conn.close()

# --- Findings ---
def add_finding(target, tool, vulnerability, details, severity="INFO"):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()

    c.execute("INSERT INTO findings (target, tool, vulnerability, details, severity, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (target, tool, vulnerability, json.dumps(details), severity, timestamp))

    # Also index in knowledge base for retrieval
    content = f"Vulnerability: {vulnerability}. Details: {json.dumps(details)}. Severity: {severity}"
    c.execute("INSERT INTO knowledge_index (topic, content, source) VALUES (?, ?, ?)",
              (f"Finding: {target}", content, "System"))

    conn.commit()
    conn.close()

# --- Lessons (The "Learning" Part) ---
def add_lesson(trigger_keywords, lesson_text, confidence=1.0):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO lessons (trigger_keywords, lesson_text, confidence, created_at) VALUES (?, ?, ?, ?)",
              (trigger_keywords, lesson_text, confidence, datetime.now().isoformat()))

    # Index for search
    c.execute("INSERT INTO knowledge_index (topic, content, source) VALUES (?, ?, ?)",
              ("Lesson", lesson_text, "Self-Reflection"))

    conn.commit()
    conn.close()

def search_knowledge(query, limit=5):
    """
    Retrieves relevant knowledge (findings or lessons) based on a query string.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    results = []
    try:
        # FTS search
        c.execute("SELECT * FROM knowledge_index WHERE knowledge_index MATCH ? ORDER BY rank LIMIT ?", (query, limit))
        rows = c.fetchall()
        for row in rows:
            results.append(dict(row))
    except sqlite3.OperationalError:
        # Fallback LIKE search
        c.execute("SELECT * FROM knowledge_index WHERE content LIKE ? LIMIT ?", (f"%{query}%", limit))
        rows = c.fetchall()
        for row in rows:
            results.append(dict(row))

    conn.close()
    return results

# --- Mission Management ---
def create_mission(target, goal):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO missions (target, goal, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
              (target, goal, "PENDING", datetime.now().isoformat(), datetime.now().isoformat()))
    mission_id = c.lastrowid
    conn.commit()
    conn.close()
    return mission_id

def update_mission(mission_id, status=None, plan=None, context=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    updates = []
    params = []

    if status:
        updates.append("status = ?")
        params.append(status)
    if plan:
        updates.append("plan = ?")
        params.append(json.dumps(plan))
    if context:
        updates.append("context = ?")
        params.append(json.dumps(context))

    updates.append("updated_at = ?")
    params.append(datetime.now().isoformat())
    params.append(mission_id)

    query = f"UPDATE missions SET {', '.join(updates)} WHERE id = ?"
    c.execute(query, tuple(params))
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
