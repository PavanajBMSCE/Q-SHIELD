
import sqlite3
from config import Config


def get_db_connection():
    connection = sqlite3.connect(Config.DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            filename TEXT,
            upload_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            file_name TEXT,
            line_number INTEGER,
            algorithm TEXT,
            algorithm_type TEXT,
            detected_usage TEXT,
            severity TEXT,
            finding TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id)
                ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS crypto_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            algorithm TEXT,
            algorithm_type TEXT,
            key_size TEXT,
            file_name TEXT,
            purpose TEXT,
            assessment TEXT,
            migration_priority TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(id)
                ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            readiness_score REAL,
            risk_level TEXT,
            summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(id)
                ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            source_algorithm TEXT,
            recommended_algorithm TEXT,
            reason TEXT,
            priority TEXT,
            standard_reference TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(id)
                ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS migration_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mode TEXT,
            algorithm TEXT,
            operation TEXT,
            input_size INTEGER,
            output_size INTEGER,
            execution_time REAL,
            success INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS benchmark_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT,
            mode TEXT,
            operation TEXT,
            key_size INTEGER,
            ciphertext_size INTEGER,
            execution_time REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comparative_benchmark_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            benchmark_id TEXT NOT NULL UNIQUE,
            repetitions INTEGER NOT NULL,
            warmups INTEGER NOT NULL,
            report_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comparison_jobs (
            comparison_id TEXT PRIMARY KEY,
            before_name TEXT NOT NULL,
            after_name TEXT NOT NULL,
            before_sha256 TEXT,
            after_sha256 TEXT,
            report_path TEXT NOT NULL,
            pdf_path TEXT NOT NULL,
            evidence_path TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Indexes for faster project-specific retrieval.
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_scan_results_project
        ON scan_results(project_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_inventory_project
        ON crypto_inventory(project_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_inventory_algorithm
        ON crypto_inventory(project_id, algorithm)
    """)

    connection.commit()
    connection.close()

    print("Q-SHIELD database initialized successfully.")
