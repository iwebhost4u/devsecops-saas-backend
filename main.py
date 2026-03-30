from datetime import datetime, timedelta, UTC
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()

DB_PATH = Path("metrics.db")


# -----------------------------
# Database helpers
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            project TEXT,
            pipeline_id TEXT,
            status TEXT,
            severity_tier TEXT,
            high INTEGER,
            medium INTEGER,
            low INTEGER,
            sbom_critical INTEGER,
            sbom_high INTEGER,
            sbom_medium INTEGER,
            sbom_low INTEGER,
            anomaly TEXT,
            ticket_url TEXT,
            sla_hours INTEGER,
            sla_deadline TEXT
        )
        """
    )

    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


# -----------------------------
# Data model
# -----------------------------
class Metric(BaseModel):
    project: str
    pipeline_id: str
    status: str
    severity_tier: str
    high: int
    medium: int
    low: int
    sbom_critical: int = 0
    sbom_high: int = 0
    sbom_medium: int = 0
    sbom_low: int = 0

    # NEW FIELDS
    anomaly: str = ""
    ticket_url: str = ""
    sla_hours: int = 0
    sla_deadline: str = ""


# -----------------------------
# Insert metric
# -----------------------------
@app.post("/metrics")
def submit_metrics(metric: Metric) -> dict[str, Any]:
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    conn = get_conn()

    conn.execute(
        """
        INSERT INTO metrics (
            timestamp, project, pipeline_id, status, severity_tier,
            high, medium, low,
            sbom_critical, sbom_high, sbom_medium, sbom_low,
            anomaly, ticket_url, sla_hours, sla_deadline
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            metric.project,
            metric.pipeline_id,
            metric.status,
            metric.severity_tier,
            metric.high,
            metric.medium,
            metric.low,
            metric.sbom_critical,
            metric.sbom_high,
            metric.sbom_medium,
            metric.sbom_low,
            metric.anomaly,
            metric.ticket_url,
            metric.sla_hours,
            metric.sla_deadline,
        ),
    )

    conn.commit()

    total = conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0]
    conn.close()

    return {"status": "stored", "total": total}


# -----------------------------
# Get metrics
# -----------------------------
@app.get("/metrics")
def get_metrics():
    conn = get_conn()

    rows = conn.execute(
        """
        SELECT *
        FROM metrics
        ORDER BY id ASC
        """
    ).fetchall()

    conn.close()

    return [dict(row) for row in rows]


# -----------------------------
# Clear metrics (optional)
# -----------------------------
@app.delete("/metrics")
def clear_metrics():
    conn = get_conn()
    conn.execute("DELETE FROM metrics")
    conn.commit()
    conn.close()

    return {"status": "cleared"}


# -----------------------------
# Health check
# -----------------------------
@app.get("/")
def root():
    return {"message": "DevSecOps SaaS API running"}