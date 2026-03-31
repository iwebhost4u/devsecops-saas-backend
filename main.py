import os
from datetime import datetime, UTC
from typing import Any

import psycopg2
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://devsecops-ai-agent-ba24eb.gitlab.io"
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL")


# -----------------------------
# DB Connection
# -----------------------------
def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id SERIAL PRIMARY KEY,
            timestamp TEXT,
            project TEXT,
            pipeline_id TEXT,
            status TEXT,
            severity_tier TEXT,
            high INT,
            medium INT,
            low INT,
            sbom_critical INT,
            sbom_high INT,
            sbom_medium INT,
            sbom_low INT,
            anomaly TEXT,
            ticket_url TEXT,
            sla_hours INT,
            sla_deadline TEXT
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


# -----------------------------
# Model
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
    anomaly: str = ""
    ticket_url: str = ""
    sla_hours: int = 0
    sla_deadline: str = ""


# -----------------------------
# Insert
# -----------------------------
@app.post("/metrics")
def submit_metrics(metric: Metric):
    conn = get_conn()
    cur = conn.cursor()

    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    cur.execute("""
        INSERT INTO metrics (
            timestamp, project, pipeline_id, status, severity_tier,
            high, medium, low,
            sbom_critical, sbom_high, sbom_medium, sbom_low,
            anomaly, ticket_url, sla_hours, sla_deadline
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
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
        metric.sla_deadline
    ))

    conn.commit()
    cur.close()
    conn.close()

    return {"status": "stored"}


# -----------------------------
# Fetch
# -----------------------------
@app.get("/metrics")
def get_metrics():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT * FROM metrics ORDER BY id ASC")
    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows


# -----------------------------
# Health
# -----------------------------
@app.get("/")
def root():
    return {"message": "SaaS API running"}