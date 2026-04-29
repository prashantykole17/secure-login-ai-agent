from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage


DEMO_USERS = [
    {
        "customer_id": "CUST1001",
        "full_name": "Alpha Mercer",
        "username": "alpha.m",
        "password": "Secure@123",
        "email": "alpha.mercer@bankdemo.local",
        "phone": "+1-312-555-4101",
        "home_city": "Chicago",
        "status": "active",
        "failed_attempts": 0,
        "trusted_devices": ["alpha-iphone", "studio-macbook"],
        "requires_password_reset": 0,
    },
    {
        "customer_id": "CUST1002",
        "full_name": "Gemma Cross",
        "username": "gemma.c",
        "password": "Bank@789",
        "email": "gemma.cross@bankdemo.local",
        "phone": "+1-214-555-6722",
        "home_city": "Dallas",
        "status": "locked",
        "failed_attempts": 4,
        "trusted_devices": ["gemma-thinkpad"],
        "requires_password_reset": 0,
    },
    {
        "customer_id": "CUST1003",
        "full_name": "Beta Cole",
        "username": "beta.c",
        "password": "Reset@456",
        "email": "beta.cole@bankdemo.local",
        "phone": "+1-408-555-6723",
        "home_city": "San Jose",
        "status": "active",
        "failed_attempts": 0,
        "trusted_devices": ["beta-pixel", "home-ipad"],
        "requires_password_reset": 0,
    },
    {
        "customer_id": "CUST1004",
        "full_name": "Delta Drake",
        "username": "delta.d",
        "password": "Vault#321",
        "email": "delta.drake@bankdemo.local",
        "phone": "+1-917-555-6724",
        "home_city": "New York",
        "status": "restricted",
        "failed_attempts": 1,
        "trusted_devices": ["delta-surface"],
        "requires_password_reset": 1,
    },
    {
        "customer_id": "CUST1005",
        "full_name": "Zeta Zane",
        "username": "zeta.z",
        "password": "Orbit#654",
        "email": "zeta.zane@bankdemo.local",
        "phone": "+1-646-555-6725",
        "home_city": "Boston",
        "status": "active",
        "failed_attempts": 0,
        "trusted_devices": ["zeta-tablet"],
        "requires_password_reset": 0,
    },
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(dt: datetime | None = None) -> str:
    return (dt or utc_now()).replace(microsecond=0).isoformat()


def json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def normalize_text(value: str | None) -> str:
    return (value or "").strip().lower()


def extract_last4(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    return digits[-4:]


def normalize_phone(value: str | None) -> str:
    return "".join(ch for ch in (value or "") if ch.isdigit())


def password_is_strong(password: str) -> bool:
    return (
        len(password) >= 8
        and any(ch.islower() for ch in password)
        and any(ch.isupper() for ch in password)
        and any(ch.isdigit() for ch in password)
    )


class BankingRepository:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout = 30000;")
        return conn

    def _drop_all_tables(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            DROP TABLE IF EXISTS risk_assessments;
            DROP TABLE IF EXISTS workflow_runs;
            DROP TABLE IF EXISTS customer_memory;
            DROP TABLE IF EXISTS utility_mobile_otps;
            DROP TABLE IF EXISTS security_alerts;
            DROP TABLE IF EXISTS otp_challenges;
            DROP TABLE IF EXISTS login_events;
            DROP TABLE IF EXISTS chat_messages;
            DROP TABLE IF EXISTS human_checks;
            DROP TABLE IF EXISTS support_sessions;
            DROP TABLE IF EXISTS users;
            """
        )

    def init_db(self, reset: bool = False) -> None:
        with self.connect() as conn:
            if reset:
                self._drop_all_tables(conn)
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_id TEXT NOT NULL UNIQUE,
                    full_name TEXT NOT NULL,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    phone_last4 TEXT NOT NULL,
                    home_city TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    trusted_devices TEXT NOT NULL DEFAULT '[]',
                    requires_password_reset INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS support_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_token TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS human_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL UNIQUE,
                    question TEXT NOT NULL,
                    answer TEXT NOT NULL,
                    is_verified INTEGER NOT NULL DEFAULT 0,
                    honeypot_hits INTEGER NOT NULL DEFAULT 0,
                    issued_at TEXT NOT NULL,
                    verified_at TEXT,
                    FOREIGN KEY (session_id) REFERENCES support_sessions(id)
                );

                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES support_sessions(id)
                );

                CREATE TABLE IF NOT EXISTS login_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    attempted_username TEXT,
                    device_id TEXT,
                    location TEXT,
                    outcome TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    ip_address TEXT DEFAULT '127.0.0.1',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS otp_challenges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_id INTEGER,
                    purpose TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    code TEXT NOT NULL,
                    device_id TEXT,
                    location TEXT,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    verified_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (session_id) REFERENCES support_sessions(id)
                );

                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    login_event_id INTEGER,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (login_event_id) REFERENCES login_events(id)
                );

                CREATE TABLE IF NOT EXISTS utility_mobile_otps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone_number TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    code TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS customer_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    memory_key TEXT NOT NULL,
                    memory_value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    session_id INTEGER,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, memory_key),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (session_id) REFERENCES support_sessions(id)
                );

                CREATE TABLE IF NOT EXISTS workflow_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL UNIQUE,
                    user_id INTEGER,
                    workflow_type TEXT NOT NULL DEFAULT 'general_support',
                    status TEXT NOT NULL DEFAULT 'active',
                    current_step TEXT NOT NULL DEFAULT 'conversation_started',
                    last_tool TEXT,
                    resolution TEXT,
                    last_message TEXT,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES support_sessions(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS risk_assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    login_event_id INTEGER,
                    score INTEGER NOT NULL,
                    decision TEXT NOT NULL,
                    signals_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (login_event_id) REFERENCES login_events(id)
                );
                """
            )
            existing = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
            if existing == 0:
                self._seed_demo_data(conn)

    def _seed_demo_data(self, conn: sqlite3.Connection) -> None:
        created_at = utc_iso()
        for user in DEMO_USERS:
            conn.execute(
                """
                INSERT INTO users (
                    customer_id, full_name, username, password, email, phone, phone_last4,
                    home_city, status, failed_attempts, trusted_devices, requires_password_reset,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["customer_id"],
                    user["full_name"],
                    user["username"],
                    user["password"],
                    user["email"],
                    user["phone"],
                    extract_last4(user["phone"]),
                    user["home_city"],
                    user["status"],
                    user["failed_attempts"],
                    json_dumps(user["trusted_devices"]),
                    user["requires_password_reset"],
                    created_at,
                ),
            )

        user_ids = {
            row["username"]: row["id"]
            for row in conn.execute("SELECT id, username FROM users").fetchall()
        }

        trusted_event = self._create_login_event(
            conn,
            user_id=user_ids["alpha.m"],
            attempted_username="alpha.m",
            device_id="alpha-iphone",
            location="Chicago",
            outcome="allowed",
            risk_level="low",
            reason="Trusted device and familiar location",
            created_at=utc_iso(utc_now() - timedelta(hours=8)),
        )
        self._create_security_alert(
            conn,
            user_id=user_ids["alpha.m"],
            login_event_id=trusted_event,
            alert_type="normal_login",
            severity="low",
            summary="Routine trusted-device login",
            status="resolved",
            created_at=utc_iso(utc_now() - timedelta(hours=8)),
        )

        self._create_login_event(
            conn,
            user_id=user_ids["gemma.c"],
            attempted_username="gemma.c",
            device_id="unknown-laptop",
            location="Dallas",
            outcome="blocked",
            risk_level="medium",
            reason="Repeated invalid password attempts caused account lock",
            created_at=utc_iso(utc_now() - timedelta(hours=3)),
        )

        suspicious_event = self._create_login_event(
            conn,
            user_id=user_ids["delta.d"],
            attempted_username="delta.d",
            device_id="unknown-android",
            location="Bucharest",
            outcome="blocked",
            risk_level="high",
            reason="Unknown device combined with unusual location",
            created_at=utc_iso(utc_now() - timedelta(hours=1, minutes=20)),
        )
        self._create_security_alert(
            conn,
            user_id=user_ids["delta.d"],
            login_event_id=suspicious_event,
            alert_type="suspicious_login",
            severity="high",
            summary="Blocked login from Bucharest on unknown-android",
            status="open",
            created_at=utc_iso(utc_now() - timedelta(hours=1, minutes=15)),
        )

    def _create_login_event(
        self,
        conn: sqlite3.Connection,
        *,
        user_id: int | None,
        attempted_username: str | None,
        device_id: str | None,
        location: str | None,
        outcome: str,
        risk_level: str,
        reason: str,
        created_at: str | None = None,
    ) -> int:
        return conn.execute(
            """
            INSERT INTO login_events (
                user_id, attempted_username, device_id, location, outcome, risk_level, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                attempted_username,
                device_id,
                location,
                outcome,
                risk_level,
                reason,
                created_at or utc_iso(),
            ),
        ).lastrowid

    def _create_security_alert(
        self,
        conn: sqlite3.Connection,
        *,
        user_id: int,
        login_event_id: int | None,
        alert_type: str,
        severity: str,
        summary: str,
        status: str = "open",
        created_at: str | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO security_alerts (
                user_id, login_event_id, alert_type, severity, status, summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                login_event_id,
                alert_type,
                severity,
                status,
                summary,
                created_at or utc_iso(),
            ),
        )

    def create_session(self) -> dict[str, Any]:
        with self.connect() as conn:
            token = secrets.token_hex(16)
            created_at = utc_iso()
            session_id = conn.execute(
                """
                INSERT INTO support_sessions (session_token, created_at, updated_at)
                VALUES (?, ?, ?)
                """,
                (token, created_at, created_at),
            ).lastrowid
            greeting = (
                "Hello, I am your login assistance AI agent. I use a conversational "
                "OpenAI model orchestrated with LangGraph. I can help with forgot password, "
                "account unlock, OTP verification, suspicious activity, and new device login."
            )
            conn.execute(
                """
                INSERT INTO chat_messages (session_id, role, content, created_at)
                VALUES (?, 'assistant', ?, ?)
                """,
                (session_id, greeting, created_at),
            )
            conn.execute(
                """
                INSERT INTO workflow_runs (
                    session_id, workflow_type, status, current_step, started_at, updated_at, last_message
                ) VALUES (?, 'general_support', 'active', 'conversation_started', ?, ?, ?)
                """,
                (session_id, created_at, created_at, greeting),
            )
            self._create_human_check(conn, session_id)
            return {"id": session_id, "sessionToken": token}

    def get_or_create_session(self, session_token: str | None) -> dict[str, Any]:
        with self.connect() as conn:
            if session_token:
                row = conn.execute(
                    "SELECT id, session_token FROM support_sessions WHERE session_token = ?",
                    (session_token,),
                ).fetchone()
                if row:
                    return {"id": row["id"], "sessionToken": row["session_token"]}
        return self.create_session()

    def get_latest_human_verified_session(self) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT s.id, s.session_token
                FROM support_sessions s
                JOIN human_checks h ON h.session_id = s.id
                WHERE h.is_verified = 1
                ORDER BY COALESCE(h.verified_at, s.updated_at) DESC, s.id DESC
                LIMIT 1
                """
            ).fetchone()
        if not row:
            return None
        return {"id": row["id"], "sessionToken": row["session_token"]}

    def _generate_human_prompt(self) -> tuple[str, str]:
        left = secrets.randbelow(7) + 3
        right = secrets.randbelow(8) + 2
        return f"Human check: what is {left} + {right}?", str(left + right)

    def _create_human_check(self, conn: sqlite3.Connection, session_id: int) -> None:
        question, answer = self._generate_human_prompt()
        conn.execute(
            """
            INSERT INTO human_checks (session_id, question, answer, is_verified, honeypot_hits, issued_at, verified_at)
            VALUES (?, ?, ?, 0, 0, ?, NULL)
            ON CONFLICT(session_id)
            DO UPDATE SET
                question = excluded.question,
                answer = excluded.answer,
                is_verified = 0,
                honeypot_hits = 0,
                issued_at = excluded.issued_at,
                verified_at = NULL
            """,
            (session_id, question, answer, utc_iso()),
        )

    def get_human_check(self, session_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT question, is_verified, issued_at, verified_at, honeypot_hits
                FROM human_checks
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if not row:
                self._create_human_check(conn, session_id)
                row = conn.execute(
                    """
                    SELECT question, is_verified, issued_at, verified_at, honeypot_hits
                    FROM human_checks
                    WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()

        return {
            "required": not bool(row["is_verified"]),
            "question": row["question"],
            "issuedAt": row["issued_at"],
            "verifiedAt": row["verified_at"],
            "honeypotHits": row["honeypot_hits"],
        }

    def verify_human_check(self, session_id: int, answer: str, honeypot: str = "") -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, question, answer, is_verified, honeypot_hits, issued_at
                FROM human_checks
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if not row:
                self._create_human_check(conn, session_id)
                row = conn.execute(
                    """
                    SELECT id, question, answer, is_verified, honeypot_hits, issued_at
                    FROM human_checks
                    WHERE session_id = ?
                    """,
                    (session_id,),
                ).fetchone()

            if row["is_verified"]:
                return {"ok": True, "message": "Human verification already completed."}

            if honeypot.strip():
                conn.execute(
                    "UPDATE human_checks SET honeypot_hits = honeypot_hits + 1 WHERE id = ?",
                    (row["id"],),
                )
                self._create_human_check(conn, session_id)
                return {
                    "ok": False,
                    "message": "Human verification failed. Please solve the new challenge.",
                }

            solve_seconds = (utc_now() - datetime.fromisoformat(row["issued_at"])).total_seconds()
            if solve_seconds < 1.2:
                self._create_human_check(conn, session_id)
                return {
                    "ok": False,
                    "message": "That was too fast to trust automatically. Please solve the new challenge.",
                }

            if normalize_text(answer) != normalize_text(row["answer"]):
                self._create_human_check(conn, session_id)
                return {
                    "ok": False,
                    "message": "Incorrect answer. Please solve the new challenge.",
                }

            conn.execute(
                """
                UPDATE human_checks
                SET is_verified = 1, verified_at = ?
                WHERE id = ?
                """,
                (utc_iso(), row["id"]),
            )

        return {"ok": True, "message": "Human verification complete."}

    def is_human_verified(self, session_id: int) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT is_verified FROM human_checks WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return bool(row and row["is_verified"])

    def append_chat_message(self, session_id: int, role: str, content: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_messages (session_id, role, content, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (session_id, role, content, utc_iso()),
            )
            conn.execute(
                "UPDATE support_sessions SET updated_at = ? WHERE id = ?",
                (utc_iso(), session_id),
            )
            if role == "user":
                self._upsert_workflow(
                    conn,
                    session_id=session_id,
                    workflow_type=self._infer_workflow_type(content),
                    current_step=self._infer_workflow_step(content),
                    last_message=content,
                )
            elif role == "assistant":
                self._upsert_workflow(
                    conn,
                    session_id=session_id,
                    current_step=self._infer_assistant_step(content),
                    last_message=content,
                    resolution=self._infer_resolution(content),
                    status=self._infer_workflow_status(content),
                )

    def get_session_messages(self, session_id: int) -> list[dict[str, str]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT role, content, created_at
                FROM chat_messages
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            ).fetchall()
            return [
                {
                    "role": row["role"],
                    "content": row["content"],
                    "createdAt": row["created_at"],
                }
                for row in rows
            ]

    def get_langchain_messages(self, session_id: int) -> list[BaseMessage]:
        messages: list[BaseMessage] = []
        for item in self.get_session_messages(session_id):
            if item["role"] == "user":
                messages.append(HumanMessage(content=item["content"]))
            elif item["role"] == "assistant":
                messages.append(AIMessage(content=item["content"]))
        return messages

    def get_user_by_identifier(self, identifier: str) -> sqlite3.Row | None:
        value = identifier.strip()
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT * FROM users
                WHERE lower(username) = lower(?)
                   OR lower(customer_id) = lower(?)
                   OR lower(email) = lower(?)
                """,
                (value, value, value),
            ).fetchone()

    def _user_public(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "customerId": row["customer_id"],
            "fullName": row["full_name"],
            "username": row["username"],
            "password": row["password"],
            "email": row["email"],
            "phone": row["phone"],
            "status": row["status"],
            "homeCity": row["home_city"],
            "failedAttempts": row["failed_attempts"],
            "requiresPasswordReset": bool(row["requires_password_reset"]),
            "trustedDevices": json.loads(row["trusted_devices"] or "[]"),
            "phoneLast4": row["phone_last4"],
        }

    def get_user_snapshot(self, identifier: str) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"found": False, "message": "No customer profile found for that identifier."}
        user = self._user_public(row)
        return {
            "found": True,
            "customerId": user["customerId"],
            "fullName": user["fullName"],
            "username": user["username"],
            "status": user["status"],
            "homeCity": user["homeCity"],
            "requiresPasswordReset": user["requiresPasswordReset"],
            "trustedDevices": user["trustedDevices"],
            "phoneHint": f"ends with {user['phoneLast4']}",
        }

    def _infer_workflow_type(self, message: str | None) -> str | None:
        lowered = normalize_text(message)
        if not lowered:
            return None
        if "unlock" in lowered or "locked" in lowered:
            return "unlock_account"
        if "forgot" in lowered or "reset" in lowered or "password" in lowered:
            return "password_reset"
        if "new device" in lowered or "new phone" in lowered or "new laptop" in lowered:
            return "new_device_login"
        if "suspicious" in lowered or "fraud" in lowered or "unknown login" in lowered:
            return "suspicious_activity"
        if "otp" in lowered:
            return "otp_verification"
        if "login" in lowered:
            return "login_support"
        return None

    def _infer_workflow_step(self, message: str | None) -> str | None:
        lowered = normalize_text(message)
        if not lowered:
            return None
        if lowered in {"yes", "send", "continue"}:
            return "verification_confirmed"
        if lowered in {"no", "cancel", "stop"}:
            return "cancel_requested"
        if lowered == "resend":
            return "otp_regeneration_requested"
        digits = "".join(ch for ch in lowered if ch.isdigit())
        if len(digits) == 6:
            return "otp_submitted"
        if "password" in lowered:
            return "password_discussion"
        if "device" in lowered:
            return "device_context_provided"
        return "customer_message_received"

    def _infer_assistant_step(self, message: str | None) -> str | None:
        lowered = normalize_text(message)
        if not lowered:
            return None
        if "otp" in lowered and "valid for 5 minutes" in lowered:
            return "otp_pending"
        if "enter that 6-digit code" in lowered or "enter the 6-digit code" in lowered:
            return "awaiting_otp"
        if "account unlocked" in lowered:
            return "account_unlocked"
        if "password updated successfully" in lowered:
            return "password_reset_completed"
        if "device" in lowered and "approved" in lowered:
            return "device_approved"
        if "security hold" in lowered or "secured" in lowered:
            return "account_secured"
        return None

    def _infer_workflow_status(self, message: str | None) -> str | None:
        lowered = normalize_text(message)
        if not lowered:
            return None
        if "successfully" in lowered or "ready for login" in lowered or "account unlocked" in lowered:
            return "completed"
        if "cancel" in lowered and "stop" in lowered:
            return "cancelled"
        return None

    def _infer_resolution(self, message: str | None) -> str | None:
        lowered = normalize_text(message)
        if "account unlocked" in lowered:
            return "account_unlocked"
        if "password updated successfully" in lowered:
            return "password_reset"
        if "device" in lowered and "approved" in lowered:
            return "device_approved"
        if "secured" in lowered:
            return "account_secured"
        return None

    def _upsert_workflow(
        self,
        conn: sqlite3.Connection,
        *,
        session_id: int,
        workflow_type: str | None = None,
        status: str | None = None,
        current_step: str | None = None,
        last_tool: str | None = None,
        resolution: str | None = None,
        last_message: str | None = None,
        user_id: int | None = None,
    ) -> None:
        existing = conn.execute(
            """
            SELECT session_id, user_id, workflow_type, status, current_step, last_tool, resolution, last_message
            FROM workflow_runs
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        now = utc_iso()
        if existing:
            conn.execute(
                """
                UPDATE workflow_runs
                SET user_id = COALESCE(?, user_id),
                    workflow_type = COALESCE(?, workflow_type),
                    status = COALESCE(?, status),
                    current_step = COALESCE(?, current_step),
                    last_tool = COALESCE(?, last_tool),
                    resolution = COALESCE(?, resolution),
                    last_message = COALESCE(?, last_message),
                    updated_at = ?
                WHERE session_id = ?
                """,
                (
                    user_id,
                    workflow_type,
                    status,
                    current_step,
                    last_tool,
                    resolution,
                    last_message,
                    now,
                    session_id,
                ),
            )
            return

        conn.execute(
            """
            INSERT INTO workflow_runs (
                session_id, user_id, workflow_type, status, current_step, last_tool, resolution, last_message, started_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                user_id,
                workflow_type or "general_support",
                status or "active",
                current_step or "conversation_started",
                last_tool,
                resolution,
                last_message,
                now,
                now,
            ),
        )

    def _remember(
        self,
        conn: sqlite3.Connection,
        *,
        user_id: int,
        memory_key: str,
        memory_value: str,
        source: str,
        session_id: int | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO customer_memory (
                user_id, memory_key, memory_value, source, session_id, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, memory_key)
            DO UPDATE SET
                memory_value = excluded.memory_value,
                source = excluded.source,
                session_id = excluded.session_id,
                updated_at = excluded.updated_at
            """,
            (user_id, memory_key, memory_value, source, session_id, utc_iso()),
        )

    def remember_customer_detail(
        self,
        identifier: str,
        memory_key: str,
        memory_value: str,
        source: str = "agent",
        session_id: int | None = None,
    ) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No customer found for memory update."}
        with self.connect() as conn:
            self._remember(
                conn,
                user_id=row["id"],
                memory_key=memory_key,
                memory_value=memory_value,
                source=source,
                session_id=session_id,
            )
        return {"ok": True, "message": f"Memory saved for {row['full_name']}.", "memoryKey": memory_key}

    def get_customer_memory(self, identifier: str) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No customer found for memory lookup."}
        with self.connect() as conn:
            memories = conn.execute(
                """
                SELECT memory_key, memory_value, source, updated_at
                FROM customer_memory
                WHERE user_id = ?
                ORDER BY memory_key ASC
                """,
                (row["id"],),
            ).fetchall()
        return {
            "ok": True,
            "fullName": row["full_name"],
            "username": row["username"],
            "memories": [
                {
                    "key": memory["memory_key"],
                    "value": memory["memory_value"],
                    "source": memory["source"],
                    "updatedAt": memory["updated_at"],
                }
                for memory in memories
            ],
        }

    def clear_agent_memory(self) -> dict[str, Any]:
        with self.connect() as conn:
            deleted = conn.execute("SELECT COUNT(*) AS total FROM customer_memory").fetchone()["total"]
            conn.execute("DELETE FROM customer_memory")
        return {
            "ok": True,
            "deletedCount": deleted,
            "message": f"Cleared {deleted} stored memory item(s).",
        }

    def get_workflow_status(self, session_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT w.workflow_type, w.status, w.current_step, w.last_tool, w.resolution, w.updated_at,
                       u.full_name, u.username
                FROM workflow_runs w
                LEFT JOIN users u ON u.id = w.user_id
                WHERE w.session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if not row:
            return {"ok": False, "message": "No workflow status found for this session."}
        return {
            "ok": True,
            "workflowType": row["workflow_type"],
            "status": row["status"],
            "currentStep": row["current_step"],
            "lastTool": row["last_tool"],
            "resolution": row["resolution"],
            "fullName": row["full_name"],
            "username": row["username"],
            "updatedAt": row["updated_at"],
        }

    def explain_account_status(self, identifier: str) -> str:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return "No matching account was found."
        user = self._user_public(row)
        return (
            f"{user['fullName']} ({user['username']}) is currently `{user['status']}`. "
            f"Home city: {user['homeCity']}. Failed attempts: {user['failedAttempts']}. "
            f"Password reset required: {user['requiresPasswordReset']}."
        )

    def _create_otp_with_conn(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        purpose: str,
        session_id: int | None = None,
        device_id: str | None = None,
        location: str | None = None,
    ) -> dict[str, Any]:
        code = f"{secrets.randbelow(1_000_000):06d}"
        challenge_id = conn.execute(
            """
            INSERT INTO otp_challenges (
                user_id, session_id, purpose, channel, code, device_id, location, status,
                expires_at, created_at
            ) VALUES (?, ?, ?, 'sms', ?, ?, ?, 'pending', ?, ?)
            """,
            (
                row["id"],
                session_id,
                purpose,
                code,
                device_id,
                location,
                utc_iso(utc_now() + timedelta(minutes=5)),
                utc_iso(),
            ),
        ).lastrowid
        return {
            "ok": True,
            "challengeId": challenge_id,
            "message": f"OTP sent to the registered phone ending in {row['phone_last4']}.",
            "otpCode": code,
        }

    def create_otp(self, identifier: str, purpose: str, session_id: int | None = None, device_id: str | None = None, location: str | None = None) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No customer found for OTP generation."}
        with self.connect() as conn:
            otp = self._create_otp_with_conn(conn, row, purpose, session_id, device_id, location)
            self._remember(
                conn,
                user_id=row["id"],
                memory_key="preferred_phone",
                memory_value=row["phone"],
                source="workflow",
                session_id=session_id,
            )
            self._remember(
                conn,
                user_id=row["id"],
                memory_key="last_workflow",
                memory_value=purpose,
                source="workflow",
                session_id=session_id,
            )
            if session_id:
                self._upsert_workflow(
                    conn,
                    session_id=session_id,
                    user_id=row["id"],
                    workflow_type=purpose,
                    status="active",
                    current_step="otp_pending",
                    last_tool="generate_otp",
                    last_message=otp["message"],
                )
            return otp

    def get_latest_session_otp(self, session_id: int) -> dict[str, Any]:
        with self.connect() as conn:
            challenge = conn.execute(
                """
                SELECT o.*, u.username, u.full_name, u.phone_last4, u.email
                FROM otp_challenges o
                JOIN users u ON u.id = o.user_id
                WHERE o.session_id = ?
                ORDER BY o.id DESC
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()

        if not challenge:
            return {"ok": False, "message": "No OTP has been generated yet in this chat session."}

        expires_at = datetime.fromisoformat(challenge["expires_at"])
        status = challenge["status"]
        if status == "pending" and expires_at < utc_now():
            with self.connect() as conn:
                conn.execute(
                    "UPDATE otp_challenges SET status = 'expired' WHERE id = ?",
                    (challenge["id"],),
                )
            status = "expired"

        return {
            "ok": True,
            "challengeId": challenge["id"],
            "username": challenge["username"],
            "fullName": challenge["full_name"],
            "phoneLast4": challenge["phone_last4"],
            "email": challenge["email"],
            "purpose": challenge["purpose"],
            "status": status,
            "expiresAt": challenge["expires_at"],
        }

    def verify_otp(self, identifier: str, otp_code: str) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No customer found for OTP verification."}

        code = "".join(ch for ch in otp_code if ch.isdigit())[:6]
        with self.connect() as conn:
            challenge = conn.execute(
                """
                SELECT *
                FROM otp_challenges
                WHERE user_id = ? AND status = 'pending'
                ORDER BY id DESC
                LIMIT 1
                """,
                (row["id"],),
            ).fetchone()
            if not challenge:
                return {"ok": False, "message": "No active OTP challenge exists for this account."}
            if datetime.fromisoformat(challenge["expires_at"]) < utc_now():
                conn.execute(
                    "UPDATE otp_challenges SET status = 'expired' WHERE id = ?",
                    (challenge["id"],),
                )
                return {"ok": False, "message": "OTP expired. Generate a new OTP."}

            attempts = challenge["attempts"] + 1
            conn.execute(
                "UPDATE otp_challenges SET attempts = ? WHERE id = ?",
                (attempts, challenge["id"]),
            )
            if code != challenge["code"]:
                if attempts >= 3:
                    conn.execute(
                        "UPDATE otp_challenges SET status = 'failed' WHERE id = ?",
                        (challenge["id"],),
                    )
                    return {"ok": False, "message": "OTP failed too many times. Generate a new OTP."}
                return {"ok": False, "message": "OTP is incorrect."}

            conn.execute(
                """
                UPDATE otp_challenges
                SET status = 'verified', verified_at = ?
                WHERE id = ?
                """,
                (utc_iso(), challenge["id"]),
            )
        return {"ok": True, "message": "OTP verified successfully."}

    def verify_latest_session_otp(self, session_id: int, otp_code: str) -> dict[str, Any]:
        with self.connect() as conn:
            challenge = conn.execute(
                """
                SELECT o.*, u.username, u.full_name, u.phone_last4
                FROM otp_challenges o
                JOIN users u ON u.id = o.user_id
                WHERE o.session_id = ?
                ORDER BY o.id DESC
                LIMIT 1
                """,
                (session_id,),
            ).fetchone()

            if not challenge:
                return {"ok": False, "message": "No OTP challenge exists yet in this chat session."}

            if challenge["status"] != "pending":
                return {
                    "ok": False,
                    "message": f"The latest OTP for {challenge['username']} is already {challenge['status']}. Generate a new OTP if needed.",
                }

            if datetime.fromisoformat(challenge["expires_at"]) < utc_now():
                conn.execute(
                    "UPDATE otp_challenges SET status = 'expired' WHERE id = ?",
                    (challenge["id"],),
                )
                return {
                    "ok": False,
                    "message": f"The OTP for {challenge['username']} expired. Generate a new OTP for the phone ending in {challenge['phone_last4']}.",
                }

            entered_code = "".join(ch for ch in otp_code if ch.isdigit())[:6]
            attempts = challenge["attempts"] + 1
            conn.execute(
                "UPDATE otp_challenges SET attempts = ? WHERE id = ?",
                (attempts, challenge["id"]),
            )

            if entered_code != challenge["code"]:
                if attempts >= 3:
                    conn.execute(
                        "UPDATE otp_challenges SET status = 'failed' WHERE id = ?",
                        (challenge["id"],),
                    )
                    return {
                        "ok": False,
                        "message": f"The OTP is incorrect and the challenge is now closed for {challenge['username']}. Generate a new OTP for the phone ending in {challenge['phone_last4']}.",
                    }
                return {
                    "ok": False,
                    "message": f"The OTP is incorrect. Re-enter the 6-digit code sent to the phone ending in {challenge['phone_last4']}.",
                }

            conn.execute(
                """
                UPDATE otp_challenges
                SET status = 'verified', verified_at = ?
                WHERE id = ?
                """,
                (utc_iso(), challenge["id"]),
            )
            self._upsert_workflow(
                conn,
                session_id=session_id,
                user_id=challenge["user_id"],
                current_step="otp_verified",
                last_tool="verify_latest_session_otp",
                last_message="Session OTP verified successfully.",
            )

        return {
            "ok": True,
            "username": challenge["username"],
            "fullName": challenge["full_name"],
            "purpose": challenge["purpose"],
            "message": f"OTP verified successfully for {challenge['username']}.",
        }

    def unlock_account(self, identifier: str, session_id: int | None = None) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No matching customer account found."}
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET status = 'active', failed_attempts = 0
                WHERE id = ?
                """,
                (row["id"],),
            )
            self._create_login_event(
                conn,
                user_id=row["id"],
                attempted_username=row["username"],
                device_id=None,
                location=row["home_city"],
                outcome="account_unlocked",
                risk_level="low",
                reason="Account unlocked through support workflow",
            )
            self._remember(
                conn,
                user_id=row["id"],
                memory_key="last_resolution",
                memory_value="account_unlocked",
                source="workflow",
                session_id=session_id,
            )
            if session_id:
                self._upsert_workflow(
                    conn,
                    session_id=session_id,
                    user_id=row["id"],
                    workflow_type="unlock_account",
                    status="completed",
                    current_step="account_unlocked",
                    last_tool="unlock_customer_account",
                    resolution="account_unlocked",
                    last_message=f"Account unlocked for {row['full_name']}.",
                )
        return {"ok": True, "message": f"Account unlocked for {row['full_name']}."}

    def reset_password(self, identifier: str, new_password: str, session_id: int | None = None) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No matching customer account found."}
        if not password_is_strong(new_password):
            return {
                "ok": False,
                "message": "Password must be at least 8 characters with uppercase, lowercase, and a number.",
            }
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET password = ?, status = 'active', failed_attempts = 0, requires_password_reset = 0
                WHERE id = ?
                """,
                (new_password, row["id"]),
            )
            conn.execute(
                """
                UPDATE security_alerts
                SET status = 'resolved', resolved_at = ?
                WHERE user_id = ? AND status = 'open'
                """,
                (utc_iso(), row["id"]),
            )
            self._create_login_event(
                conn,
                user_id=row["id"],
                attempted_username=row["username"],
                device_id=None,
                location=row["home_city"],
                outcome="password_reset",
                risk_level="low",
                reason="Password updated through AI assistant workflow",
            )
            self._remember(
                conn,
                user_id=row["id"],
                memory_key="last_resolution",
                memory_value="password_reset",
                source="workflow",
                session_id=session_id,
            )
            if session_id:
                self._upsert_workflow(
                    conn,
                    session_id=session_id,
                    user_id=row["id"],
                    workflow_type="password_reset",
                    status="completed",
                    current_step="password_reset_completed",
                    last_tool="reset_customer_password",
                    resolution="password_reset",
                    last_message=f"Password updated successfully for {row['full_name']}.",
                )
        return {"ok": True, "message": f"Password updated successfully for {row['full_name']}."}

    def approve_new_device(self, identifier: str, device_id: str, location: str, session_id: int | None = None) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No matching customer account found."}
        trusted_devices = json.loads(row["trusted_devices"] or "[]")
        if normalize_text(device_id) not in {normalize_text(item) for item in trusted_devices}:
            trusted_devices.append(device_id.strip())
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET trusted_devices = ?, failed_attempts = 0 WHERE id = ?",
                (json_dumps(trusted_devices), row["id"]),
            )
            self._create_login_event(
                conn,
                user_id=row["id"],
                attempted_username=row["username"],
                device_id=device_id,
                location=location,
                outcome="allowed_with_otp",
                risk_level="medium",
                reason="New device approved after assisted verification",
            )
            self._remember(
                conn,
                user_id=row["id"],
                memory_key="last_approved_device",
                memory_value=device_id,
                source="workflow",
                session_id=session_id,
            )
            if session_id:
                self._upsert_workflow(
                    conn,
                    session_id=session_id,
                    user_id=row["id"],
                    workflow_type="new_device_login",
                    status="completed",
                    current_step="device_approved",
                    last_tool="approve_customer_device",
                    resolution="device_approved",
                    last_message=f"Device {device_id} approved for {row['full_name']}.",
                )
        return {
            "ok": True,
            "message": f"Device `{device_id}` approved for {row['full_name']} from {location}.",
        }

    def get_security_alerts(self, identifier: str) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No matching customer account found."}
        with self.connect() as conn:
            alerts = conn.execute(
                """
                SELECT severity, status, summary, created_at
                FROM security_alerts
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 5
                """,
                (row["id"],),
            ).fetchall()
        if not alerts:
            return {"ok": True, "message": "No security alerts are recorded for this customer.", "alerts": []}
        return {
            "ok": True,
            "alerts": [
                {
                    "severity": alert["severity"],
                    "status": alert["status"],
                    "summary": alert["summary"],
                    "createdAt": alert["created_at"],
                }
                for alert in alerts
            ],
            "message": "Security alerts retrieved successfully.",
        }

    def secure_account(self, identifier: str, session_id: int | None = None) -> dict[str, Any]:
        row = self.get_user_by_identifier(identifier)
        if not row:
            return {"ok": False, "message": "No matching customer account found."}
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET status = 'restricted', requires_password_reset = 1
                WHERE id = ?
                """,
                (row["id"],),
            )
            event_id = self._create_login_event(
                conn,
                user_id=row["id"],
                attempted_username=row["username"],
                device_id=None,
                location=row["home_city"],
                outcome="account_secured",
                risk_level="high",
                reason="Customer requested immediate security hold",
            )
            self._create_security_alert(
                conn,
                user_id=row["id"],
                login_event_id=event_id,
                alert_type="manual_security_hold",
                severity="high",
                summary="Account placed into restricted mode through AI support flow",
            )
            self._remember(
                conn,
                user_id=row["id"],
                memory_key="last_resolution",
                memory_value="account_secured",
                source="workflow",
                session_id=session_id,
            )
            if session_id:
                self._upsert_workflow(
                    conn,
                    session_id=session_id,
                    user_id=row["id"],
                    workflow_type="suspicious_activity",
                    status="completed",
                    current_step="account_secured",
                    last_tool="secure_customer_account",
                    resolution="account_secured",
                    last_message=f"Account secured for {row['full_name']}.",
                )
        return {"ok": True, "message": f"Account secured for {row['full_name']}. Password reset is now required."}

    def get_dashboard_data(self) -> dict[str, Any]:
        with self.connect() as conn:
            users = [
                self._user_public(row)
                for row in conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
            ]
            events = [
                {
                    "username": row["attempted_username"],
                    "deviceId": row["device_id"],
                    "location": row["location"],
                    "outcome": row["outcome"],
                    "riskLevel": row["risk_level"],
                    "reason": row["reason"],
                    "createdAt": row["created_at"],
                }
                for row in conn.execute(
                    """
                    SELECT attempted_username, device_id, location, outcome, risk_level, reason, created_at
                    FROM login_events
                    ORDER BY id DESC
                    LIMIT 10
                    """
                ).fetchall()
            ]
            alerts = [
                {
                    "summary": row["summary"],
                    "severity": row["severity"],
                    "status": row["status"],
                    "createdAt": row["created_at"],
                }
                for row in conn.execute(
                    """
                    SELECT summary, severity, status, created_at
                    FROM security_alerts
                    ORDER BY id DESC
                    LIMIT 10
                    """
                ).fetchall()
            ]
            workflows = [
                {
                    "workflowType": row["workflow_type"],
                    "status": row["status"],
                    "currentStep": row["current_step"],
                    "fullName": row["full_name"],
                    "username": row["username"],
                    "lastTool": row["last_tool"],
                    "updatedAt": row["updated_at"],
                }
                for row in conn.execute(
                    """
                    SELECT w.workflow_type, w.status, w.current_step, w.last_tool, w.updated_at,
                           u.full_name, u.username
                    FROM workflow_runs w
                    LEFT JOIN users u ON u.id = w.user_id
                    ORDER BY w.updated_at DESC
                    LIMIT 10
                    """
                ).fetchall()
            ]
            memories = [
                {
                    "fullName": row["full_name"],
                    "username": row["username"],
                    "key": row["memory_key"],
                    "value": row["memory_value"],
                    "source": row["source"],
                    "updatedAt": row["updated_at"],
                }
                for row in conn.execute(
                    """
                    SELECT m.memory_key, m.memory_value, m.source, m.updated_at, u.full_name, u.username
                    FROM customer_memory m
                    JOIN users u ON u.id = m.user_id
                    ORDER BY m.updated_at DESC
                    LIMIT 12
                    """
                ).fetchall()
            ]
            risk_assessments = [
                {
                    "username": row["username"],
                    "score": row["score"],
                    "decision": row["decision"],
                    "signals": json.loads(row["signals_json"]),
                    "createdAt": row["created_at"],
                }
                for row in conn.execute(
                    """
                    SELECT r.score, r.decision, r.signals_json, r.created_at, u.username
                    FROM risk_assessments r
                    LEFT JOIN users u ON u.id = r.user_id
                    ORDER BY r.created_at DESC
                    LIMIT 10
                    """
                ).fetchall()
            ]
            metrics_row = conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM workflow_runs WHERE status = 'active') AS active_workflows,
                    (SELECT COUNT(*) FROM security_alerts WHERE status = 'open') AS open_alerts,
                    (SELECT COUNT(*) FROM otp_challenges WHERE status = 'pending') AS pending_otps,
                    (SELECT COUNT(*) FROM risk_assessments WHERE decision = 'block') AS blocked_risk_cases
                """
            ).fetchone()
            metrics = {
                "activeWorkflows": metrics_row["active_workflows"],
                "openAlerts": metrics_row["open_alerts"],
                "pendingOtps": metrics_row["pending_otps"],
                "blockedRiskCases": metrics_row["blocked_risk_cases"],
            }
            return {
                "users": users,
                "events": events,
                "alerts": alerts,
                "workflows": workflows,
                "memories": memories,
                "riskAssessments": risk_assessments,
                "metrics": metrics,
            }

    def generate_mobile_demo_otp(self, phone_number: str, purpose: str = "demo_mobile_otp") -> dict[str, Any]:
        digits = normalize_phone(phone_number)
        if len(digits) < 10:
            return {"ok": False, "message": "Enter a valid mobile number with at least 10 digits."}

        display_number = phone_number.strip()
        code = f"{secrets.randbelow(1_000_000):06d}"
        created_at = utc_iso()
        expires_at = utc_iso(utc_now() + timedelta(minutes=5))

        with self.connect() as conn:
            otp_id = conn.execute(
                """
                INSERT INTO utility_mobile_otps (
                    phone_number, purpose, code, status, expires_at, created_at
                ) VALUES (?, ?, ?, 'generated', ?, ?)
                """,
                (display_number, purpose, code, expires_at, created_at),
            ).lastrowid

        return {
            "ok": True,
            "otpId": otp_id,
            "phoneNumber": display_number,
            "purpose": purpose,
            "otpCode": code,
            "expiresAt": expires_at,
            "validForSeconds": 300,
            "message": f"OTP generated for {display_number}.",
        }

    def verify_mobile_demo_otp(self, phone_number: str, otp_code: str) -> dict[str, Any]:
        digits = normalize_phone(phone_number)
        entered_code = "".join(ch for ch in otp_code if ch.isdigit())[:6]
        if len(digits) < 10:
            return {"ok": False, "message": "Enter a valid mobile number with at least 10 digits."}
        if len(entered_code) != 6:
            return {"ok": False, "message": "Enter the 6-digit OTP code."}

        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, phone_number, purpose, code, status, expires_at, created_at
                FROM utility_mobile_otps
                WHERE status = 'generated'
                ORDER BY id DESC
                LIMIT 50
                """
            ).fetchall()

            challenge = next(
                (
                    row
                    for row in rows
                    if normalize_phone(row["phone_number"]) == digits
                ),
                None,
            )

            if not challenge:
                return {"ok": False, "message": "No active generated OTP was found for that mobile number."}

            expires_at = datetime.fromisoformat(challenge["expires_at"])
            if expires_at < utc_now():
                conn.execute(
                    "UPDATE utility_mobile_otps SET status = 'expired' WHERE id = ?",
                    (challenge["id"],),
                )
                return {"ok": False, "message": "OTP expired. Generate a new OTP."}

            if entered_code != challenge["code"]:
                return {"ok": False, "message": "OTP validation failed. The code does not match."}

            conn.execute(
                "UPDATE utility_mobile_otps SET status = 'verified' WHERE id = ?",
                (challenge["id"],),
            )

        return {
            "ok": True,
            "phoneNumber": phone_number.strip(),
            "message": "OTP verified successfully.",
        }

    def get_recent_mobile_demo_otps(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, phone_number, purpose, code, status, expires_at, created_at
                FROM utility_mobile_otps
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            now = utc_now()
            for row in rows:
                if row["status"] == "generated" and datetime.fromisoformat(row["expires_at"]) < now:
                    conn.execute(
                        "UPDATE utility_mobile_otps SET status = 'expired' WHERE id = ?",
                        (row["id"],),
                    )
        return [
            {
                "id": row["id"],
                "phoneNumber": row["phone_number"],
                "purpose": row["purpose"],
                "otpCode": row["code"],
                "status": (
                    "expired"
                    if row["status"] == "generated" and datetime.fromisoformat(row["expires_at"]) < utc_now()
                    else row["status"]
                ),
                "expiresAt": row["expires_at"],
                "createdAt": row["created_at"],
                "remainingSeconds": max(
                    0,
                    int((datetime.fromisoformat(row["expires_at"]) - utc_now()).total_seconds()),
                ),
            }
            for row in rows
        ]

    def get_latest_banking_chat_otp_by_phone(self, phone_number: str) -> dict[str, Any]:
        digits = normalize_phone(phone_number)
        if len(digits) < 10:
            return {"ok": False, "message": "Enter a valid mobile number with at least 10 digits."}

        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT o.id, o.purpose, o.code, o.status, o.expires_at, o.created_at,
                       u.full_name, u.username, u.phone
                FROM otp_challenges o
                JOIN users u ON u.id = o.user_id
                ORDER BY o.id DESC
                LIMIT 100
                """
            ).fetchall()

        challenge = next(
            (row for row in rows if normalize_phone(row["phone"]) == digits),
            None,
        )

        if not challenge:
            return {"ok": False, "message": "No banking chat OTP was found for that mobile number yet."}

        expires_at = datetime.fromisoformat(challenge["expires_at"])
        status = challenge["status"]
        remaining_seconds = max(0, int((expires_at - utc_now()).total_seconds()))
        if status == "pending" and remaining_seconds == 0:
            with self.connect() as conn:
                conn.execute(
                    "UPDATE otp_challenges SET status = 'expired' WHERE id = ?",
                    (challenge["id"],),
                )
            status = "expired"

        return {
            "ok": True,
            "phoneNumber": challenge["phone"],
            "fullName": challenge["full_name"],
            "username": challenge["username"],
            "purpose": challenge["purpose"],
            "otpCode": challenge["code"],
            "status": status,
            "expiresAt": challenge["expires_at"],
            "createdAt": challenge["created_at"],
            "remainingSeconds": remaining_seconds,
            "message": f"Latest banking chat OTP fetched for {challenge['full_name']}.",
        }

    def _record_risk_assessment(
        self,
        conn: sqlite3.Connection,
        *,
        user_id: int | None,
        login_event_id: int | None,
        score: int,
        decision: str,
        signals: list[str],
    ) -> None:
        conn.execute(
            """
            INSERT INTO risk_assessments (
                user_id, login_event_id, score, decision, signals_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, login_event_id, score, decision, json_dumps(signals), utc_iso()),
        )

    def _compute_risk(self, conn: sqlite3.Connection, user: sqlite3.Row, device_id: str, location: str) -> dict[str, Any]:
        score = 0
        reasons: list[str] = []
        signals: list[str] = []
        trusted_devices = json.loads(user["trusted_devices"] or "[]")
        normalized_device = normalize_text(device_id)
        normalized_location = normalize_text(location)
        risky_locations = {"bucharest", "moscow", "lagos", "tehran", "kyiv"}

        if normalized_device not in {normalize_text(item) for item in trusted_devices}:
            score += 45
            reasons.append("Unrecognized device")
            signals.append("new_device")
        if location and normalized_location != normalize_text(user["home_city"]):
            score += 35
            reasons.append("Location differs from home city")
            signals.append("location_mismatch")
        if user["failed_attempts"] >= 2:
            score += 20
            reasons.append("Recent failed password attempts")
            signals.append("failed_attempt_pattern")
        if user["requires_password_reset"]:
            score += 20
            reasons.append("Account marked for password reset")
            signals.append("reset_required")

        if normalized_location in risky_locations:
            score += 25
            reasons.append("Location flagged as elevated risk")
            signals.append("risky_location")

        recent_event = conn.execute(
            """
            SELECT location, created_at
            FROM login_events
            WHERE user_id = ? AND outcome IN ('allowed', 'allowed_with_otp')
            ORDER BY id DESC
            LIMIT 1
            """,
            (user["id"],),
        ).fetchone()
        if recent_event:
            recent_time = datetime.fromisoformat(recent_event["created_at"])
            recent_location = normalize_text(recent_event["location"])
            if (
                recent_location
                and normalized_location
                and recent_location != normalized_location
                and (utc_now() - recent_time) <= timedelta(hours=6)
            ):
                score += 20
                reasons.append("Recent login from another city suggests unusual travel")
                signals.append("impossible_travel_like_pattern")

        open_alert_count = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_alerts
            WHERE user_id = ? AND status = 'open'
            """,
            (user["id"],),
        ).fetchone()["total"]
        if open_alert_count:
            score += 10
            reasons.append("Existing open security alerts on the profile")
            signals.append("open_security_alerts")

        if user["status"] == "restricted":
            return {
                "score": 90,
                "decision": "block",
                "reasons": ["Account already secured pending reset"],
                "signals": ["restricted_account"],
            }
        if score >= 75:
            return {
                "score": score,
                "decision": "block",
                "reasons": reasons or ["High-risk signal detected"],
                "signals": signals or ["high_risk"],
            }
        if score >= 40:
            return {
                "score": score,
                "decision": "otp_required",
                "reasons": reasons or ["Step-up verification required"],
                "signals": signals or ["medium_risk"],
            }
        return {
            "score": score,
            "decision": "allowed",
            "reasons": reasons or ["Trusted login pattern"],
            "signals": signals or ["trusted_pattern"],
        }

    def simulate_login(self, username: str, password: str, device_id: str, location: str) -> dict[str, Any]:
        row = self.get_user_by_identifier(username)
        if not row:
            with self.connect() as conn:
                self._create_login_event(
                    conn,
                    user_id=None,
                    attempted_username=username,
                    device_id=device_id,
                    location=location,
                    outcome="blocked",
                    risk_level="medium",
                    reason="Unknown username",
                )
            return {"status": "blocked", "message": "Unknown username or customer ID."}

        with self.connect() as conn:
            if row["status"] == "locked":
                self._create_login_event(
                    conn,
                    user_id=row["id"],
                    attempted_username=row["username"],
                    device_id=device_id,
                    location=location,
                    outcome="blocked",
                    risk_level="high",
                    reason="Account is locked and needs support recovery",
                )
                return {"status": "blocked", "message": "Account is locked. Use the chatbot unlock flow."}

            if password != row["password"]:
                failed_attempts = row["failed_attempts"] + 1
                conn.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (failed_attempts, row["id"]),
                )
                reason = "Invalid password"
                if failed_attempts >= 3:
                    conn.execute(
                        "UPDATE users SET status = 'locked' WHERE id = ?",
                        (row["id"],),
                    )
                    reason = "Invalid password threshold exceeded and account locked"
                self._create_login_event(
                    conn,
                    user_id=row["id"],
                    attempted_username=row["username"],
                    device_id=device_id,
                    location=location,
                    outcome="blocked",
                    risk_level="medium",
                    reason=reason,
                )
                return {
                    "status": "blocked",
                    "message": "Password incorrect. After 3 failed attempts the account becomes locked.",
                }

            risk = self._compute_risk(conn, row, device_id, location)
            decision = risk["decision"]
            reasons = risk["reasons"]
            if decision == "allowed":
                conn.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (row["id"],))
                login_event_id = self._create_login_event(
                    conn,
                    user_id=row["id"],
                    attempted_username=row["username"],
                    device_id=device_id,
                    location=location,
                    outcome="allowed",
                    risk_level="low",
                    reason=", ".join(reasons),
                )
                self._record_risk_assessment(
                    conn,
                    user_id=row["id"],
                    login_event_id=login_event_id,
                    score=risk["score"],
                    decision=decision,
                    signals=risk["signals"],
                )
                return {
                    "status": "allowed",
                    "message": "Login allowed. Trusted profile and low-risk signal.",
                    "riskScore": risk["score"],
                    "riskReasons": reasons,
                    "riskSignals": risk["signals"],
                }

            if decision == "otp_required":
                otp = self._create_otp_with_conn(conn, row, "login", None, device_id, location)
                login_event_id = self._create_login_event(
                    conn,
                    user_id=row["id"],
                    attempted_username=row["username"],
                    device_id=device_id,
                    location=location,
                    outcome="otp_required",
                    risk_level="medium",
                    reason=", ".join(reasons),
                )
                self._record_risk_assessment(
                    conn,
                    user_id=row["id"],
                    login_event_id=login_event_id,
                    score=risk["score"],
                    decision=decision,
                    signals=risk["signals"],
                )
                return {
                    "status": "otp_required",
                    "message": "Risk checks require OTP verification before login is allowed.",
                    "challengeId": otp["challengeId"],
                    "otpCode": otp["otpCode"],
                    "riskScore": risk["score"],
                    "riskReasons": reasons,
                    "riskSignals": risk["signals"],
                }

            event_id = self._create_login_event(
                conn,
                user_id=row["id"],
                attempted_username=row["username"],
                device_id=device_id,
                location=location,
                outcome="blocked",
                risk_level="high",
                reason=", ".join(reasons),
            )
            self._record_risk_assessment(
                conn,
                user_id=row["id"],
                login_event_id=event_id,
                score=risk["score"],
                decision=decision,
                signals=risk["signals"],
            )
            conn.execute(
                """
                UPDATE users
                SET status = 'restricted', requires_password_reset = 1
                WHERE id = ?
                """,
                (row["id"],),
            )
            self._create_security_alert(
                conn,
                user_id=row["id"],
                login_event_id=event_id,
                alert_type="suspicious_login",
                severity="high",
                summary=f"Blocked login from {location} on {device_id}",
            )
            return {
                "status": "blocked",
                "message": "Login blocked as suspicious. Use the suspicious activity chatbot flow.",
                "riskScore": risk["score"],
                "riskReasons": reasons,
                "riskSignals": risk["signals"],
            }

    def verify_login_otp(self, challenge_id: int, otp_code: str) -> dict[str, Any]:
        with self.connect() as conn:
            challenge = conn.execute(
                "SELECT * FROM otp_challenges WHERE id = ?",
                (challenge_id,),
            ).fetchone()
            if not challenge:
                return {"status": "failed", "message": "OTP challenge not found."}
            user = conn.execute("SELECT * FROM users WHERE id = ?", (challenge["user_id"],)).fetchone()
            if not user:
                return {"status": "failed", "message": "Customer linked to OTP challenge not found."}

        verification = self.verify_otp(user["username"], otp_code)
        if not verification["ok"]:
            return {"status": "failed", "message": verification["message"]}

        approval = self.approve_new_device(
            user["username"],
            challenge["device_id"] or "new-device",
            challenge["location"] or user["home_city"],
        )
        return {"status": "verified", "message": approval["message"]}
