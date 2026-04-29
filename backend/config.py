from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def load_env_file() -> None:
    env_path = ROOT_DIR / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(slots=True)
class Settings:
    app_name: str
    host: str
    port: int
    openai_api_key: str
    openai_model: str
    db_path: Path
    system_prompt: str


def get_settings() -> Settings:
    load_env_file()
    db_path = os.getenv("APP_DB_PATH", str(ROOT_DIR / "login_agent.db"))
    return Settings(
        app_name="AI Login Assistance Agent",
        host=os.getenv("APP_HOST", "127.0.0.1"),
        port=int(os.getenv("APP_PORT", "8000")),
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-5-mini"),
        db_path=Path(db_path),
        system_prompt=(
            "You are a login assistance AI agent. Help users with login support "
            "through secure, step-by-step conversation. Use tools whenever account data, "
            "OTP validation, password reset, account unlock, device approval, login risk, "
            "or suspicious activity actions are needed. Never invent account state. "
            "If a tool reports failure or asks for verification, explain it clearly and "
            "ask for the exact next piece of information needed. "
            "Use the workflow-status tool to stay aligned with the current recovery stage "
            "when the conversation becomes long or the user changes direction. "
            "Use customer-memory tools when the user mentions lasting preferences or when "
            "a remembered detail can improve support continuity. "
            "When a user provides a 6-digit OTP or says they are entering the OTP, use the "
            "latest OTP from the current chat session instead of guessing the account. "
            "Use only the available tools. Do not offer email delivery or unsupported channels "
            "unless a tool explicitly supports them. "
            "This project is a demo environment. Do not reveal OTP codes in the chat reply. "
            "When an OTP is generated, tell the user it is valid for 5 minutes and instruct them "
            "to retrieve the code from the OTP utility page."
        ),
    )
