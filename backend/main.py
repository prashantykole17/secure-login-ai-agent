from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.agent import BankingSupportAgent
from backend.config import ROOT_DIR, get_settings
from backend.repository import BankingRepository
from backend.schemas import BankingOtpLookupRequest, ChatRequest, HumanCheckRequest, LoginSimulationRequest, MobileOtpRequest, VerifyMobileOtpRequest, VerifyOtpRequest


settings = get_settings()
repository = BankingRepository(str(settings.db_path))
repository.init_db()
agent = BankingSupportAgent(settings, repository)

app = FastAPI(title=settings.app_name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = ROOT_DIR / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


def _require_human_verified(session_id: int) -> None:
    if repository.is_human_verified(session_id):
        return
    raise HTTPException(
        status_code=403,
        detail={
            "message": "Human verification is required before using this feature.",
            "humanCheck": repository.get_human_check(session_id),
        },
    )


def _get_verified_utility_session(session_token: str | None) -> dict:
    session_data = repository.get_or_create_session(session_token)
    if repository.is_human_verified(session_data["id"]):
        return session_data

    fallback_session = repository.get_latest_human_verified_session()
    if fallback_session:
        return fallback_session

    raise HTTPException(
        status_code=403,
        detail={
            "message": "Human verification is required before using this feature.",
            "humanCheck": repository.get_human_check(session_data["id"]),
        },
    )


@app.get("/")
def root() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/otp-utility")
def otp_utility() -> FileResponse:
    return FileResponse(static_dir / "otp_utility.html")


@app.get("/data-snapshot")
def data_snapshot() -> FileResponse:
    return FileResponse(static_dir / "data_snapshot.html")


@app.get("/api/bootstrap")
def bootstrap(session: str | None = None) -> dict:
    session_data = repository.get_or_create_session(session)
    return {
        "sessionToken": session_data["sessionToken"],
        "messages": repository.get_session_messages(session_data["id"]),
        "dashboard": repository.get_dashboard_data(),
        "workflow": repository.get_workflow_status(session_data["id"]),
        "humanCheck": repository.get_human_check(session_data["id"]),
        "aiConfigured": bool(settings.openai_api_key),
        "model": settings.openai_model,
    }


@app.post("/api/human-check/verify")
def verify_human_check(payload: HumanCheckRequest) -> dict:
    session_data = repository.get_or_create_session(payload.sessionToken)
    result = repository.verify_human_check(session_data["id"], payload.answer, payload.honeypot)
    result["sessionToken"] = session_data["sessionToken"]
    result["humanCheck"] = repository.get_human_check(session_data["id"])
    return result


@app.post("/api/chat")
def chat(payload: ChatRequest) -> dict:
    session_data = repository.get_or_create_session(payload.sessionToken)
    _require_human_verified(session_data["id"])
    repository.append_chat_message(session_data["id"], "user", payload.message)

    if not settings.openai_api_key:
        reply = (
            "The OpenAI model is not configured yet. Add OPENAI_API_KEY in the .env file "
            "and restart the app so the LangGraph assistant can answer."
        )
    else:
        try:
            reply = agent.generate_reply(session_data["id"], payload.message)
        except Exception as exc:  # pragma: no cover - runtime integration guard
            raise HTTPException(status_code=500, detail=f"AI agent failed: {exc}") from exc

    if not isinstance(reply, str):
        reply = str(reply)

    repository.append_chat_message(session_data["id"], "assistant", reply)
    return {
        "sessionToken": session_data["sessionToken"],
        "messages": repository.get_session_messages(session_data["id"]),
        "dashboard": repository.get_dashboard_data(),
        "workflow": repository.get_workflow_status(session_data["id"]),
        "humanCheck": repository.get_human_check(session_data["id"]),
        "aiConfigured": bool(settings.openai_api_key),
        "model": settings.openai_model,
    }


@app.get("/api/dashboard")
def dashboard() -> dict:
    return repository.get_dashboard_data()


@app.post("/api/simulate-login")
def simulate_login(payload: LoginSimulationRequest) -> dict:
    result = repository.simulate_login(
        payload.username,
        payload.password,
        payload.deviceId,
        payload.location,
    )
    result["dashboard"] = repository.get_dashboard_data()
    return result


@app.post("/api/verify-login-otp")
def verify_login_otp(payload: VerifyOtpRequest) -> dict:
    result = repository.verify_login_otp(payload.challengeId, payload.otpCode)
    result["dashboard"] = repository.get_dashboard_data()
    return result


@app.post("/api/reset-demo")
def reset_demo() -> dict:
    repository.init_db(reset=True)
    session_data = repository.create_session()
    return {
        "sessionToken": session_data["sessionToken"],
        "messages": repository.get_session_messages(session_data["id"]),
        "dashboard": repository.get_dashboard_data(),
        "workflow": repository.get_workflow_status(session_data["id"]),
        "humanCheck": repository.get_human_check(session_data["id"]),
        "aiConfigured": bool(settings.openai_api_key),
        "model": settings.openai_model,
    }


@app.post("/api/clear-memory")
def clear_memory() -> dict:
    result = repository.clear_agent_memory()
    result["dashboard"] = repository.get_dashboard_data()
    return result


@app.post("/api/utility/mobile-otp")
def generate_mobile_otp(payload: MobileOtpRequest) -> dict:
    result = repository.generate_mobile_demo_otp(payload.phoneNumber, payload.purpose)
    result["history"] = repository.get_recent_mobile_demo_otps()
    return result


@app.get("/api/utility/mobile-otp")
def recent_mobile_otps() -> dict:
    return {"history": repository.get_recent_mobile_demo_otps()}


@app.post("/api/utility/mobile-otp/verify")
def verify_mobile_otp(payload: VerifyMobileOtpRequest) -> dict:
    result = repository.verify_mobile_demo_otp(payload.phoneNumber, payload.otpCode)
    result["history"] = repository.get_recent_mobile_demo_otps()
    return result


@app.post("/api/utility/banking-chat-otp")
def lookup_banking_chat_otp(payload: BankingOtpLookupRequest) -> dict:
    return repository.get_latest_banking_chat_otp_by_phone(payload.phoneNumber)
