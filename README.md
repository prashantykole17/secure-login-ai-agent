# AI Login Assistance Agent

This project is a proper local full-stack application with:

- `FastAPI` backend APIs
- `LangGraph` workflow orchestration
- `OpenAI` conversational model integration
- `SQLite` database for accounts, chat history, OTP records, login events, and security alerts
- chatbot-style frontend UI
- OTP generation and validation inside the app
- all requested banking login support use cases

## Architecture

### Backend

- `backend/main.py` -> FastAPI app and API routes
- `backend/agent.py` -> LangGraph agent using an OpenAI chat model
- `backend/tools.py` -> agent tools for account lookup, OTP, unlock, password reset, device approval, and alerts
- `backend/repository.py` -> SQLite schema, seed data, and banking business logic
- `backend/schemas.py` -> request models
- `backend/config.py` -> environment and app settings

### Frontend

- `static/index.html`
- `static/app.js`
- `static/styles.css`

## Implemented use cases

- Forgot password with OTP validation
- Account unlock after secure verification
- New device login approval
- Suspicious login review and account securing
- OTP challenge for risky login attempts
- Failed login tracking and automatic account locking
- Demo dashboard for users, login events, and security alerts

## OpenAI and LangGraph

The chatbot is implemented with `LangGraph` and `langchain-openai`.

- The model is configured in `.env`
- Default model: `gpt-5-mini`
- The LangGraph agent uses tools to safely access customer records and perform banking actions

This follows current documentation patterns:

- OpenAI recommends the `Responses API` for new agent-like applications: [Migrate to the Responses API](https://platform.openai.com/docs/guides/migrate-to-responses)
- LangChain's `ChatOpenAI` supports `use_responses_api=True` and can be used with LangGraph-managed conversations: [ChatOpenAI integration](https://docs.langchain.com/oss/python/integrations/chat/openai)
- LangGraph's `StateGraph` pattern is the standard graph-building approach: [LangGraph quickstart](https://docs.langchain.com/oss/python/langgraph/quickstart)

## Setup

### 1. Copy environment file

Create `.env` from `.env.example` and add your OpenAI API key:

```text
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-5-mini
APP_HOST=127.0.0.1
APP_PORT=8000
APP_DB_PATH=banking_agent.db
```

### 2. Install dependencies

Windows Command Prompt:

```bat
setup.bat
```

PowerShell:

```powershell
.\setup.ps1
```

Manual install:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Run the app

Command Prompt:

```bat
run_app.bat
```

PowerShell:

```powershell
.\run_app.ps1
```

Or directly:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open:

```text
http://127.0.0.1:8000
```

## Demo users

- `asha.m` / `Secure@123` -> trusted profile
- `ravi.k` / `Bank@789` -> locked account case
- `priya.n` / `Reset@456` -> password reset case
- `daniel.l` / `Vault#321` -> suspicious activity case

## API routes

- `GET /api/bootstrap`
- `POST /api/chat`
- `GET /api/dashboard`
- `POST /api/simulate-login`
- `POST /api/verify-login-otp`
- `POST /api/reset-demo`

## Important note

The chatbot requires a valid `OPENAI_API_KEY` to produce conversational AI responses through LangGraph. Without that key, the app still loads, the database still works, and the login simulator still runs, but the chatbot will prompt you to configure OpenAI.

For SQLite, there are no host/user/password details. The database is just a file path:

- `APP_DB_PATH=banking_agent.db`

If you want a custom location, set an absolute path in `.env`, for example:

```text
APP_DB_PATH=C:\Users\YourName\Projects\banking-agent\banking_agent.db
```
