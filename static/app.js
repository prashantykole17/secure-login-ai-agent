const state = {
  sessionToken: null,
  pendingChallengeId: null,
  humanVerified: false,
};

const messagesEl = document.getElementById("messages");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const simulatorForm = document.getElementById("simulator-form");
const simResult = document.getElementById("sim-result");
const otpForm = document.getElementById("otp-form");
const otpInput = document.getElementById("otp-input");
const usersList = document.getElementById("users-list");
const eventsList = document.getElementById("events-list");
const alertsList = document.getElementById("alerts-list");
const workflowsList = document.getElementById("workflows-list");
const memoriesList = document.getElementById("memories-list");
const riskList = document.getElementById("risk-list");
const metricsStrip = document.getElementById("metrics-strip");
const clearMemoryBtn = document.getElementById("clear-memory");
const resetDemoBtn = document.getElementById("reset-demo");
const aiStatus = document.getElementById("ai-status");
const modelCaption = document.getElementById("model-caption");
const humanGate = document.getElementById("human-gate");
const humanQuestion = document.getElementById("human-question");
const humanCheckForm = document.getElementById("human-check-form");
const humanAnswer = document.getElementById("human-answer");
const humanHoneypot = document.getElementById("human-honeypot");
const humanResult = document.getElementById("human-result");
const SESSION_STORAGE_KEY = "loginAgentSessionToken";

function saveSessionToken(sessionToken) {
  if (!sessionToken) {
    return;
  }
  localStorage.setItem(SESSION_STORAGE_KEY, sessionToken);
}

function loadStoredSessionToken() {
  return localStorage.getItem(SESSION_STORAGE_KEY);
}

function escapeHtml(text) {
  return String(text ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function renderHumanCheck(humanCheck) {
  const required = Boolean(humanCheck?.required);
  state.humanVerified = !required;
  humanGate.classList.toggle("hidden", !required);
  if (required) {
    humanQuestion.textContent = humanCheck.question || "Solve the challenge to continue.";
  }
}

function renderMessages(messages) {
  messagesEl.innerHTML = messages
    .map(
      (message) =>
        `<article class="message ${message.role}">${escapeHtml(message.content)}</article>`
    )
    .join("");
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function renderAiStatus(aiConfigured, model) {
  aiStatus.textContent = aiConfigured ? `AI Ready | ${model}` : "AI Key Missing";
  modelCaption.textContent = aiConfigured
    ? `The chatbot is using LangGraph with the OpenAI model ${model}. The simulator below now includes richer workflow, memory, and risk telemetry.`
    : "Add OPENAI_API_KEY to .env to enable the LangGraph + OpenAI chatbot. The simulator and dashboards still work without the API key.";
}

function buildUserCard(user) {
  return `
    <article class="mini-card">
      <strong>${escapeHtml(user.fullName)}</strong>
      <div>Username: ${escapeHtml(user.username)}</div>
      <div>Password: ${escapeHtml(user.password)}</div>
      <div>Status: ${escapeHtml(user.status)}</div>
      <div>Trusted: ${escapeHtml((user.trustedDevices || []).join(", ") || "-")}</div>
    </article>
  `;
}

function buildEventCard(event) {
  return `
    <article class="mini-card">
      <strong>${escapeHtml(event.username || "unknown-user")}</strong>
      <div>${escapeHtml(event.outcome)} | ${escapeHtml(event.riskLevel)}</div>
      <div>${escapeHtml(event.reason)}</div>
      <div>${escapeHtml(event.deviceId || "-")} from ${escapeHtml(event.location || "-")}</div>
    </article>
  `;
}

function buildAlertCard(alert) {
  return `
    <article class="mini-card">
      <strong>${escapeHtml(String(alert.severity || "").toUpperCase())}</strong>
      <div>${escapeHtml(alert.summary)}</div>
      <div>Status: ${escapeHtml(alert.status)}</div>
    </article>
  `;
}

function buildWorkflowCard(workflow) {
  return `
    <article class="mini-card">
      <strong>${escapeHtml(workflow.workflowType)}</strong>
      <div>Status: ${escapeHtml(workflow.status)}</div>
      <div>Step: ${escapeHtml(workflow.currentStep || "-")}</div>
      <div>Customer: ${escapeHtml(workflow.username || workflow.fullName || "-")}</div>
      <div>Tool: ${escapeHtml(workflow.lastTool || "-")}</div>
    </article>
  `;
}

function buildMemoryCard(memory) {
  return `
    <article class="mini-card">
      <strong>${escapeHtml(memory.username || memory.fullName || "-")}</strong>
      <div>${escapeHtml(memory.key)}: ${escapeHtml(memory.value)}</div>
      <div>Source: ${escapeHtml(memory.source)}</div>
    </article>
  `;
}

function buildRiskCard(item) {
  return `
    <article class="mini-card">
      <strong>${escapeHtml(item.username || "unknown-user")}</strong>
      <div>Score: ${escapeHtml(item.score)} | ${escapeHtml(item.decision)}</div>
      <div>Signals: ${escapeHtml((item.signals || []).join(", ") || "-")}</div>
    </article>
  `;
}

function renderMetrics(metrics) {
  if (!metricsStrip) {
    return;
  }
  const safeMetrics = metrics || {
    activeWorkflows: 0,
    openAlerts: 0,
    pendingOtps: 0,
    blockedRiskCases: 0,
  };

  metricsStrip.innerHTML = `
    <article class="metric-card">
      <div>Active Workflows</div>
      <strong>${escapeHtml(safeMetrics.activeWorkflows)}</strong>
    </article>
    <article class="metric-card">
      <div>Open Alerts</div>
      <strong>${escapeHtml(safeMetrics.openAlerts)}</strong>
    </article>
    <article class="metric-card">
      <div>Pending OTPs</div>
      <strong>${escapeHtml(safeMetrics.pendingOtps)}</strong>
    </article>
    <article class="metric-card">
      <div>Blocked Risk Cases</div>
      <strong>${escapeHtml(safeMetrics.blockedRiskCases)}</strong>
    </article>
  `;
}

function renderList(target, items, builder, emptyLabel) {
  if (!target) {
    return;
  }
  target.innerHTML = items && items.length
    ? items.map(builder).join("")
    : `<article class="mini-card"><strong>${escapeHtml(emptyLabel)}</strong></article>`;
}

function renderDashboard(dashboard) {
  renderList(usersList, dashboard.users || [], buildUserCard, "No users");
  renderList(eventsList, dashboard.events || [], buildEventCard, "No login events");
  renderList(alertsList, dashboard.alerts || [], buildAlertCard, "No alerts");
  renderList(workflowsList, dashboard.workflows || [], buildWorkflowCard, "No workflows");
  renderList(memoriesList, dashboard.memories || [], buildMemoryCard, "No memory saved");
  renderList(riskList, dashboard.riskAssessments || [], buildRiskCard, "No risk assessments");
  renderMetrics(dashboard.metrics);
}

function renderSimulatorRisk(data) {
  if (!data.riskReasons && !data.riskSignals) {
    return;
  }
  const reasons = (data.riskReasons || []).join(", ") || "-";
  const signals = (data.riskSignals || []).join(", ") || "-";
  simResult.innerHTML += `
    <br /><br />Risk score: <strong>${escapeHtml(data.riskScore ?? "-")}</strong>
    <br />Reasons: ${escapeHtml(reasons)}
    <br />Signals: ${escapeHtml(signals)}
  `;
}

async function parseJsonResponse(response) {
  const data = await response.json();
  if (!response.ok) {
    throw data;
  }
  return data;
}

async function loadBootstrap(sessionToken = null) {
  const activeSessionToken = sessionToken || loadStoredSessionToken();
  const url = activeSessionToken
    ? `/api/bootstrap?session=${encodeURIComponent(activeSessionToken)}`
    : "/api/bootstrap";
  const response = await fetch(url);
  const data = await response.json();
  state.sessionToken = data.sessionToken;
  saveSessionToken(data.sessionToken);
  renderMessages(data.messages);
  renderDashboard(data.dashboard);
  renderAiStatus(data.aiConfigured, data.model);
  renderHumanCheck(data.humanCheck);
}

async function sendChat({ message = "" }) {
  const response = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      sessionToken: state.sessionToken,
      message,
    }),
  });

  try {
    const data = await parseJsonResponse(response);
    state.sessionToken = data.sessionToken;
    saveSessionToken(data.sessionToken);
    renderMessages(data.messages);
    renderDashboard(data.dashboard);
    renderAiStatus(data.aiConfigured, data.model);
    renderHumanCheck(data.humanCheck);
  } catch (error) {
    if (error?.detail?.humanCheck) {
      renderHumanCheck(error.detail.humanCheck);
      humanResult.className = "result-card blocked";
      humanResult.textContent = error.detail.message;
      return;
    }
    throw error;
  }
}

async function refreshDashboard() {
  const response = await fetch("/api/dashboard");
  const data = await response.json();
  renderDashboard(data);
}

humanCheckForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/api/human-check/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      sessionToken: state.sessionToken,
      answer: humanAnswer.value.trim(),
      honeypot: humanHoneypot.value,
    }),
  });
  const data = await response.json();
  state.sessionToken = data.sessionToken;
  saveSessionToken(data.sessionToken);
  humanResult.className = `result-card ${data.ok ? "allowed" : "blocked"}`;
  humanResult.textContent = data.message;
  humanAnswer.value = "";
  humanHoneypot.value = "";
  renderHumanCheck(data.humanCheck);
});

chatForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.humanVerified) {
    humanResult.className = "result-card blocked";
    humanResult.textContent = "Complete the human check before sending chat messages.";
    return;
  }
  const message = chatInput.value.trim();
  if (!message) {
    return;
  }
  chatInput.value = "";
  await sendChat({ message });
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest(".quick-prompt");
  if (!button) {
    return;
  }
  if (!state.humanVerified) {
    humanResult.className = "result-card blocked";
    humanResult.textContent = "Complete the human check before using quick prompts.";
    return;
  }
  await sendChat({ message: button.dataset.prompt });
});

simulatorForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    username: document.getElementById("sim-username").value.trim(),
    password: document.getElementById("sim-password").value.trim(),
    deviceId: document.getElementById("sim-device").value.trim(),
    location: document.getElementById("sim-location").value.trim(),
  };

  const response = await fetch("/api/simulate-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  simResult.className = `result-card ${data.status}`;
  simResult.innerHTML = escapeHtml(data.message);
  state.pendingChallengeId = data.challengeId || null;
  if (data.otpCode) {
    simResult.innerHTML += `<br /><br />Generated demo OTP: <strong>${escapeHtml(
      data.otpCode
    )}</strong>`;
  }
  renderSimulatorRisk(data);
  otpForm.classList.toggle("hidden", !state.pendingChallengeId);
  renderDashboard(data.dashboard);
});

otpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.pendingChallengeId) {
    return;
  }

  const response = await fetch("/api/verify-login-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challengeId: state.pendingChallengeId,
      otpCode: otpInput.value.trim(),
    }),
  });
  const data = await response.json();
  simResult.className = `result-card ${data.status === "verified" ? "allowed" : "blocked"}`;
  simResult.textContent = data.message;
  otpInput.value = "";
  if (data.status === "verified") {
    state.pendingChallengeId = null;
    otpForm.classList.add("hidden");
  }
  renderDashboard(data.dashboard);
});

resetDemoBtn.addEventListener("click", async () => {
  const response = await fetch("/api/reset-demo", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const data = await response.json();
  state.sessionToken = data.sessionToken;
  saveSessionToken(data.sessionToken);
  state.pendingChallengeId = null;
  otpForm.classList.add("hidden");
  simResult.className = "result-card muted";
  simResult.textContent =
    "Demo data reset complete. Start a new chat flow or rerun the login simulator.";
  renderMessages(data.messages);
  renderDashboard(data.dashboard);
  renderAiStatus(data.aiConfigured, data.model);
  renderHumanCheck(data.humanCheck);
});

clearMemoryBtn.addEventListener("click", async () => {
  const response = await fetch("/api/clear-memory", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  const data = await response.json();
  simResult.className = "result-card muted";
  simResult.textContent = data.message;
  renderDashboard(data.dashboard);
});

loadBootstrap().then(refreshDashboard);
