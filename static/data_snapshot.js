const usersList = document.getElementById("users-list");
const eventsList = document.getElementById("events-list");
const alertsList = document.getElementById("alerts-list");
const workflowsList = document.getElementById("workflows-list");
const memoriesList = document.getElementById("memories-list");
const riskList = document.getElementById("risk-list");
const metricsStrip = document.getElementById("metrics-strip");
const refreshButton = document.getElementById("snapshot-refresh");
const snapshotStatus = document.getElementById("snapshot-status");

function escapeHtml(text) {
  return String(text ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
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

function renderList(target, items, builder, emptyLabel) {
  target.innerHTML = items && items.length
    ? items.map(builder).join("")
    : `<article class="mini-card"><strong>${escapeHtml(emptyLabel)}</strong></article>`;
}

function renderMetrics(metrics) {
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

function renderDashboard(dashboard) {
  renderList(usersList, dashboard.users || [], buildUserCard, "No users");
  renderList(eventsList, dashboard.events || [], buildEventCard, "No login events");
  renderList(alertsList, dashboard.alerts || [], buildAlertCard, "No alerts");
  renderList(workflowsList, dashboard.workflows || [], buildWorkflowCard, "No workflows");
  renderList(memoriesList, dashboard.memories || [], buildMemoryCard, "No memory saved");
  renderList(riskList, dashboard.riskAssessments || [], buildRiskCard, "No risk assessments");
  renderMetrics(dashboard.metrics);
}

async function loadSnapshot() {
  snapshotStatus.textContent = "Refreshing";
  refreshButton.disabled = true;

  try {
    const response = await fetch("/api/dashboard");
    const data = await response.json();
    renderDashboard(data);
    snapshotStatus.textContent = "Live";
  } catch (error) {
    snapshotStatus.textContent = "Unavailable";
  } finally {
    refreshButton.disabled = false;
  }
}

refreshButton.addEventListener("click", loadSnapshot);
loadSnapshot();
