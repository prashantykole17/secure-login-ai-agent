const otpForm = document.getElementById("mobile-otp-form");
const verifyForm = document.getElementById("mobile-otp-verify-form");
const otpResult = document.getElementById("mobile-otp-result");
const otpHistory = document.getElementById("mobile-otp-history");
const chatOtpForm = document.getElementById("chat-otp-form");
const chatOtpResult = document.getElementById("chat-otp-result");

let otpHistoryItems = [];

function escapeHtml(text) {
  return String(text ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function formatRemaining(seconds) {
  if (seconds <= 0) {
    return "Expired";
  }
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs}s`;
}

function renderHistory(items) {
  otpHistoryItems = items.map((item) => ({ ...item }));
  if (!items.length) {
    otpHistory.innerHTML = '<div class="result-card muted">No OTPs generated yet.</div>';
    return;
  }

  otpHistory.innerHTML = items
    .map(
      (item) => `
        <article class="mini-card">
          <strong>${escapeHtml(item.phoneNumber)}</strong>
          <div>OTP: ${escapeHtml(item.otpCode)}</div>
          <div>Purpose: ${escapeHtml(item.purpose)}</div>
          <div>Status: ${escapeHtml(item.status)}</div>
          <div>Expires: ${escapeHtml(item.expiresAt)}</div>
          <div>Remaining: ${escapeHtml(formatRemaining(item.remainingSeconds))}</div>
        </article>
      `
    )
    .join("");
}

function tickHistoryCountdown() {
  if (!otpHistoryItems.length) {
    return;
  }

  otpHistoryItems = otpHistoryItems.map((item) => {
    const nextSeconds = Math.max(0, Number(item.remainingSeconds || 0) - 1);
    const nextStatus =
      item.status === "generated" && nextSeconds === 0 ? "expired" : item.status;
    return {
      ...item,
      remainingSeconds: nextSeconds,
      status: nextStatus,
    };
  });

  renderHistory(otpHistoryItems);
}

async function parseJsonResponse(response) {
  const data = await response.json();
  if (!response.ok) {
    throw data;
  }
  return data;
}

async function loadHistory() {
  const response = await fetch("/api/utility/mobile-otp");
  const data = await response.json();
  renderHistory(data.history || []);
}

otpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const phoneNumber = document.getElementById("mobile-number").value.trim();
  const purpose = document.getElementById("otp-purpose").value.trim() || "demo_mobile_otp";

  const response = await fetch("/api/utility/mobile-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ phoneNumber, purpose }),
  });

  try {
    const data = await parseJsonResponse(response);
    otpResult.className = "result-card allowed";
    otpResult.innerHTML = `
      OTP generated for <strong>${escapeHtml(data.phoneNumber)}</strong><br /><br />
      Generated OTP: <strong>${escapeHtml(data.otpCode)}</strong><br />
      Purpose: ${escapeHtml(data.purpose)}<br />
      Valid for: <strong>5 minutes</strong><br />
      Expires at: ${escapeHtml(data.expiresAt)}
    `;
    document.getElementById("verify-mobile-number").value = data.phoneNumber;
    renderHistory(data.history || []);
  } catch (error) {
    otpResult.className = "result-card blocked";
    otpResult.textContent = error.message || "OTP generation failed.";
  }
});

verifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const phoneNumber = document.getElementById("verify-mobile-number").value.trim();
  const otpCode = document.getElementById("verify-otp-code").value.trim();

  const response = await fetch("/api/utility/mobile-otp/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ phoneNumber, otpCode }),
  });

  try {
    const data = await parseJsonResponse(response);
    otpResult.className = `result-card ${data.ok ? "allowed" : "blocked"}`;
    otpResult.innerHTML = data.ok
      ? `OTP verified successfully for <strong>${escapeHtml(data.phoneNumber)}</strong>.`
      : escapeHtml(data.message);
    renderHistory(data.history || []);
  } catch (error) {
    otpResult.className = "result-card blocked";
    otpResult.textContent = error.message || "OTP verification failed.";
  }
});

chatOtpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const phoneNumber = document.getElementById("chat-otp-phone").value.trim();

  const response = await fetch("/api/utility/chat-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ phoneNumber }),
  });

  try {
    const data = await parseJsonResponse(response);
    chatOtpResult.className = "result-card allowed";
    chatOtpResult.innerHTML = `
      Chat OTP found for <strong>${escapeHtml(data.fullName)}</strong><br /><br />
      Username: ${escapeHtml(data.username)}<br />
      Mobile: ${escapeHtml(data.phoneNumber)}<br />
      OTP: <strong>${escapeHtml(data.otpCode)}</strong><br />
      Purpose: ${escapeHtml(data.purpose)}<br />
      Status: ${escapeHtml(data.status)}<br />
      Remaining: ${escapeHtml(formatRemaining(data.remainingSeconds))}<br />
      Expires at: ${escapeHtml(data.expiresAt)}
    `;
  } catch (error) {
    chatOtpResult.className = "result-card blocked";
    chatOtpResult.textContent = error.message || "Lookup failed.";
  }
});

loadHistory();
setInterval(tickHistoryCountdown, 1000);
