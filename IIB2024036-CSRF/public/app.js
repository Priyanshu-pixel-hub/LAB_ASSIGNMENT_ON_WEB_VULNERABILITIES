/**
 * public/app.js
 * 
 * Simple Client-Side Logic for Student Portal CSRF Demonstration
 */

let csrfToken = "";

document.addEventListener("DOMContentLoaded", () => {
  // Check if we are on the login page
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    initLogin();
    return;
  }

  // Otherwise, initialize the student profile page
  initProfilePage();
});

// ============================================================================
// 1. LOGIN PAGE LOGIC
// ============================================================================
function initLogin() {
  const form = document.getElementById("login-form");
  const errorAlert = document.getElementById("login-error");
  const autofillBtn = document.getElementById("btn-autofill");

  // Auto-fill test credentials button
  if (autofillBtn) {
    autofillBtn.addEventListener("click", () => {
      document.getElementById("username").value = "student";
      document.getElementById("password").value = "Password123!";
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorAlert.style.display = "none";

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        window.location.href = "/dashboard";
      } else {
        errorAlert.textContent = data.message || "Invalid credentials.";
        errorAlert.style.display = "block";
      }
    } catch (err) {
      errorAlert.textContent = "Error connecting to server.";
      errorAlert.style.display = "block";
    }
  });
}

// ============================================================================
// 2. PROFILE PAGE & CSRF DEMONSTRATION LOGIC
// ============================================================================
async function initProfilePage() {
  // Load initial student details & session mode
  await loadProfile();
  await loadCsrfToken();

  // Button: Log Out
  document.getElementById("btn-logout").addEventListener("click", handleLogout);

  // Button: Reset Email Baseline
  document.getElementById("btn-reset-email").addEventListener("click", handleResetEmail);

  // Mode Switcher Buttons (if present)
  const btnVuln = document.getElementById("btn-mode-vulnerable");
  const btnSec = document.getElementById("btn-mode-secure");
  if (btnVuln) btnVuln.addEventListener("click", () => setMode("vulnerable"));
  if (btnSec) btnSec.addEventListener("click", () => setMode("secure"));

  // Legitimate Form: POST with CSRF Token
  document.getElementById("legitimate-update-form").addEventListener("submit", handleLegitimateUpdate);
}

// Load student profile from server
async function loadProfile() {
  try {
    const res = await fetch("/api/auth/me");
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    const data = await res.json();
    if (data.success) {
      document.getElementById("student-name").textContent = data.user.name;
      document.getElementById("student-id").textContent = data.user.id;
      document.getElementById("current-email").textContent = data.user.email;
      updateModeUI(data.labMode);
    }
  } catch (err) {
    console.error("Failed to load profile:", err);
  }
}

// Fetch session CSRF token
async function loadCsrfToken() {
  try {
    const res = await fetch("/api/secure/csrf-token");
    const data = await res.json();
    if (data.success) {
      csrfToken = data.csrfToken;
      const el = document.getElementById("active-csrf-token");
      if (el) el.textContent = csrfToken;
    }
  } catch (err) {
    console.error("Failed to fetch CSRF token:", err);
  }
}

// Switch educational mode between 'vulnerable' and 'secure'
async function setMode(mode) {
  try {
    const res = await fetch("/api/lab/mode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode })
    });
    const data = await res.json();
    if (data.success) {
      updateModeUI(data.labMode);
      hideResult("demo-result");
    }
  } catch (err) {
    console.error("Failed to set mode:", err);
  }
}

// Update UI based on active mode
function updateModeUI(mode) {
  const btnVuln = document.getElementById("btn-mode-vulnerable");
  const btnSec = document.getElementById("btn-mode-secure");
  const statusAlert = document.getElementById("mode-status-alert");
  const statusText = document.getElementById("mode-status-text");

  if (mode === "vulnerable") {
    if (btnVuln) btnVuln.className = "mode-btn active-vulnerable";
    if (btnSec) btnSec.className = "mode-btn";
    if (statusAlert) statusAlert.className = "alert alert-danger";
    if (statusText) statusText.textContent = "VULNERABLE MODE (State-changing GET allowed; no CSRF token verified)";
  } else {
    if (btnVuln) btnVuln.className = "mode-btn";
    if (btnSec) btnSec.className = "mode-btn active-secure";
    if (statusAlert) statusAlert.className = "alert alert-success";
    if (statusText) statusText.textContent = "SECURE MODE (State-changing GET rejected with 405; mutations require POST + CSRF token)";
  }
}

// Action: Trigger the forged GET attack
async function runGetExploit() {
  const attackEmail = "attacker@evil.com";
  const resultBox = document.getElementById("demo-result");

  try {
    const res = await fetch(`/api/vulnerable/change-email?email=${encodeURIComponent(attackEmail)}`);
    const data = await res.json();

    if (res.ok && data.success) {
      // Vulnerable demonstration succeeded
      document.getElementById("current-email").textContent = data.details.updatedEmail;
      resultBox.className = "alert alert-danger";
      resultBox.innerHTML = `
        <strong>🚨 VULNERABILITY EXPLOITED!</strong><br>
        Email was changed to <code>${data.details.updatedEmail}</code> via an un-tokenized HTTP GET request.<br>
        <em>Reason: The browser sent the student's session cookie automatically. The server did not verify user intent.</em>
      `;
      resultBox.style.display = "block";
    } else {
      // Secure demonstration blocked the exploit
      resultBox.className = "alert alert-success";
      resultBox.innerHTML = `
        <strong>🛡️ EXPLOIT BLOCKED (HTTP ${res.status})</strong><br>
        ${data.message || data.error}<br>
        <em>The email remains unchanged at: <strong>${document.getElementById("current-email").textContent}</strong></em>
      `;
      resultBox.style.display = "block";
    }
  } catch (err) {
    resultBox.className = "alert alert-danger";
    resultBox.textContent = "Request error: " + err.message;
    resultBox.style.display = "block";
  }
}

// Action: Test GET against the secure endpoint (shows 405 Method Not Allowed)
async function testSecureGet() {
  const resultBox = document.getElementById("demo-result");

  try {
    const res = await fetch("/api/secure/change-email?email=test@test.com");
    const data = await res.json();

    resultBox.className = "alert alert-info";
    resultBox.innerHTML = `
      <strong>HTTP ${res.status} ${res.statusText}</strong><br>
      ${data.message}<br>
      <em>Rule: In RFC 7231, GET requests must only retrieve data, not change state.</em>
    `;
    resultBox.style.display = "block";
  } catch (err) {
    resultBox.className = "alert alert-danger";
    resultBox.textContent = "Request error: " + err.message;
    resultBox.style.display = "block";
  }
}

// Action: Legitimate POST email update with CSRF token
async function handleLegitimateUpdate(e) {
  e.preventDefault();
  const newEmail = document.getElementById("new-email").value.trim();
  const resultBox = document.getElementById("legitimate-result");

  try {
    const res = await fetch("/api/secure/change-email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-csrf-token": csrfToken
      },
      body: JSON.stringify({ email: newEmail })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      document.getElementById("current-email").textContent = data.currentEmail;
      document.getElementById("new-email").value = "";
      if (data.newCsrfToken) {
        csrfToken = data.newCsrfToken;
        document.getElementById("active-csrf-token").textContent = csrfToken;
      }
      resultBox.className = "alert alert-success";
      resultBox.innerHTML = `
        <strong>✅ Success:</strong> Email updated legitimately to <code>${data.currentEmail}</code> using POST and a valid CSRF token.
      `;
      resultBox.style.display = "block";
    } else {
      resultBox.className = "alert alert-danger";
      resultBox.textContent = "Error: " + (data.message || data.error);
      resultBox.style.display = "block";
    }
  } catch (err) {
    resultBox.className = "alert alert-danger";
    resultBox.textContent = "Request error: " + err.message;
    resultBox.style.display = "block";
  }
}

// Action: Reset email baseline
async function handleResetEmail() {
  try {
    const res = await fetch("/api/lab/reset", { method: "POST" });
    const data = await res.json();
    if (data.success) {
      document.getElementById("current-email").textContent = data.student.email;
      hideResult("demo-result");
      hideResult("legitimate-result");
    }
  } catch (err) {
    console.error("Reset failed:", err);
  }
}

// Action: Logout
async function handleLogout() {
  await fetch("/api/auth/logout", { method: "POST" });
  window.location.href = "/login";
}

function hideResult(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = "none";
}
