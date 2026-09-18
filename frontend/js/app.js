/**
 * Global App State, Router, Offline Listener, and API Client
 */

const AppState = {
  token: localStorage.getItem("cyber_token") || null,
  user: null,
  currentTab: "user-portal",
  isOffline: false,
  fingerprint: null,
  geo: null
};

// Real-Time Sound & Synthesizer State
let soundEnabled = true;
let audioCtx = null;

function toggleSoundAlerts() {
  soundEnabled = !soundEnabled;
  const label = document.getElementById("sound-toggle-label");
  const btn = document.getElementById("btn-sound-toggle");
  if (label) label.textContent = soundEnabled ? "🔊 Sound: ON" : "🔇 Sound: OFF";
  if (btn) {
    btn.classList.toggle("btn-primary", soundEnabled);
    btn.classList.toggle("btn-secondary", !soundEnabled);
  }
  showToast(`Security Sound Sirens ${soundEnabled ? 'Enabled' : 'Muted'}`, "info");
}

function playSecurityAlertSound() {
  if (!soundEnabled) return;
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    if (!audioCtx) audioCtx = new AudioContext();
    if (audioCtx.state === "suspended") {
      audioCtx.resume();
    }
    const now = audioCtx.currentTime;
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();

    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(880, now); // A5 siren
    osc.frequency.exponentialRampToValueAtTime(440, now + 0.15);
    osc.frequency.exponentialRampToValueAtTime(880, now + 0.3);
    osc.frequency.exponentialRampToValueAtTime(440, now + 0.45);

    gain.gain.setValueAtTime(0.2, now);
    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.5);

    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start(now);
    osc.stop(now + 0.5);
  } catch (e) {
    console.log("Audio synthesis notice:", e);
  }
}

// Global Alert Banner Controller
function showSecurityAlertBanner(alert) {
  const banner = document.getElementById("emergency-alert-banner");
  const title = document.getElementById("banner-alert-title");
  const desc = document.getElementById("banner-alert-desc");
  if (!banner) return;

  const isFailedPassword = alert.type === "SUSPICIOUS_FAILED_LOGIN" || alert.type === "REPEATED_FAILED_LOGINS" || alert.type === "BRUTE_FORCE_LOCKOUT";

  if (title) {
    title.textContent = isFailedPassword 
      ? "⚠️ SECURITY WARNING: INCORRECT PASSWORD ATTEMPT DETECTED" 
      : "🚨 SECURITY ALERT: SUSPICIOUS SIGN-IN BLOCKED";
  }
  if (desc) {
    const reason = alert.reason || "Someone tried to sign into your account with an incorrect password.";
    const origin = alert.origin || "Unknown Location";
    const ip = alert.ip || "Unknown IP";
    const dev = alert.device || "Unknown Device";
    desc.innerHTML = `<strong>${reason}</strong> &bull; Device: <span style="color: #fff;">${dev}</span> &bull; Location: <span style="color: #fff;">${origin}</span> (<code>${ip}</code>). Access was blocked.`;
  }

  banner.style.display = "block";
  playSecurityAlertSound();
}

function dismissAlertBanner() {
  const banner = document.getElementById("emergency-alert-banner");
  if (banner) banner.style.display = "none";
}

// Practice Guide Section Switcher
function switchPracticeGuideSection(secId) {
  const sections = ["demo", "buttons", "ml", "aws", "viva"];
  sections.forEach(s => {
    const secEl = document.getElementById(`pg-sec-${s}`);
    const btnEl = document.getElementById(`pg-tab-btn-${s}`);
    if (secEl) secEl.style.display = (s === secId) ? "block" : "none";
    if (btnEl) btnEl.classList.toggle("active", s === secId);
  });
}

// Global API Helper with Correlation ID
async function apiFetch(endpoint, options = {}) {
  const correlationId = "req_" + Math.random().toString(36).substring(2, 10);
  const headers = {
    "Content-Type": "application/json",
    "X-Request-Id": correlationId,
    ...(options.headers || {})
  };

  if (AppState.token) {
    headers["Authorization"] = `Bearer ${AppState.token}`;
  }

  try {
    const res = await fetch(endpoint, { ...options, headers });
    
    // Handle 503 Maintenance
    if (res.status === 503) {
      openModal("modal-maintenance");
      throw new Error("System under maintenance");
    }

    // Handle 401 Session Expired / Revoked
    if (res.status === 401 && AppState.token) {
      const isPrimaryDev = (AppState.user && AppState.user.is_primary_device !== false && AppState.user.device_tier !== "SECONDARY") || localStorage.getItem("is_primary_device") === "true";
      if (isPrimaryDev) {
        console.warn("[Session] Primary device session preserved against transient 401.");
        return { ok: false, status: 401, error: "Unauthorized" };
      }
      handleSessionExpired();
      throw new Error("Session expired");
    }

    // Handle 403 Access Blocked / Account Locked
    if (res.status === 403) {
      const data = await res.json().catch(() => ({}));
      const errCode = data.detail?.error || (typeof data.detail === "object" ? data.detail?.error : null);
      if (errCode === "ACCOUNT_LOCKED") {
        const isPrimaryDev = (AppState.user && AppState.user.is_primary_device !== false && AppState.user.device_tier !== "SECONDARY") || localStorage.getItem("is_primary_device") === "true";
        if (isPrimaryDev) {
          // Primary device is immune to token wipe: keeps session alive and shows unfreeze HUD
          if (AppState.user) {
            AppState.user.status = "LOCKED";
            AppState.user.account_is_frozen = true;
          }
          showToast("Account locked by incident response. Your Primary Device remains authenticated to unfreeze access.", "warning");
          if (typeof renderUserPortal === "function") renderUserPortal();
          return { ok: false, status: 403, data };
        }
        AppState.token = null;
        AppState.user = null;
        localStorage.removeItem("cyber_token");
        openModal("modal-account-locked");
        if (typeof renderUserPortal === "function") renderUserPortal();
      } else {
        showToast(data.detail?.message || (typeof data.detail === "string" ? data.detail : "Access blocked by security policy"), "error");
      }
      return { ok: false, status: 403, data };
    }

    const data = await res.json().catch(() => ({}));
    
    if (res.status === 500) {
      showToast("Internal Server Error (500). Please try again later.", "error");
    }
    
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    if (!navigator.onLine) {
      showToast("Network connection lost. You are currently offline.", "error");
    }
    return { ok: false, status: 0, error: err.message };
  }
}

// Router & Tab Switching
function switchTab(tabId) {
  // Super Admin Route Protection: CMS dashboard only accessible to Super Admin logins
  if (tabId === "cms-dashboard" && typeof isSuperAdmin === "function" && !isSuperAdmin(AppState.user)) {
    showToast("Access Restricted: Super Admin privileges required.", "error");
    if (AppState.currentTab !== "user-portal") {
      switchTab("user-portal");
    }
    return;
  }

  AppState.currentTab = tabId;
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  let viewFound = false;
  document.querySelectorAll(".tab-view").forEach(view => {
    const isTarget = view.id === tabId || view.id === `view-${tabId}` || (tabId === "user-portal" && view.id === "view-user-portal");
    if (isTarget) viewFound = true;
    view.classList.toggle("active", isTarget);
  });
  
  if (!viewFound) {
    document.querySelectorAll(".tab-view").forEach(v => v.classList.remove("active"));
    const view404 = document.getElementById("view-404");
    if (view404) view404.classList.add("active");
  }

  // Trigger sub-view initializations
  if (tabId === "attack-studio" && typeof initAttackSimulator === "function") {
    initAttackSimulator();
  } else if (tabId === "soc-dashboard" && typeof initSocDashboard === "function") {
    initSocDashboard();
  } else if (tabId === "cloudwatch-view" && typeof initCloudWatchView === "function") {
    initCloudWatchView();
  } else if (tabId === "cms-dashboard" && typeof cmsLoadData === "function") {
    cmsLoadData();
  }
}

// Toast Notifications
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  // Format message cleanly if object or array
  let cleanMsg = message;
  if (typeof message === "object" && message !== null) {
    if (Array.isArray(message)) {
      cleanMsg = message.map(item => (typeof item === "object" && item !== null) ? (item.msg || item.detail || JSON.stringify(item)) : String(item)).join("; ");
    } else if (message.message) {
      cleanMsg = message.message;
    } else if (message.detail) {
      cleanMsg = typeof message.detail === "string" ? message.detail : (Array.isArray(message.detail) ? message.detail.map(d => d.msg || JSON.stringify(d)).join("; ") : JSON.stringify(message.detail));
    } else {
      cleanMsg = JSON.stringify(message);
    }
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.setAttribute("role", "status");
  toast.innerHTML = `
    <span class="toast-icon">${type === "success" ? "✓" : type === "error" ? "⚠" : "ℹ"}</span>
    <span>${cleanMsg}</span>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(50px)";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Modal Controls & Accessibility
function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) {
    el.classList.add("active");
    // Trap focus inside modal
    const firstInput = el.querySelector("input:not([type='hidden']), button.btn-primary, button.modal-close-btn");
    if (firstInput) {
      setTimeout(() => firstInput.focus(), 50);
    }
  }
}
window.openModal = openModal;

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.remove("active");
  if (modalId === "modal-mfa-challenge" && window.mfaPollInterval) {
    clearInterval(window.mfaPollInterval);
    window.mfaPollInterval = null;
  }
}
window.closeModal = closeModal;

// Universal HTML Escaper for Security & Safe Rendering
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
window.escapeHtml = escapeHtml;

// Global Controller for Amazon SNS & Dispatched Security Mailbox Modal
async function openDispatchedMailbox() {
  openModal("modal-dispatched-notifications");
  if (typeof window.fetchDispatchedNotifications === "function") {
    await window.fetchDispatchedNotifications();
  }
}
window.openDispatchedMailbox = openDispatchedMailbox;

// Central Password Modal Controller
function switchPasswordMode(mode) {
  const formAuth = document.getElementById("form-change-password-auth");
  const formToken = document.getElementById("form-reset-password-token");
  const btnAuth = document.getElementById("tab-pw-auth");
  const btnToken = document.getElementById("tab-pw-token");

  if (mode === "auth") {
    if (formAuth) formAuth.style.display = "block";
    if (formToken) formToken.style.display = "none";
    if (btnAuth) btnAuth.classList.add("active");
    if (btnToken) btnToken.classList.remove("active");
  } else {
    if (formAuth) formAuth.style.display = "none";
    if (formToken) formToken.style.display = "block";
    if (btnAuth) btnAuth.classList.remove("active");
    if (btnToken) btnToken.classList.add("active");
  }
}
window.switchPasswordMode = switchPasswordMode;

function openPasswordModal(preferredMode) {
  const isAuth = !!(AppState && AppState.user && AppState.token);
  const mode = preferredMode || (isAuth ? "auth" : "token");
  switchPasswordMode(mode);
  openModal("modal-reset-password");
}
window.openPasswordModal = openPasswordModal;

async function handleChangePasswordAuth(e) {
  if (e && e.preventDefault) e.preventDefault();
  const currentPassword = document.getElementById("change-curr-password")?.value || "";
  const newPassword = document.getElementById("change-new-password")?.value || "";

  if (!currentPassword) {
    showToast("Please enter your current master password.", "warning");
    return;
  }
  if (!newPassword || newPassword.length < 8) {
    showToast("New password must be at least 8 characters with mixed cases & numbers.", "warning");
    return;
  }

  if (!AppState.token) {
    showToast("Please sign in or use the Single-Use Token tab.", "warning");
    switchPasswordMode("token");
    return;
  }

  showToast("Updating master credentials...", "info");
  const res = await apiFetch("/api/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
  });

  if (res.ok) {
    closeModal("modal-reset-password");
    const currInput = document.getElementById("change-curr-password");
    const newInput = document.getElementById("change-new-password");
    if (currInput) currInput.value = "";
    if (newInput) newInput.value = "";
    showToast("Master password successfully updated! Remote sessions revoked.", "success");
  } else {
    const errorMsg = res.data?.detail || res.error || "Failed to update password. Check your current password.";
    showToast(errorMsg, "error");
  }
}
window.handleChangePasswordAuth = handleChangePasswordAuth;

// Global Escape Key Listener for Modals
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.querySelectorAll(".cyber-modal-overlay.active").forEach(modal => {
      // Keep unclosable critical notices locked
      if (modal.id === "modal-maintenance") return;
      modal.classList.remove("active");
    });
  }
});

// Global Backdrop Click Listener for Modals
document.addEventListener("click", (e) => {
  if (e.target && e.target.classList.contains("cyber-modal-overlay")) {
    if (e.target.id === "modal-maintenance") return;
    e.target.classList.remove("active");
  }
});

function handleSessionExpired() {
  AppState.token = null;
  AppState.user = null;
  localStorage.removeItem("cyber_token");
  openModal("modal-session-expired");
  renderUserPortal();
}

// Offline State Detector
window.addEventListener("online", () => {
  AppState.isOffline = false;
  document.getElementById("offline-banner").style.display = "none";
  showToast("Network connection restored.", "success");
});

window.addEventListener("offline", () => {
  fetch("/api/cloudwatch/metrics").then(() => {
    AppState.isOffline = false;
    const banner = document.getElementById("offline-banner");
    if (banner) banner.style.display = "none";
  }).catch(() => {
    AppState.isOffline = true;
    const banner = document.getElementById("offline-banner");
    if (banner) banner.style.display = "block";
    showToast("You are currently offline. Actions may fail.", "warning");
  });
});

// Quick Interactive Demo Helpers (Anyone can test in 1-click)
async function demoSimulateFailedLogin() {
  showToast("Simulating remote attacker guessing wrong password in Edge...", "info");
  await apiFetch("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({
      email: (AppState.user?.email || "demo@awssecurity.io"),
      password: "WrongPassword123!",
      geo: { lat: 40.7128, lon: -74.0060, city: "New York", country: "US" },
      fingerprint: {
        browser: "Microsoft Edge",
        browser_id: "bid_remote_edge_attacker",
        os: "Windows NT 10.0",
        screen_resolution: "1920x1080",
        canvas_hash: "canvas_diff_edge_demo"
      }
    })
  });
  if (typeof loadUserAlerts === "function") {
    setTimeout(() => loadUserAlerts(true), 400);
  }
}

async function demoSimulateTokyoAttack() {
  showToast("Launching Tokyo Impossible Travel Scenario (8,500 km/h flight speed)...", "warning");
  const res = await apiFetch("/api/security/simulate-attack", {
    method: "POST",
    body: JSON.stringify({
      attack_type: "IMPOSSIBLE_TRAVEL",
      target_email: (AppState.user?.email || "demo@awssecurity.io")
    })
  });
  if (res.ok) {
    showToast(`🚨 Tokyo Scenario Blocked! Risk Score: ${res.data?.risk_score}/100. Siren active.`, "error");
    if (typeof loadUserAlerts === "function") {
      setTimeout(() => loadUserAlerts(true), 400);
    }
  }
}

// Password Visibility Toggle
function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    btn.textContent = "🙈";
    btn.title = "Hide password";
  } else {
    input.type = "password";
    btn.textContent = "👁️";
    btn.title = "Show password";
  }
}
window.togglePasswordVisibility = togglePasswordVisibility;

// Maintenance Mode Real-Time Controller & Global State Sync
let lastMaintenanceState = null;

function applyMaintenanceState(isMaint) {
  lastMaintenanceState = isMaint;
  const banner = document.getElementById("maintenance-banner");
  const syncIndicator = document.getElementById("sync-status-indicator");
  const bannerAdminBtn = document.getElementById("btn-banner-disable-maint");
  const modalAdminBtn = document.getElementById("btn-modal-maint-admin-unlock");
  const cmsMaintBtn = document.getElementById("cms-btn-maintenance");

  const isRootAdmin = !!(AppState.user && (
    AppState.user.is_root_admin || 
    AppState.user.role === "ROOT_ADMIN" || 
    AppState.user.email === "demo@awssecurity.io"
  ));

  if (banner) {
    banner.style.display = isMaint ? "block" : "none";
  }

  if (bannerAdminBtn) {
    bannerAdminBtn.style.display = (isMaint && isRootAdmin) ? "inline-flex" : "none";
  }

  if (modalAdminBtn) {
    modalAdminBtn.style.display = (isMaint && isRootAdmin) ? "inline-flex" : "none";
  }

  if (syncIndicator) {
    if (isMaint) {
      syncIndicator.textContent = "🛠️ SERVICE UNDER MAINTENANCE";
      syncIndicator.style.color = "var(--accent-amber)";
    } else {
      syncIndicator.textContent = "LIVE SYNC: 2s";
      syncIndicator.style.color = "";
    }
  }

  if (cmsMaintBtn) {
    if (isMaint) {
      cmsMaintBtn.innerText = "Disable";
      cmsMaintBtn.classList.replace("btn-secondary", "btn-danger");
    } else {
      cmsMaintBtn.innerText = "Enable";
      cmsMaintBtn.classList.replace("btn-danger", "btn-secondary");
    }
  }

  if (isMaint) {
    if (!isRootAdmin) {
      openModal("modal-maintenance");
    }
  } else {
    closeModal("modal-maintenance");
  }
}
window.applyMaintenanceState = applyMaintenanceState;

async function syncSystemStatus() {
  try {
    const res = await fetch("/api/system/status");
    if (res.ok) {
      const data = await res.json();
      const isMaint = !!data.maintenance_mode;
      if (lastMaintenanceState !== isMaint) {
        applyMaintenanceState(isMaint);
      }
    }
  } catch (err) {
    // Suppress network errors during background sync
  }
}
window.syncSystemStatus = syncSystemStatus;

// App Initialization
document.addEventListener("DOMContentLoaded", async () => {
  // Initialize light/dark theme preference
  if (typeof initTheme === "function") {
    initTheme();
  }

  // Initialize Auth UI state (hide logout & admin by default)
  if (typeof updateAuthUI === "function") {
    updateAuthUI();
  }

  // Navigation clicks (attached immediately for zero delay)
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // Extract fingerprint immediately
  if (typeof generateBrowserFingerprint === "function") {
    generateBrowserFingerprint().then(fp => {
      AppState.fingerprint = fp;
      const fpBadge = document.getElementById("client-fp-display");
      if (fpBadge) fpBadge.textContent = `${fp.os} • ${fp.screen_resolution}`;
    }).catch(e => console.warn("Fingerprint init notice:", e));
  }

  // Extract geolocation non-blocking in background
  if (typeof getClientGeolocation === "function") {
    getClientGeolocation().then(geo => {
      AppState.geo = geo;
    }).catch(e => console.warn("Geolocation init notice:", e));
  }

  // Check login state
  if (AppState.token && typeof checkCurrentUser === "function") {
    await checkCurrentUser();
  } else if (typeof renderUserPortal === "function") {
    renderUserPortal();
  }

  // Initial maintenance check & start continuous real-time 2.5s synchronization
  await syncSystemStatus();
  setInterval(() => {
    if (!document.hidden) {
      syncSystemStatus();
    }
  }, 2500);
});

// ============================================================================
// SUPER ADMIN & PRIVILEGE CONFIGURATION
// Add Super Admin emails and roles below:
// ============================================================================
const SUPER_ADMIN_CONFIG = {
  // Super Admin email list (case-insensitive)
  emails: [
    "likhithadm@gmail.com",
    "superadmin@awssecurity.io",
    ...(JSON.parse(localStorage.getItem("super_admin_emails") || "[]"))
  ],
  roles: ["SUPER_ADMIN"],
  passwords: [] // Kept confidential under admin
};
window.SUPER_ADMIN_CONFIG = SUPER_ADMIN_CONFIG;

function isSuperAdmin(user = AppState.user) {
  if (!user) return false;
  // Check explicit super admin flag
  if (user.is_super_admin === true) return true;
  const userEmail = (user.email || "").toLowerCase().trim();
  if (userEmail && SUPER_ADMIN_CONFIG.emails.some(e => e.toLowerCase().trim() === userEmail)) {
    return true;
  }
  if (user.role && SUPER_ADMIN_CONFIG.roles.includes(String(user.role).toUpperCase().trim())) {
    return true;
  }
  return false;
}
window.isSuperAdmin = isSuperAdmin;

// Helper to easily register/change super admin email at runtime or from console:
window.setSuperAdminEmail = function(email) {
  if (!email) return;
  const trimmed = email.toLowerCase().trim();
  if (!SUPER_ADMIN_CONFIG.emails.includes(trimmed)) {
    SUPER_ADMIN_CONFIG.emails.push(trimmed);
  }
  const saved = JSON.parse(localStorage.getItem("super_admin_emails") || "[]");
  if (!saved.includes(trimmed)) {
    saved.push(trimmed);
    localStorage.setItem("super_admin_emails", JSON.stringify(saved));
  }
  updateAuthUI();
  console.log(`[SuperAdmin] Registered super admin email: ${trimmed}`);
  showToast(`Super Admin email registered: ${trimmed}`, "success");
};

// Central Auth UI updater for Logout button and Admin privileges
function updateAuthUI() {
  const isLoggedIn = !!(AppState.token && AppState.user);
  const isSuper = isSuperAdmin(AppState.user);

  // 1. Logout button: ONLY show when user logs in
  const navLogoutItem = document.getElementById("nav-item-logout");
  const navLogoutBtn = document.getElementById("btn-prominent-logout");
  if (navLogoutItem) {
    navLogoutItem.style.display = isLoggedIn ? "inline-flex" : "none";
  }
  if (navLogoutBtn) {
    navLogoutBtn.style.display = isLoggedIn ? "inline-flex" : "none";
  }

  // 2. Admin Privileges / CMS tab: ONLY show for Super Admin
  const navCmsItem = document.getElementById("nav-item-cms");
  const navCmsBtn = document.querySelector('[data-tab="cms-dashboard"]');
  if (navCmsItem) {
    navCmsItem.style.display = isSuper ? "inline-flex" : "none";
  }
  if (navCmsBtn && navCmsBtn.parentElement && navCmsBtn.parentElement !== navCmsItem) {
    navCmsBtn.parentElement.style.display = isSuper ? "inline-flex" : "none";
  }

  // Maintenance mode admin overrides
  const bannerAdminBtn = document.getElementById("btn-banner-disable-maint");
  const modalAdminBtn = document.getElementById("btn-modal-maint-admin-unlock");
  if (bannerAdminBtn) bannerAdminBtn.style.display = (isSuper && lastMaintenanceState) ? "inline-flex" : "none";
  if (modalAdminBtn) modalAdminBtn.style.display = (isSuper && lastMaintenanceState) ? "inline-flex" : "none";

  // If user is currently on CMS tab without super admin rights, redirect to portal
  if (AppState.currentTab === "cms-dashboard" && !isSuper) {
    switchTab("user-portal");
  }
}
window.updateAuthUI = updateAuthUI;
window.checkAdminUI = updateAuthUI;

// ============================================================================
// UI ENHANCEMENTS (Theme, Mobile, Accessibility, Shortcuts)
// ============================================================================

function applyTheme(theme) {
  const isLight = (theme === "light");
  const html = document.documentElement;
  const body = document.body;

  if (isLight) {
    html.setAttribute("data-theme", "light");
    if (body) {
      body.setAttribute("data-theme", "light");
      body.classList.remove("theme-dark");
      body.classList.add("theme-light");
    }
  } else {
    html.removeAttribute("data-theme");
    if (body) {
      body.removeAttribute("data-theme");
      body.classList.remove("theme-light");
      body.classList.add("theme-dark");
    }
  }

  // Update theme button icon & label
  const themeIcon = document.getElementById("theme-icon");
  const themeLabel = document.getElementById("theme-label");
  const themeBtn = document.getElementById("btn-theme-toggle");
  if (themeIcon) themeIcon.textContent = isLight ? "☀️" : "🌙";
  if (themeLabel) themeLabel.textContent = isLight ? "Light" : "Dark";
  if (themeBtn) themeBtn.title = isLight ? "Switch to Dark Mode" : "Switch to Light Mode";

  localStorage.setItem("theme", isLight ? "light" : "dark");
}
window.applyTheme = applyTheme;

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || (document.body && document.body.getAttribute("data-theme")) || (document.body && document.body.classList.contains("theme-light") ? "light" : "dark");
  const nextTheme = (current === "light") ? "dark" : "light";
  applyTheme(nextTheme);
  showToast(`Theme changed to ${nextTheme === "light" ? "Light" : "Dark"} Mode`, "info");
}
window.toggleTheme = toggleTheme;

function initTheme() {
  const saved = localStorage.getItem("theme");
  if (saved) {
    applyTheme(saved);
  } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
    applyTheme("light");
  } else {
    applyTheme("dark");
  }
}
window.initTheme = initTheme;
// Immediately execute theme initialization to prevent flash
initTheme();

// Global Keyboard Shortcuts
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.querySelectorAll(".cyber-modal-overlay.active").forEach(m => m.classList.remove("active"));
  }
  if ((e.ctrlKey || e.metaKey) && e.key === "k") {
    e.preventDefault();
    showToast("Global Search feature coming soon...", "info");
  }
});

// Scroll listener for back-to-top
window.addEventListener("scroll", () => {
  const btn = document.getElementById("back-to-top");
  if (btn) {
    if (window.scrollY > 300) btn.style.display = "flex";
    else btn.style.display = "none";
  }
});

// Initialize features on load
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    if (!localStorage.getItem("cookies_accepted")) {
      const banner = document.getElementById("cookie-banner");
      if (banner) banner.classList.add("visible");
    }
  }, 1000);
  
  setupPasswordToggles();
});

// Cookie banner dismissal
function acceptCookies() {
  try {
    localStorage.setItem("cookies_accepted", "true");
  } catch (e) {
    console.warn("Storage access issue:", e);
  }
  const banner = document.getElementById("cookie-banner");
  if (banner) {
    banner.classList.remove("visible");
    banner.style.display = "none";
  }
}
window.acceptCookies = acceptCookies;


// ============================================================================
// COPY TO CLIPBOARD HELPER
// ============================================================================
function copyToClipboard(text, btnElement) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      const originalText = btnElement.innerHTML;
      btnElement.innerHTML = "? Copied!";
      setTimeout(() => btnElement.innerHTML = originalText, 2000);
    }).catch(err => {
      console.error("Failed to copy:", err);
      showToast("Failed to copy to clipboard", "error");
    });
  } else {
    // Fallback
    const textArea = document.createElement("textarea");
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    try {
      document.execCommand("copy");
      const originalText = btnElement.innerHTML;
      btnElement.innerHTML = "? Copied!";
      setTimeout(() => btnElement.innerHTML = originalText, 2000);
    } catch (err) {
      showToast("Failed to copy to clipboard", "error");
    }
    document.body.removeChild(textArea);
  }
}


// ============================================================================
// SKELETON LOADERS & EMPTY STATES HELPER
// ============================================================================
function renderSkeletonRows(containerId, count=3) {
  const container = document.getElementById(containerId);
  if (!container) return;
  let html = "";
  for(let i=0; i<count; i++){
    html += `<tr style="background:transparent;"><td colspan="10"><div class="skeleton" style="height:40px; width:100%;"></div></td></tr>`;
  }
  container.innerHTML = html;
}

function renderEmptyState(containerId, message) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = `
    <tr><td colspan="10">
      <div style="padding: 2rem; text-align: center; color: var(--text-dim);">
        <span class="material-symbols-outlined" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;">inventory_2</span>
        <div>${message}</div>
      </div>
    </td></tr>
  `;
}


// ============================================================================
// EMAIL VERIFICATION FLOW
// ============================================================================
async function submitEmailVerification(e) {
  e.preventDefault();
  const code = document.getElementById("verify-code-input").value;
  const email = document.getElementById("verify-email-hidden").value;
  
  if (!code || !email) return;
  
  showToast("Verifying email...", "info");
  const res = await apiFetch("/api/auth/verify-email", {
    method: "POST",
    body: JSON.stringify({ email: email, code: code })
  });
  
  if (res.ok) {
    showToast(res.data.message, "success");
    closeModal("modal-email-verification");
    document.getElementById("form-email-verify").reset();
    // Re-render user portal or switch to login
    switchTab("user-portal");
  } else {
    showToast(res.data?.detail || "Invalid verification code.", "error");
  }
}

