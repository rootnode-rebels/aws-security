/**
 * Legitimate User Security Portal Controller
 * Manages Login, Register, Password Strength, Sessions, Alerts, MFA, and Account Deletion.
 */

let userPollingInterval = null;
let lastSeenAlertIds = new Set();
let isFirstAlertsLoad = true;
let isFetchingSessions = false;
let isFetchingAlerts = false;
let lastSessionsSignature = "";
let lastAlertsSignature = "";

async function checkCurrentUser() {
  const res = await apiFetch("/api/auth/me");
  if (res.ok && res.data) {
    AppState.user = res.data;
    const isPrimary = (res.data.is_primary_device !== false && res.data.device_tier !== "SECONDARY");
    localStorage.setItem("is_primary_device", isPrimary ? "true" : "false");
    renderUserPortal();
    loadUserSessions(true);
    loadUserAlerts();
    
    // Launch background worker, real-time SSE stream, and notification permissions
    startBackgroundTimerWorker();
    connectSecurityStream();
    checkNotificationPermission();

    if (!userPollingInterval) {
      // High-frequency live synchronization (every 2 seconds) - runs in background!
      userPollingInterval = setInterval(() => {
        if (AppState.token) {
          loadUserSessions();
          loadUserAlerts();
        }
      }, 2000);
    }
  } else {
    const wasPrimary = localStorage.getItem("is_primary_device") === "true";
    if (!wasPrimary) {
      AppState.token = null;
      localStorage.removeItem("cyber_token");
      if (userPollingInterval) {
        clearInterval(userPollingInterval);
        userPollingInterval = null;
      }
      if (timerWorker) {
        timerWorker.postMessage("stop");
        timerWorker = null;
      }
      if (sseConnection) {
        sseConnection.close();
        sseConnection = null;
      }
    }
    renderUserPortal();
  }
}

function renderUserPortal() {
  const authContainer = document.getElementById("portal-auth-container");
  const dashboardContainer = document.getElementById("portal-dashboard-container");

  if (!AppState.user) {
    if (authContainer) authContainer.style.display = "block";
    if (dashboardContainer) dashboardContainer.style.display = "none";
  } else {
    if (authContainer) authContainer.style.display = "none";
    if (dashboardContainer) dashboardContainer.style.display = "block";

    // Populate user profile info
    const nameEl = document.getElementById("user-display-name");
    const emailEl = document.getElementById("user-display-email");
    const statusEl = document.getElementById("user-display-status");
    const lastLoginEl = document.getElementById("user-last-login");
    const tierBadge = document.getElementById("user-device-tier-badge");
    const secNotice = document.getElementById("secondary-device-notice");

    if (nameEl) nameEl.textContent = AppState.user.full_name;
    if (emailEl) emailEl.textContent = AppState.user.email;
    
    const isPrimary = (AppState.user.is_primary_device !== false && AppState.user.device_tier !== "SECONDARY");
    const isFrozen = (AppState.user.status === "LOCKED" || AppState.user.account_is_frozen === true);

    if (statusEl) {
      statusEl.textContent = isFrozen ? "LOCKED (FROZEN)" : AppState.user.status;
      statusEl.className = `badge ${!isFrozen && AppState.user.status === 'ACTIVE' ? 'badge-low' : 'badge-high'}`;
    }
    if (lastLoginEl && AppState.user.last_login) {
      const city = AppState.user.last_login.geo?.city || "New York";
      const dev = AppState.user.last_login.device || "Desktop";
      lastLoginEl.textContent = `${city} (${dev})`;
    }

    const unfreezeBanner = document.getElementById("primary-unfreeze-banner");
    if (unfreezeBanner) {
      unfreezeBanner.style.display = (isPrimary && isFrozen) ? "flex" : "none";
    }

    if (tierBadge) {
      if (isPrimary) {
        tierBadge.innerHTML = '<span class="pulse-dot pulse-dot-emerald"></span>PRIMARY DEVICE';
        tierBadge.className = "capsule-badge capsule-emerald";
        tierBadge.style.cssText = "";
      } else {
        tierBadge.innerHTML = '<span class="pulse-dot pulse-dot-amber"></span>SECONDARY DEVICE';
        tierBadge.className = "capsule-badge capsule-amber";
        tierBadge.style.cssText = "";
      }
    }

    const roleBadge = document.getElementById("user-role-badge");
    const isRootAdmin = AppState.user.is_root_admin || AppState.user.role === "ROOT_ADMIN" || AppState.user.email === "demo@awssecurity.io";
    if (roleBadge) {
      if (isRootAdmin) {
        roleBadge.style.display = "inline-flex";
        roleBadge.innerHTML = '<span class="pulse-dot pulse-dot-emerald"></span>👑 ROOT ADMIN';
      } else {
        roleBadge.style.display = "none";
      }
    }

    // Populate trust center hardware card if rendered
    const tcDevName = document.getElementById("trust-center-device-name");
    const tcFp = document.getElementById("trust-center-fp");
    const btnManageDevice = document.getElementById("btn-manage-device");
    if (tcDevName) {
      if (isPrimary) {
        const devLabel = AppState.user.primary_device?.label || `${AppState.fingerprint?.browser || 'Browser'} on ${AppState.fingerprint?.os || 'Desktop'} (Main Device)`;
        tcDevName.textContent = devLabel;
      } else {
        // Zero data about primary device hardware or label leaked to secondary devices!
        tcDevName.textContent = "Primary Security Device (Protected)";
      }
    }
    if (tcFp) {
      if (isPrimary) {
        const rawHash = AppState.fingerprint?.canvas_hash || AppState.user.primary_device?.canvas_hash || "SECURE";
        tcFp.textContent = `#DEV-${rawHash.substring(0, 8).toUpperCase()}`;
      } else {
        tcFp.textContent = "#DEV-PROTECTED";
      }
    }
    if (btnManageDevice) {
      if (isPrimary) {
        btnManageDevice.onclick = () => openModal('modal-primary-device-prompt');
        btnManageDevice.title = "Manage Main Device";
        btnManageDevice.innerHTML = '<span class="material-symbols-outlined" style="font-size: 0.95rem;">tune</span><span>Manage Device</span>';
      } else {
        btnManageDevice.onclick = () => openModal('modal-set-primary-confirm');
        btnManageDevice.title = "Transfer Main Device status to this computer (Requires Master Password)";
        btnManageDevice.innerHTML = '<span class="material-symbols-outlined" style="font-size: 0.95rem;">key</span><span>Make Main Device</span>';
      }
    }

    if (secNotice) {
      secNotice.style.display = isPrimary ? "none" : "flex";
    }

    const btnKillOthersHeader = document.getElementById("btn-kill-others-header");
    const btnFreeze = document.getElementById("btn-portal-freeze");
    if (btnKillOthersHeader) {
      btnKillOthersHeader.style.display = isPrimary ? "inline-flex" : "none";
    }
    if (btnFreeze) {
      // User requirement: Secondary devices must have ZERO option to terminate or freeze
      btnFreeze.style.display = isPrimary ? "inline-flex" : "none";
      if (isPrimary) {
        btnFreeze.title = "Sign out all devices immediately";
        btnFreeze.disabled = false;
        btnFreeze.style.opacity = "1";
        btnFreeze.style.cursor = "pointer";
      }
    }

    const panicBox = document.getElementById("panic-purge-box");
    if (panicBox) {
      if (isPrimary) {
        panicBox.innerHTML = `
          <div class="panic-purge-header">
            <span class="panic-title">
              <span class="material-symbols-outlined" style="font-size: 1.1rem;">gpp_bad</span>
              Emergency Sign Out Everywhere
            </span>
            <span class="pulse-dot pulse-dot-crimson"></span>
          </div>
          <p class="panic-desc">
            If you think someone else has your password or is in your account, sign out of all other devices now.
          </p>
          <button class="btn btn-danger btn-sm glow-crimson panic-btn" onclick="emergencyLockAccount()">
            <span class="material-symbols-outlined" style="font-size: 1rem;">lock_reset</span>
            <span>Sign Out All Other Devices</span>
          </button>
        `;
      } else {
        panicBox.innerHTML = `
          <div class="panic-purge-header">
            <span class="panic-title text-muted" style="display: flex; align-items: center; gap: 6px;">
              <span class="material-symbols-outlined" style="font-size: 1.1rem; color: var(--accent-amber);">lock</span>
              Controls Restricted to Main Device
            </span>
            <span class="capsule-badge capsule-amber" style="font-size: 0.65rem;">MAIN DEVICE ONLY</span>
          </div>
          <p class="panic-desc">
            Important security controls like signing out everywhere can only be done from your primary device.
          </p>
          <div style="font-size: 0.74rem; color: var(--text-muted); padding: 0.45rem 0.65rem; background: rgba(255,255,255,0.03); border-radius: 6px; border: 1px dashed rgba(255,255,255,0.08); text-align: center;">
            🛡️ Secondary device: viewing in read-only mode.
          </div>
        `;
      }
    }
  }
}

// Live Password Strength Evaluator
function checkPasswordStrength(password) {
  const bar = document.getElementById("pw-strength-bar");
  const label = document.getElementById("pw-strength-label");
  if (!bar || !label) return;

  if (!password) {
    bar.style.width = "0%";
    label.textContent = "Enter password";
    return;
  }

  let score = 0;
  if (password.length >= 8) score += 25;
  if (password.length >= 12) score += 15;
  if (/[A-Z]/.test(password)) score += 20;
  if (/[a-z]/.test(password)) score += 15;
  if (/[0-9]/.test(password)) score += 15;
  if (/[^A-Za-z0-9]/.test(password)) score += 10;

  bar.style.width = `${Math.min(100, score)}%`;

  if (score < 40) {
    bar.style.backgroundColor = "#ef4444";
    label.textContent = "Weak (min 8 chars, uppercase, number & symbol)";
    label.style.color = "#ef4444";
  } else if (score < 75) {
    bar.style.backgroundColor = "#f59e0b";
    label.textContent = "Moderate";
    label.style.color = "#f59e0b";
  } else {
    bar.style.backgroundColor = "#10b981";
    label.textContent = "Strong password";
    label.style.color = "#10b981";
  }
}

// Auth Tab Switcher
function switchAuthTab(mode) {
  const loginForm = document.getElementById("form-login");
  const regForm = document.getElementById("form-register");
  const btnLogin = document.getElementById("auth-tab-login");
  const btnReg = document.getElementById("auth-tab-register");

  if (mode === "login") {
    if (loginForm) loginForm.style.display = "block";
    if (regForm) regForm.style.display = "none";
    if (btnLogin) {
      btnLogin.classList.add("active");
      btnLogin.setAttribute("aria-selected", "true");
    }
    if (btnReg) {
      btnReg.classList.remove("active");
      btnReg.setAttribute("aria-selected", "false");
    }
  } else {
    if (loginForm) loginForm.style.display = "none";
    if (regForm) regForm.style.display = "block";
    if (btnLogin) {
      btnLogin.classList.remove("active");
      btnLogin.setAttribute("aria-selected", "false");
    }
    if (btnReg) {
      btnReg.classList.add("active");
      btnReg.setAttribute("aria-selected", "true");
    }
  }
}
window.switchAuthTab = switchAuthTab;
window.toggleAuthTab = switchAuthTab;

// Registration Handler
async function handleRegister(e) {
  e.preventDefault();
  const name = document.getElementById("reg-name").value.trim();
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;

  if (!AppState.fingerprint && typeof generateBrowserFingerprint === "function") {
    AppState.fingerprint = await generateBrowserFingerprint().catch(() => ({}));
  }

  const res = await apiFetch("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({
      email,
      full_name: name,
      password,
      fingerprint: AppState.fingerprint || {},
      geo: AppState.geo || { lat: 40.7128, lon: -74.0060, city: "New York", country: "US" }
    })
  });

  if (res.ok) {
    showToast("Account created as Root Admin! 👑 Please sign in.", "success");
    // Switch to login tab
    switchAuthTab("login");
    const loginEmail = document.getElementById("login-email");
    if (loginEmail) loginEmail.value = email;
    const loginPass = document.getElementById("login-password");
    if (loginPass) loginPass.focus();
  } else {
    let errorMsg = "Registration failed. Check inputs.";
    if (typeof res.data?.detail === "string") {
      errorMsg = res.data.detail;
    } else if (Array.isArray(res.data?.detail)) {
      errorMsg = res.data.detail.map(d => d.msg || JSON.stringify(d)).join("; ");
    } else if (res.data?.detail?.message) {
      errorMsg = res.data.detail.message;
    } else if (res.error) {
      errorMsg = res.error;
    }
    showToast(errorMsg, "error");
  }
}

// Demo Auto-fill Helper
function autoFillDemoUser() {
  const emailInput = document.getElementById("login-email");
  const passInput = document.getElementById("login-password");
  if (emailInput) emailInput.value = "demo@awssecurity.io";
  if (passInput) passInput.value = "AWSSecurity#2026";
  showToast("Demo user loaded: demo@awssecurity.io (Sachin)", "info");
}

// Login Handler
async function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;

  const payload = {
    email,
    password,
    fingerprint: AppState.fingerprint,
    geo: AppState.geo
  };

  const res = await apiFetch("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  if (res.ok) {
    if (res.data.status === "MFA_REQUIRED") {
      // Step-Up / Secondary Device MFA Challenge
      document.getElementById("mfa-email-hidden").value = email;
      document.getElementById("mfa-temp-token-hidden").value = res.data.temp_token;

      const codeInput = document.getElementById("mfa-code-input");
      if (codeInput) {
        codeInput.value = ""; // Empty: User must enter code received on Primary Device!
        setTimeout(() => codeInput.focus(), 100);
      }

      const targetDevEl = document.getElementById("mfa-target-device");
      if (targetDevEl) targetDevEl.textContent = res.data.target_primary_device || "Primary Security Portal";

      openModal("modal-mfa-challenge");
      showToast("Verification code dispatched to your Primary Device screen.", "warning");

      // Start automatic cross-device polling: if Primary Device clicks 'Approve Device', sign in automatically!
      if (window.mfaPollInterval) clearInterval(window.mfaPollInterval);
      window.mfaPollInterval = setInterval(async () => {
        try {
          const pollRes = await fetch(`/api/auth/mfa-poll/${res.data.temp_token}`);
          if (pollRes.ok) {
            const pollData = await pollRes.json();
            if (pollData.status === "APPROVED" && pollData.token) {
              clearInterval(window.mfaPollInterval);
              window.mfaPollInterval = null;
              closeModal("modal-mfa-challenge");
              AppState.token = pollData.token;
              localStorage.setItem("cyber_token", pollData.token);
              showToast("Approved by Primary Device! Welcome back.", "success");
              await checkCurrentUser();
            } else if (pollData.status === "EXPIRED") {
              clearInterval(window.mfaPollInterval);
              window.mfaPollInterval = null;
              closeModal("modal-mfa-challenge");
              showToast("Verification request expired or rejected.", "error");
            }
          }
        } catch (e) {
          // Ignore polling blips
        }
      }, 1500);
      return;
    }

    // Successful login
    AppState.token = res.data.token;
    localStorage.setItem("cyber_token", res.data.token);
    showToast(`Welcome back, ${res.data.user.full_name}!`, "success");

    if (res.data.prompt_primary_device) {
      const devNameEl = document.getElementById("pdp-device-name");
      const devLocEl = document.getElementById("pdp-device-location");
      const browser = AppState.fingerprint?.browser || "Browser";
      const os = AppState.fingerprint?.os || "Desktop";
      if (devNameEl) devNameEl.textContent = `${browser} on ${os}`;
      if (devLocEl) {
        const city = AppState.geo?.city || "Current Location";
        const country = AppState.geo?.country || "US";
        devLocEl.textContent = `${city}, ${country}`;
      }
      openModal("modal-primary-device-prompt");
    }

    await checkCurrentUser();
  } else {
    if (res.status === 403) {
      showToast("🚨 Sign-in blocked: Unusual or suspicious location detected.", "error");
      playSecurityAlertSound();
    } else {
      showToast(res.data?.detail || "Incorrect email or password. Please try again.", "error");
    }
  }
}

// Set / Confirm Primary Device Designation
async function confirmPrimaryDevice(isPrimary) {
  const browser = AppState.fingerprint?.browser || "Browser";
  const os = AppState.fingerprint?.os || "Desktop";
  const label = isPrimary 
    ? `Main Device (${browser} on ${os})`
    : `Secondary Device (${browser} on ${os})`;

  const res = await apiFetch("/api/auth/devices/set-primary", {
    method: "POST",
    body: JSON.stringify({
      is_primary: isPrimary,
      device_label: label
    })
  });

  closeModal("modal-primary-device-prompt");

  if (res.ok) {
    if (isPrimary) {
      showToast("🛡️ Saved as your main device!", "success");
    } else {
      showToast("📱 Saved as a secondary device.", "info");
    }
  } else {
    showToast(res.data?.detail || "Could not save device designation.", "error");
  }

  await checkCurrentUser();
}
window.confirmPrimaryDevice = confirmPrimaryDevice;

// MFA Verification Handler
async function handleVerifyMFA(e) {
  e.preventDefault();
  const email = document.getElementById("mfa-email-hidden").value;
  const tempToken = document.getElementById("mfa-temp-token-hidden").value;
  const code = document.getElementById("mfa-code-input").value.trim();

  const res = await apiFetch("/api/auth/verify-mfa", {
    method: "POST",
    body: JSON.stringify({ email, temp_token: tempToken, mfa_code: code })
  });

  if (res.ok) {
    if (window.mfaPollInterval) {
      clearInterval(window.mfaPollInterval);
      window.mfaPollInterval = null;
    }
    closeModal("modal-mfa-challenge");
    AppState.token = res.data.token;
    localStorage.setItem("cyber_token", res.data.token);
    showToast("Identity verified via code. Access granted!", "success");
    await checkCurrentUser();
  } else {
    showToast(res.data?.detail || "Invalid verification code. Please check your Primary Device.", "error");
  }
}
window.handleVerifyMFA = handleVerifyMFA;

// Approve or Deny Secondary Device from Primary Device
async function executeApproveSecondary(approved, specificToken = null) {
  let tempToken = specificToken;
  if (!tempToken || tempToken === "undefined" || tempToken === "null") {
    tempToken = document.getElementById("sec-approval-token-hidden")?.value || "LATEST";
  }

  const res = await apiFetch("/api/auth/devices/approve-secondary", {
    method: "POST",
    body: JSON.stringify({ temp_token: tempToken, approved: approved })
  });

  closeModal("modal-secondary-device-approval");
  stopTitlePulse();

  if (res.ok) {
    if (approved) {
      showToast("✅ Secondary device approved! Access granted.", "success");
    } else {
      showToast("⛔ Secondary device request denied and blocked.", "info");
    }
    loadUserAlerts(true);
    loadUserSessions(true);
  } else {
    showToast(res.data?.detail || "Action failed.", "error");
  }
}
window.executeApproveSecondary = executeApproveSecondary;

// Transfer Primary Device Authority using Secondary Password
async function executeSetPrimaryWithPassword(e) {
  e.preventDefault();
  const pwd = document.getElementById("input-transfer-sec-password").value;
  if (!pwd) {
    showToast("Please enter your Master Secondary Security Password.", "warning");
    return;
  }

  const browser = AppState.fingerprint?.browser || "Browser";
  const os = AppState.fingerprint?.os || "Desktop";
  const label = `Primary Security Portal (${browser} on ${os})`;

  const res = await apiFetch("/api/auth/devices/set-primary", {
    method: "POST",
    body: JSON.stringify({
      is_primary: true,
      device_label: label,
      secondary_password: pwd
    })
  });

  if (res.ok) {
    closeModal("modal-set-primary-confirm");
    document.getElementById("input-transfer-sec-password").value = "";
    showToast("👑 Primary Device authority successfully transferred to this machine!", "success");
    await checkCurrentUser();
  } else {
    showToast(res.data?.detail || "Incorrect Secondary Password. Transfer denied.", "error");
  }
}
window.executeSetPrimaryWithPassword = executeSetPrimaryWithPassword;

// Update Master Secondary Security Password
async function handleUpdateSecondaryPassword(e) {
  e.preventDefault();
  const curPwd = document.getElementById("sec-pwd-current").value;
  const newPwd = document.getElementById("sec-pwd-new").value;
  const confirmPwd = document.getElementById("sec-pwd-confirm").value;

  if (newPwd !== confirmPwd) {
    showToast("New secondary passwords do not match.", "error");
    return;
  }

  const res = await apiFetch("/api/auth/secondary-password/update", {
    method: "POST",
    body: JSON.stringify({
      current_password: curPwd,
      new_secondary_password: newPwd
    })
  });

  if (res.ok) {
    closeModal("modal-update-secondary-password");
    document.getElementById("sec-pwd-current").value = "";
    document.getElementById("sec-pwd-new").value = "";
    document.getElementById("sec-pwd-confirm").value = "";
    showToast("Master Secondary Security Password updated successfully!", "success");
    await checkCurrentUser();
  } else {
    showToast(res.data?.detail || "Failed to update secondary password.", "error");
  }
}
window.handleUpdateSecondaryPassword = handleUpdateSecondaryPassword;

// Self-unfreeze account from authenticated Primary Device
async function executeSelfUnlock() {
  const res = await apiFetch("/api/auth/unlock-self", { method: "POST" });
  if (res.ok) {
    showToast("Account successfully restored to ACTIVE!", "success");
    if (AppState.user) {
      AppState.user.status = "ACTIVE";
      AppState.user.account_is_frozen = false;
    }
    const unfreezeBanner = document.getElementById("primary-unfreeze-banner");
    if (unfreezeBanner) unfreezeBanner.style.display = "none";
    await checkCurrentUser();
  } else {
    showToast(res.data?.detail || "Could not restore account.", "error");
  }
}
window.executeSelfUnlock = executeSelfUnlock;

// Active Sessions Controller (Primary Portal Preservation & Remote Device Termination)
async function loadUserSessions(force = false) {
  const container = document.getElementById("sessions-table-body");
  if (!container || isFetchingSessions) return;

  isFetchingSessions = true;
  try {
    const res = await apiFetch("/api/auth/sessions");
    if (res.ok && res.data?.sessions) {
      const sessions = res.data.sessions;
      const signature = JSON.stringify(sessions.map(s => [s.session_id, s.status, s.is_current]));

      // Dynamically update Hero Bento Metrics with live telemetry counts
      const totalSessions = sessions.length;
      const mDevCount = document.getElementById("metric-devices-count");
      const mDevSub = document.getElementById("metric-devices-sub");
      const mSessCount = document.getElementById("metric-sessions-count");
      const mSessFooter = document.getElementById("metric-sessions-footer");
      if (mDevCount) mDevCount.textContent = totalSessions;
      if (mDevSub) mDevSub.textContent = `/ ${totalSessions} Active`;
      if (mSessCount) mSessCount.textContent = `${totalSessions} Active ${totalSessions === 1 ? 'Device' : 'Devices'}`;
      if (mSessFooter) mSessFooter.textContent = `SYNCED`;

      // Dynamically populate secondary / companion devices in Device Trust Center
      const secondarySessions = sessions.filter(s => s.device_tier !== "PRIMARY" && s.is_primary_device !== true);
      const secContainer = document.getElementById("trust-center-secondary-devices-container");
      if (secContainer) {
        if (secondarySessions.length === 0) {
          secContainer.innerHTML = `
            <div style="font-size: 0.76rem; color: var(--text-muted); padding: 0.65rem; border: 1px dashed rgba(255, 255, 255, 0.08); border-radius: 6px; text-align: center;">
              No secondary devices connected. Sign in from another browser or device to see it here.
            </div>
          `;
        } else {
          secContainer.innerHTML = secondarySessions.map(s => {
            const isCurrent = s.is_current === true;
            const devStr = (s.device || "").toLowerCase();
            let dIcon = "devices";
            if (devStr.includes("iphone") || devStr.includes("android") || devStr.includes("mobile")) dIcon = "smartphone";
            else if (devStr.includes("mac") || devStr.includes("laptop") || devStr.includes("chrome") || devStr.includes("edge") || devStr.includes("firefox")) dIcon = "laptop_mac";

            return `
              <div class="secondary-device-trust-card">
                <div class="secondary-trust-left">
                  <div class="secondary-trust-icon">
                    <span class="material-symbols-outlined">${dIcon}</span>
                  </div>
                  <div>
                    <div class="secondary-trust-name">${s.device || 'Secondary Device'}</div>
                    <div class="secondary-trust-meta">IP: ${s.ip_address} &bull; ${s.geo?.city || 'Local'} &bull; ${new Date(s.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
                  </div>
                </div>
                <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                  <span class="capsule-badge capsule-amber" style="font-size: 0.68rem;">
                    <span class="pulse-dot pulse-dot-amber"></span>${isCurrent ? 'THIS DEVICE' : 'SECONDARY DEVICE'}
                  </span>
                  <span class="badge-restricted">CANNOT SIGN OUT OTHERS</span>
                </div>
              </div>
            `;
          }).join("");
        }
      }

      // Skip DOM rebuild if nothing changed (avoids micro-stutter)
      if (!force && signature === lastSessionsSignature) {
        return;
      }
      lastSessionsSignature = signature;

      if (sessions.length === 0) {
        container.innerHTML = `<tr><td colspan="4" class="empty-state-box" style="padding: 2rem; text-align: center;"><div class="empty-state-icon" style="font-size: 2rem; margin-bottom: 0.5rem;">🔒</div><div style="color: var(--text-muted);">No active sessions found.</div></td></tr>`;
        return;
      }

      container.innerHTML = sessions.map(s => {
        const isCurrent = s.is_current === true;
        const isPrimarySession = s.device_tier === "PRIMARY" || s.is_primary_device === true;

        // Choose appropriate icon
        const devStr = (s.device || "").toLowerCase();
        let devIcon = "devices";
        if (devStr.includes("iphone") || devStr.includes("android") || devStr.includes("mobile")) {
          devIcon = "smartphone";
        } else if (devStr.includes("mac") || devStr.includes("laptop") || devStr.includes("chrome") || devStr.includes("edge") || devStr.includes("firefox")) {
          devIcon = "laptop_mac";
        } else if (devStr.includes("linux") || devStr.includes("server") || devStr.includes("aws")) {
          devIcon = "dns";
        }

        let deviceBadge;
        if (isCurrent && isPrimarySession) {
          deviceBadge = `<span class="capsule-badge capsule-emerald"><span class="pulse-dot pulse-dot-emerald"></span>THIS DEVICE (MAIN)</span>`;
        } else if (isCurrent && !isPrimarySession) {
          deviceBadge = `<span class="capsule-badge capsule-amber"><span class="pulse-dot pulse-dot-amber"></span>THIS BROWSER (SECONDARY)</span>`;
        } else if (isPrimarySession) {
          deviceBadge = `<span class="capsule-badge capsule-emerald">MAIN DEVICE</span>`;
        } else {
          deviceBadge = `<span class="capsule-badge capsule-amber">SECONDARY DEVICE</span>`;
        }

        const isUserOnSecondary = AppState.user && (AppState.user.is_primary_device === false || AppState.user.device_tier === "SECONDARY");

        let actionCell;
        if (isCurrent) {
          actionCell = `<span class="badge-this-device"><span class="pulse-dot ${isPrimarySession ? 'pulse-dot-emerald' : 'pulse-dot-amber'}"></span>THIS DEVICE</span>`;
        } else if (isPrimarySession) {
          actionCell = `<span class="badge-protected" title="Main device cannot be signed out remotely"><span>Protected (Main)</span></span>`;
        } else if (isUserOnSecondary) {
          actionCell = `<span class="badge-restricted" title="Secondary devices cannot sign out remote devices"><span>Read-Only</span></span>`;
        } else {
          actionCell = `<button class="btn-terminate-session" onclick="killSession('${s.session_id}')" title="Sign out this device">
               <span class="material-symbols-outlined" style="font-size: 0.95rem;">logout</span>
               <span>Sign Out</span>
             </button>`;
        }

        return `
          <tr class="${isCurrent ? 'session-row-current' : ''}">
            <td>
              <div class="session-device-cell">
                <span class="material-symbols-outlined session-icon ${isPrimarySession ? 'text-emerald' : 'text-amber'}">${devIcon}</span>
                <div>
                  <div class="session-device-name">${s.device || 'Web Browser'}</div>
                  <div class="session-device-badge-wrap">${deviceBadge}</div>
                </div>
              </div>
            </td>
            <td>
              <div class="session-geo">${s.geo?.city || 'Local Location'}, ${s.geo?.country || 'US'}</div>
              <div class="session-ip-mono text-muted" style="font-size: 0.76rem;">IP: ${s.ip_address}</div>
            </td>
            <td>
              <span class="${isCurrent ? 'text-emerald' : 'text-secondary'} session-lifetime" style="display: flex; align-items: center; gap: 5px;">
                ${isCurrent ? '<span class="pulse-dot pulse-dot-emerald"></span>Active Now' : new Date(s.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
              </span>
            </td>
            <td style="text-align: right;">${actionCell}</td>
          </tr>
        `;
      }).join("");
    }
  } finally {
    isFetchingSessions = false;
  }
}

async function killSession(sessionId) {
  if (!confirm("Sign out this device? Your main device will remain logged in.")) return;
  const res = await apiFetch("/api/auth/sessions/kill", {
    method: "POST",
    body: JSON.stringify({ session_id: sessionId })
  });
  if (res.ok) {
    if (res.data?.was_current_session) {
      showToast("Session signed out. Logging out...", "info");
      handleLogout();
    } else {
      showToast("Device signed out successfully. Your main device remains active.", "success");
      loadUserSessions(true);
    }
  } else {
    showToast(res.data?.detail || "Failed to sign out session.", "error");
  }
}

async function killAllOtherSessions() {
  const isUserOnSecondary = AppState.user && (AppState.user.is_primary_device === false || AppState.user.device_tier === "SECONDARY");
  if (isUserOnSecondary) {
    showToast("⚠️ Restricted: Signing out other devices can only be authorized from your main device.", "warning");
    return;
  }
  if (!confirm("Sign out of all other devices? Your current device will remain logged in.")) return;
  const res = await apiFetch("/api/auth/sessions/kill-others", { method: "POST" });
  if (res.ok) {
    const count = res.data?.terminated_count || 0;
    showToast(`Signed out of ${count} remote device(s). Your main device remains active.`, "success");
    loadUserSessions(true);
  } else {
    showToast(res.data?.detail || "Failed to sign out other devices.", "error");
  }
}

// =============================================================
// Native Desktop Notifications, Tab Flashing, SSE Stream & Web Worker
// =============================================================
let titlePulseInterval = null;
let originalPageTitle = document.title || "AWSSecurity | Real-Time Account Hijacking Defense";
let timerWorker = null;
let sseConnection = null;

function startTitlePulse(code) {
  if (titlePulseInterval) return;
  originalPageTitle = document.title;
  let toggle = false;
  titlePulseInterval = setInterval(() => {
    document.title = toggle ? `🔔 (1) CODE: ${code || '------'} - ALLOW ACCESS?` : `🚨 NEW DEVICE SIGN-IN REQUEST!`;
    toggle = !toggle;
  }, 1000);
}

function stopTitlePulse() {
  if (titlePulseInterval) {
    clearInterval(titlePulseInterval);
    titlePulseInterval = null;
  }
  document.title = originalPageTitle;
}
window.stopTitlePulse = stopTitlePulse;

async function checkNotificationPermission() {
  const badge = document.getElementById("btn-desktop-notif-status");
  if (!badge) return;
  if (!("Notification" in window)) {
    badge.style.display = "none";
    return;
  }
  if (Notification.permission === "granted") {
    badge.className = "capsule-badge capsule-emerald";
    badge.innerHTML = '<span class="pulse-dot pulse-dot-emerald"></span>🔔 DESKTOP ALERTS: ACTIVE';
    badge.title = "System desktop notifications are enabled. You will receive real popups even when minimized.";
  } else if (Notification.permission === "denied") {
    badge.className = "capsule-badge capsule-crimson";
    badge.innerHTML = '🔕 DESKTOP ALERTS: BLOCKED';
    badge.title = "Desktop notifications blocked in browser settings. Click to learn how to enable.";
  } else {
    badge.className = "capsule-badge capsule-amber";
    badge.innerHTML = '<span class="pulse-dot pulse-dot-amber"></span>🔔 ENABLE DESKTOP ALERTS';
    badge.title = "Click to enable native background desktop notifications for secondary sign-in requests.";
  }
}

async function toggleDesktopNotifications() {
  if (!("Notification" in window)) {
    showToast("This browser does not support Desktop Notifications.", "info");
    return;
  }
  if (Notification.permission === "default") {
    const perm = await Notification.requestPermission();
    checkNotificationPermission();
    if (perm === "granted") {
      showToast("🔔 Desktop notifications enabled! You will be alerted even when this tab is minimized.", "success");
      try {
        new Notification("AWSSecurity Desktop Alerts Activated", {
          body: "You will receive instant system notifications when secondary devices request sign-in access.",
          icon: "/static/favicon.ico"
        });
      } catch (e) {}
    } else {
      showToast("Notifications were not enabled.", "warning");
    }
  } else if (Notification.permission === "granted") {
    showToast("🔔 Desktop notifications are currently ACTIVE.", "info");
  } else {
    showToast("Notifications are blocked in your browser settings. Please allow notifications in site settings.", "warning");
  }
}
window.toggleDesktopNotifications = toggleDesktopNotifications;

function fireNativeDesktopNotification(alert) {
  if (!("Notification" in window)) return;
  if (Notification.permission === "default") {
    Notification.requestPermission().then(perm => {
      checkNotificationPermission();
      if (perm === "granted") fireNativeDesktopNotification(alert);
    });
    return;
  }
  if (Notification.permission !== "granted") return;

  const code = alert.verification_code || "";
  const dev = alert.device || "Secondary Device";
  const loc = alert.origin || "Current Location";

  const title = code ? `🔐 Sign-In Request: Code ${code}` : "🚨 AWSSecurity Alert";
  const body = `${dev} from ${loc} is requesting sign-in access. Click to view and approve.`;

  try {
    const notif = new Notification(title, {
      body: body,
      icon: "/static/favicon.ico",
      tag: "sec-approval-" + (alert.alert_id || Date.now()),
      requireInteraction: true
    });

    notif.onclick = function() {
      window.focus();
      openModal("modal-secondary-device-approval");
      notif.close();
    };
  } catch (err) {
    console.warn("Could not display native notification", err);
  }
}

function handleIncomingSecondaryApproval(alert) {
  const isUserOnSecondary = AppState.user && (AppState.user.is_primary_device === false || AppState.user.device_tier === "SECONDARY");
  if (isUserOnSecondary) return;

  const devEl = document.getElementById("sec-approval-device");
  const locEl = document.getElementById("sec-approval-location");
  const ipEl = document.getElementById("sec-approval-ip");
  const codeEl = document.getElementById("sec-approval-code");
  const tokenHidden = document.getElementById("sec-approval-token-hidden");
  if (devEl) devEl.textContent = alert.device || "Secondary Device";
  if (locEl) locEl.textContent = alert.origin || "Unknown Location";
  if (ipEl) ipEl.textContent = alert.ip || "127.0.0.1";
  if (codeEl) codeEl.textContent = alert.verification_code || "------";
  if (tokenHidden) tokenHidden.value = alert.temp_token || "";

  openModal("modal-secondary-device-approval");
  playSecurityAlertSound();
  showToast(`📲 Sign-in verification code: ${alert.verification_code}`, "info");

  // Fire Real HTML5 Native Desktop Notification on Windows!
  fireNativeDesktopNotification(alert);

  // Pulse document title so the user notices even if on another tab
  startTitlePulse(alert.verification_code);
}

function startBackgroundTimerWorker() {
  if (window.Worker && !timerWorker) {
    try {
      timerWorker = new Worker("/static/js/timer_worker.js");
      timerWorker.onmessage = function(e) {
        if (e.data?.type === "tick" && AppState.token) {
          loadUserAlerts();
        }
      };
      timerWorker.postMessage("start");
    } catch (err) {
      console.warn("Timer worker failed, falling back to window interval", err);
    }
  }
}

function connectSecurityStream() {
  if (!AppState.token) return;
  const isPrimary = AppState.user && (AppState.user.is_primary_device !== false && AppState.user.device_tier !== "SECONDARY");
  if (!isPrimary) return;

  if (sseConnection) {
    sseConnection.close();
    sseConnection = null;
  }

  try {
    sseConnection = new EventSource(`/api/security/stream?token=${encodeURIComponent(AppState.token)}`);
    sseConnection.addEventListener("alert", (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === "SECONDARY_DEVICE_APPROVAL_REQUEST") {
          handleIncomingSecondaryApproval(data);
        } else {
          if (typeof showSecurityAlertBanner === "function") {
            showSecurityAlertBanner(data);
          }
        }
        loadUserAlerts(true);
      } catch (err) {
        console.error("SSE parse error", err);
      }
    });
    sseConnection.onerror = (err) => {
      if (sseConnection && sseConnection.readyState === EventSource.CLOSED) {
        sseConnection = null;
      }
    };
  } catch (e) {
    console.warn("SSE connection error", e);
  }
}

// User Security Alerts Inbox with Real-Time Notifications
async function loadUserAlerts(force = false) {
  const container = document.getElementById("alerts-inbox-container");
  const badge = document.getElementById("alerts-count-badge");
  if (!container || isFetchingAlerts) return;

  isFetchingAlerts = true;
  try {
    const res = await apiFetch("/api/security/user-alerts");
    if (res.ok && res.data?.alerts) {
      const alerts = res.data.alerts;
      if (badge) badge.textContent = alerts.length;

      const isUserOnSecondary = AppState.user && (AppState.user.is_primary_device === false || AppState.user.device_tier === "SECONDARY");

      // Check for newly arrived alerts
      const newAlerts = alerts.filter(a => !lastSeenAlertIds.has(a.alert_id));
      if (!isFirstAlertsLoad && newAlerts.length > 0) {
        for (const latest of newAlerts) {
          if (latest.type === "SECONDARY_DEVICE_APPROVAL_REQUEST" && latest.status === "PENDING_APPROVAL") {
            handleIncomingSecondaryApproval(latest);
          } else if (latest.type === "SECONDARY_DEVICE_LOGIN") {
            if (!isUserOnSecondary) {
              showToast(latest.reason || "ℹ️ Another device signed into your account.", "info");
            }
          } else if (latest.type === "SUSPICIOUS_FAILED_LOGIN" || latest.type === "REPEATED_FAILED_LOGINS" || latest.type === "BRUTE_FORCE_LOCKOUT") {
            showToast(`⚠️ Security Warning: ${latest.reason || 'Someone tried to sign in with an incorrect password.'}`, "error");
            playSecurityAlertSound();
            showSecurityAlertBanner(latest);
          } else if ((latest.risk_score || 0) >= 40) {
            showToast(`🚨 Security Alert: ${latest.reason || 'Suspicious access detected!'}`, "error");
            playSecurityAlertSound();
            showSecurityAlertBanner(latest);
          }
        }
      } else if (isFirstAlertsLoad && alerts.length > 0) {
        // On initial page load or fresh login, check if there are recent pending approval requests
        const pendingApprovalAlert = alerts.find(a => {
          const ageMs = Date.now() - new Date(a.created_at).getTime();
          return ageMs < 10 * 60 * 1000 && a.type === "SECONDARY_DEVICE_APPROVAL_REQUEST" && a.status === "PENDING_APPROVAL";
        });
        if (pendingApprovalAlert && !isUserOnSecondary) {
          handleIncomingSecondaryApproval(pendingApprovalAlert);
        }

        // Also check if there are recent unresolved security alerts (within last 15 mins)
        const recentAlert = alerts.find(a => {
          const ageMs = Date.now() - new Date(a.created_at).getTime();
          return ageMs < 15 * 60 * 1000 && a.status !== "RESOLVED" && (a.type === "SUSPICIOUS_FAILED_LOGIN" || a.type === "REPEATED_FAILED_LOGINS" || a.type === "BRUTE_FORCE_LOCKOUT" || (a.risk_score || 0) >= 40);
        });
        if (recentAlert) {
          showToast(`⚠️ Recent Security Warning: ${recentAlert.reason || 'Someone tried to sign in with an incorrect password.'}`, "error");
          playSecurityAlertSound();
          showSecurityAlertBanner(recentAlert);
        }
      }

      // Update seen cache
      alerts.forEach(a => lastSeenAlertIds.add(a.alert_id));
      isFirstAlertsLoad = false;

      const signature = JSON.stringify(alerts.map(a => [a.alert_id, a.risk_score, a.status]));
      if (!force && signature === lastAlertsSignature) {
        return;
      }
      lastAlertsSignature = signature;

      if (alerts.length === 0) {
        container.innerHTML = `
          <div style="padding: 1.75rem 1rem; text-align: center; background: rgba(9, 14, 25, 0.4); border-radius: 8px; border: 1px dashed rgba(255, 255, 255, 0.08);">
            <div style="font-size: 2rem; margin-bottom: 0.5rem;">🛡️</div>
            <div style="font-weight: 600; color: #ffffff; font-size: 0.92rem;">No Security Alerts</div>
            <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 4px; max-width: 320px; margin-left: auto; margin-right: auto;">
              Everything looks good. No unauthorized access attempts detected.
            </div>
          </div>
        `;
        return;
      }

      container.innerHTML = alerts.map(a => {
        const isUserOnSecondary = AppState.user && (AppState.user.is_primary_device === false || AppState.user.device_tier === "SECONDARY");
        const vCode = a.verification_code || (a.reason && a.reason.match(/Verification code:\s*([0-9A-Za-z]+)/i)?.[1]) || "";
        const isSecondaryApproval = a.type === "SECONDARY_DEVICE_APPROVAL_REQUEST"
          || a.type === "DEVICE_APPROVAL_REQUIRED"
          || Boolean(vCode)
          || (a.reason && (a.reason.includes("requesting sign-in access") || a.reason.includes("Verification code:")));
        const isSecondaryLogin = a.type === "SECONDARY_DEVICE_LOGIN";
        const isFailedLogin = a.type === "SUSPICIOUS_FAILED_LOGIN" || a.type === "REPEATED_FAILED_LOGINS" || a.type === "BRUTE_FORCE_LOCKOUT";
        const isCritical = (a.risk_score || 0) >= 70;
        const isInfo = isSecondaryLogin || (a.risk_score || 0) <= 25;

        const isPending = a.status === "PENDING_APPROVAL" || a.status === "PENDING" || (!a.status && isSecondaryApproval);
        const isApproved = a.status === "RESOLVED_APPROVED" || a.status === "APPROVED" || a.status === "RESOLVED_VERIFIED";
        const isDenied = a.status === "RESOLVED_DENIED" || a.status === "DENIED";

        let riskBadge;
        let cardClass;
        let iconName;
        let iconClass;
        let alertTitle;

        if (isSecondaryApproval) {
          cardClass = "alert-approval";
          iconName = "security_update_good";
          iconClass = "text-emerald";
          alertTitle = "Secondary Device Sign-In Request";
          if (isApproved) {
            riskBadge = `<span class="capsule-badge capsule-emerald font-bold">✅ APPROVED</span>`;
          } else if (isDenied) {
            riskBadge = `<span class="capsule-badge capsule-crimson font-bold">⛔ DENIED</span>`;
          } else {
            riskBadge = `<span class="capsule-badge capsule-amber font-bold"><span class="pulse-dot pulse-dot-amber"></span>VERIFICATION CODE</span>`;
          }
        } else if (isInfo) {
          cardClass = "alert-info";
          iconName = "devices";
          iconClass = "text-cyan";
          riskBadge = `<span class="capsule-badge capsule-cyan font-bold">ℹ️ NEW SIGN-IN</span>`;
          alertTitle = "New Device Sign-In";
        } else if (isFailedLogin) {
          cardClass = "alert-warning";
          iconName = "key_off";
          iconClass = "text-amber";
          riskBadge = `<span class="capsule-badge capsule-amber font-bold">⚠️ WRONG PASSWORD</span>`;
          alertTitle = "Incorrect Password Attempt";
        } else if (isCritical) {
          cardClass = "alert-critical";
          iconName = "gpp_bad";
          iconClass = "text-crimson";
          riskBadge = `<span class="capsule-badge capsule-crimson font-bold">🚨 BLOCKED (${Math.round(a.risk_score)}/100)</span>`;
          alertTitle = "Suspicious Access Blocked";
        } else {
          cardClass = "alert-warning";
          iconName = "warning";
          iconClass = "text-amber";
          riskBadge = `<span class="capsule-badge capsule-amber font-bold">⚠️ WARNING</span>`;
          alertTitle = "Security Warning";
        }

        const ipLabel = "IP Address:";
        const clientLabel = "Device:";

        let actionsHtml = "";
        if (isUserOnSecondary) {
          actionsHtml = `
            <button class="btn btn-secondary btn-sm" onclick="dismissUserAlert('${a.alert_id}')">
              <span>Dismiss</span>
            </button>
            <span class="badge-restricted" style="margin-left: auto;">READ-ONLY</span>
          `;
        } else if (isSecondaryApproval) {
          if (isPending) {
            actionsHtml = `
              <button class="btn btn-primary btn-sm glow-emerald" onclick="executeApproveSecondary(true, '${a.temp_token || 'LATEST'}')" style="background: linear-gradient(135deg, #10b981, #059669); font-weight: 700; border: none; box-shadow: 0 0 15px rgba(16, 185, 129, 0.4); padding: 0.45rem 0.9rem;">
                <span class="material-symbols-outlined" style="font-size: 1rem;">check_circle</span>
                <span>Allow Sign-In (1-Click)</span>
              </button>
              <button class="btn btn-danger btn-sm" onclick="executeApproveSecondary(false, '${a.temp_token || 'LATEST'}')">
                <span class="material-symbols-outlined" style="font-size: 0.9rem;">cancel</span>
                <span>Deny & Block</span>
              </button>
              <button class="btn btn-secondary btn-sm" onclick="dismissUserAlert('${a.alert_id}')">
                <span>Dismiss</span>
              </button>
            `;
          } else {
            actionsHtml = `
              <button class="btn btn-secondary btn-sm" onclick="dismissUserAlert('${a.alert_id}')">
                <span>Dismiss</span>
              </button>
              <span class="badge-protected" style="margin-left: auto;">${a.status || 'RESOLVED'}</span>
            `;
          }
        } else {
          if (isFailedLogin) {
            // Attacker failed to log in - DO NOT show "Terminate Attacker" (no session exists!)
            actionsHtml = `
              <button class="btn btn-secondary btn-sm" onclick="dismissUserAlert('${a.alert_id}')">
                <span>Dismiss</span>
              </button>
              <button class="btn btn-warning btn-sm" onclick="openModal('modal-reset-password')" title="Change your password if you think someone guessed it">
                <span class="material-symbols-outlined" style="font-size: 0.9rem;">lock_reset</span>
                <span>Change Password</span>
              </button>
              <span class="badge-protected" style="margin-left: auto; font-size: 0.68rem;">ATTEMPT BLOCKED</span>
            `;
          } else if (isSecondaryLogin) {
            actionsHtml = `
              <button class="btn btn-secondary btn-sm" onclick="dismissUserAlert('${a.alert_id}')">
                <span>Dismiss</span>
              </button>
              <button class="btn btn-warning btn-sm" onclick="killAllOtherSessions()" title="Sign out this device if you don't recognize it">
                <span class="material-symbols-outlined" style="font-size: 0.9rem;">logout</span>
                <span>Sign Out Other Devices</span>
              </button>
            `;
          } else {
            actionsHtml = `
              <button class="btn btn-secondary btn-sm" onclick="dismissUserAlert('${a.alert_id}')">
                <span>Dismiss</span>
              </button>
              <button class="btn btn-warning btn-sm" onclick="killAllOtherSessions()" title="Sign out all other devices immediately">
                <span class="material-symbols-outlined" style="font-size: 0.9rem;">logout</span>
                <span>Sign Out Other Devices</span>
              </button>
              <button class="btn btn-danger btn-sm" onclick="emergencyLockAccount()" title="Sign out everywhere immediately">
                <span class="material-symbols-outlined" style="font-size: 0.9rem;">lock_reset</span>
                <span>Sign Out Everywhere</span>
              </button>
            `;
          }
        }

        return `
          <div class="alert-card ${cardClass}">
            <div class="alert-card-header">
              <div class="alert-header-info">
                <span class="material-symbols-outlined ${iconClass}" style="font-size: 1.25rem;">
                  ${iconName}
                </span>
                <div>
                  <div class="alert-title">${alertTitle}</div>
                  <div class="alert-time text-muted">${new Date(a.created_at).toLocaleTimeString()}</div>
                </div>
              </div>
              ${riskBadge}
            </div>
            <div style="font-size: 0.8rem; color: #e2e8f0; line-height: 1.4;">
              ${a.reason || 'Suspicious access detected.'}
            </div>
            ${isSecondaryApproval && vCode ? `
              <div style="margin: 0.75rem 0; padding: 0.75rem 1rem; background: rgba(16, 185, 129, 0.08); border: 1px dashed rgba(16, 185, 129, 0.4); border-radius: 8px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
                <div>
                  <div style="font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 2px;">Secondary Device Verification Code:</div>
                  <div style="font-family: var(--font-mono); font-size: 1.6rem; font-weight: 800; letter-spacing: 0.25em; color: var(--accent-emerald); text-shadow: 0 0 10px rgba(16, 185, 129, 0.5);">${vCode}</div>
                </div>
                ${isPending ? `
                  <span class="capsule-badge capsule-amber" style="font-size: 0.72rem; padding: 0.3rem 0.6rem;">
                    <span class="pulse-dot pulse-dot-amber"></span>AWAITING APPROVAL
                  </span>
                ` : `
                  <span class="capsule-badge capsule-emerald" style="font-size: 0.72rem; padding: 0.3rem 0.6rem;">
                    ✅ ${a.status || 'RESOLVED'}
                  </span>
                `}
              </div>
            ` : ''}
            <div class="alert-meta-box">
              <div><span class="text-muted">Location:</span> <strong>${a.origin || 'Unknown'}</strong></div>
              <div><span class="text-muted">${ipLabel}</span> <code class="font-mono text-cyan">${a.ip}</code></div>
              <div><span class="text-muted">${clientLabel}</span> ${a.device || 'Web Browser'}</div>
            </div>
            <div class="alert-actions-bar">
              ${actionsHtml}
            </div>
          </div>
        `;
      }).join("");
    }
  } finally {
    isFetchingAlerts = false;
  }
}

// Dismiss alert handlers
async function dismissUserAlert(alertId) {
  const res = await apiFetch("/api/security/user-alerts/dismiss", {
    method: "POST",
    body: JSON.stringify({ alert_id: alertId })
  });
  if (res.ok) {
    showToast("Alert dismissed.", "info");
    loadUserAlerts(true);
  }
}
window.dismissUserAlert = dismissUserAlert;

async function dismissAllUserAlerts() {
  const res = await apiFetch("/api/security/user-alerts/dismiss-all", { method: "POST" });
  if (res.ok) {
    showToast("All alerts cleared.", "info");
    loadUserAlerts(true);
  }
}
window.dismissAllUserAlerts = dismissAllUserAlerts;

// Emergency Lock Account: Preserves Primary Device Session
async function emergencyLockAccount() {
  const isUserOnSecondary = AppState.user && (AppState.user.is_primary_device === false || AppState.user.device_tier === "SECONDARY");
  if (isUserOnSecondary) {
    showToast("⚠️ Restricted: Signing out everywhere can only be done from your main device.", "warning");
    return;
  }
  if (!confirm("Sign out of all other devices? Your main device will remain active and protected.")) return;
  const res = await apiFetch("/api/auth/lock-account", { method: "POST" });
  if (res.ok) {
    showToast("Signed out of all other devices. Your main device remains active.", "warning");
    if (AppState.user) {
      AppState.user.status = "LOCKED";
      AppState.user.account_is_frozen = true;
    }
    renderUserPortal();
    loadUserSessions(true);
    loadUserAlerts(true);
  } else {
    showToast(res.data?.detail || "Failed to sign out other devices.", "error");
  }
}
window.emergencyLockAccount = emergencyLockAccount;

// Delete Account
async function handleDeleteAccount(e) {
  e.preventDefault();
  const password = document.getElementById("del-account-password").value;
  const res = await apiFetch("/api/auth/delete-account", {
    method: "POST",
    body: JSON.stringify({ password })
  });
  if (res.ok) {
    closeModal("modal-delete-account");
    AppState.token = null;
    AppState.user = null;
    localStorage.removeItem("cyber_token");
    showToast("Your account has been deleted permanently.", "info");
    renderUserPortal();
  } else {
    showToast(res.data?.detail || "Failed to delete account. Incorrect password.", "error");
  }
}

// Forgot & Reset Password
async function handleForgotPassword(e) {
  e.preventDefault();
  const email = document.getElementById("forgot-email").value.trim();
  const res = await apiFetch("/api/auth/forgot-password", {
    method: "POST",
    body: JSON.stringify({ email })
  });
  closeModal("modal-forgot-password");
  showToast(res.data?.message || "Password reset link dispatched if account exists.", "info");
  if (res.data?.demo_reset_token) {
    document.getElementById("reset-token-input").value = res.data.demo_reset_token;
    openModal("modal-reset-password");
  }
}

async function handleResetPassword(e) {
  e.preventDefault();
  const token = document.getElementById("reset-token-input").value.trim();
  const newPassword = document.getElementById("reset-new-password").value;
  const res = await apiFetch("/api/auth/reset-password", {
    method: "POST",
    body: JSON.stringify({ token, new_password: newPassword })
  });
  if (res.ok) {
    closeModal("modal-reset-password");
    showToast("Password updated successfully! Please sign in with your new password.", "success");
  } else {
    showToast(res.data?.detail || "Failed to reset password. Invalid or expired token.", "error");
  }
}

function handleLogout() {
  if (sseConnection) {
    try { sseConnection.close(); } catch(e) {}
    sseConnection = null;
  }
  if (timerWorker) {
    try { timerWorker.terminate(); } catch(e) {}
    timerWorker = null;
  }
  stopTitlePulse();
  AppState.token = null;
  AppState.user = null;
  localStorage.removeItem("cyber_token");
  if (userPollingInterval) {
    clearInterval(userPollingInterval);
    userPollingInterval = null;
  }
  showToast("Logged out securely.", "info");
  renderUserPortal();
}
