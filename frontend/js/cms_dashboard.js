/**
 * CMS Dashboard Controller
 * Handles logic for the Content Management System and Admin operations.
 */

// Initialize CMS on load or tab switch
document.addEventListener('DOMContentLoaded', () => {
  const cmsTabBtn = document.getElementById('nav-cms-dashboard');
  if (cmsTabBtn) {
    cmsTabBtn.addEventListener('click', () => {
      cmsLoadData();
    });
  }
});

/**
 * Main loader for CMS data
 */
async function cmsLoadData() {
  if (typeof isSuperAdmin === 'function' && !isSuperAdmin(AppState.user)) {
    console.warn('[CMS] Super Admin login required to load CMS data.');
    return;
  }
  await cmsFetchStats();
  await cmsFetchUsers();
  await cmsFetchSessions();
}
window.cmsLoadData = cmsLoadData;

/**
 * Fetch and populate top-level stats
 */
async function cmsFetchStats() {
  try {
    const response = await apiFetch('/api/cms/stats');
    if (!response.ok) throw new Error(response.data?.detail || 'Failed to fetch stats');
    
    const data = response.data;
    
    const uEl = document.getElementById('cms-metric-users');
    const sEl = document.getElementById('cms-metric-sessions');
    const bEl = document.getElementById('cms-metric-blocked');
    const maintBtn = document.getElementById('cms-btn-maintenance');

    if (uEl) uEl.innerText = data.total_users || 0;
    if (sEl) sEl.innerText = data.active_sessions || 0;
    if (bEl) bEl.innerText = data.blocked_hijacks || 0;
    
    if (maintBtn) {
      if (data.maintenance_mode) {
        maintBtn.innerText = 'Disable';
        maintBtn.classList.replace('btn-secondary', 'btn-danger');
      } else {
        maintBtn.innerText = 'Enable';
        maintBtn.classList.replace('btn-danger', 'btn-secondary');
      }
    }
  } catch (err) {
    console.error('[CMS] Error fetching stats:', err);
  }
}

/**
 * Fetch and populate the users table
 */
async function cmsFetchUsers() {
  const tbody = document.getElementById('cms-users-tbody');
  if (!tbody) return;
  if (typeof renderSkeletonRows === "function") renderSkeletonRows("cms-users-tbody", 5);
  else tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading users...</td></tr>';
  
  try {
    const response = await apiFetch('/api/cms/users');
    if (!response.ok) throw new Error(response.data?.detail || 'Failed to fetch users');
    
    const users = response.data;
    
    if (!Array.isArray(users) || users.length === 0) {
      if (typeof renderEmptyState === "function") renderEmptyState("cms-users-tbody", "No users found.");
      else tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No users found.</td></tr>';
      return;
    }
    
    tbody.innerHTML = ''; // Clear loading
    
    users.forEach(user => {
      const tr = document.createElement('tr');
      
      const mfaEnabled = user.mfa_enabled !== false ? 
        '<span class="badge badge-low font-mono" style="color: var(--accent-emerald); border-color: rgba(16, 185, 129, 0.3);">✓ Active (Zero-Trust)</span>' : 
        '<span style="color: var(--text-muted);">Disabled</span>';
        
      const lastLogin = user.last_login ? new Date(user.last_login).toLocaleString() : (user.last_successful_login?.timestamp ? new Date(user.last_successful_login.timestamp * 1000).toLocaleString() : 'Never');

      const isLocked = user.status === 'LOCKED';
      const statusBadge = isLocked
        ? '<span class="badge badge-critical font-mono">LOCKED</span>'
        : '<span class="badge badge-low font-mono">ACTIVE</span>';

      const isSuper = (typeof isSuperAdmin === 'function') ? isSuperAdmin(user) : (user.is_super_admin || user.role === 'SUPER_ADMIN');
      
      tr.innerHTML = `
        <td>
          <div style="display: flex; align-items: center; gap: 0.4rem;">
            <strong>${user.full_name || user.name || 'User'}</strong>
            ${isSuper ? '<span class="badge badge-low font-mono" style="font-size: 0.65rem; color: var(--accent-amber); border-color: rgba(245, 158, 11, 0.4);" title="Super Administrator">👑 Super Admin</span>' : ''}
          </div>
        </td>
        <td><code class="font-mono text-cyan">${user.email}</code>&nbsp;<span class="copy-btn" onclick="copyToClipboard('${user.email}')" title="Copy Email">??</span></td>
        <td>${statusBadge}</td>
        <td>${mfaEnabled}</td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${lastLogin}</td>
        <td>
          <div style="display: flex; gap: 0.4rem; align-items: center;">
            ${isLocked ? `
              <button class="btn btn-warning btn-sm" onclick="cmsUnlockUser('${user.email}')" title="Restore account access and unfreeze">
                Unlock
              </button>
            ` : ''}
            <button class="btn btn-danger btn-sm" onclick="cmsDeleteUser('${user.email}')" title="Delete this user account permanently">
              Delete
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('[CMS] Error fetching users:', err);
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-crimson);">Error loading users: ${err.message}</td></tr>`;
  }
}

/**
 * Unlock a locked/frozen user account
 */
async function cmsUnlockUser(email) {
  try {
    const response = await apiFetch(`/api/cms/users/${encodeURIComponent(email)}/unlock`, {
      method: 'POST'
    });

    if (!response.ok) {
      throw new Error(response.data?.detail || 'Failed to unlock user');
    }

    if (typeof showToast === 'function') {
      showToast(`Account ${email} successfully unlocked and restored to ACTIVE!`, 'success');
    }

    await cmsLoadData();
  } catch (err) {
    if (typeof showToast === 'function') {
      showToast(`Error unlocking account: ${err.message}`, 'error');
    } else {
      alert(`Error unlocking account: ${err.message}`);
    }
    console.error('[CMS] Error unlocking user:', err);
  }
}
window.cmsUnlockUser = cmsUnlockUser;

/**
 * Delete a user by email
 */
async function cmsDeleteUser(email) {
  if (!confirm(`Are you sure you want to delete user ${email}? This action cannot be undone.`)) {
    return;
  }
  
  try {
    const response = await apiFetch(`/api/cms/users/${encodeURIComponent(email)}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      throw new Error(response.data?.detail || 'Failed to delete user');
    }
    
    if (typeof showToast === 'function') {
      showToast(`User ${email} deleted successfully.`, 'success');
    }
    
    // Refresh the table and stats
    await cmsLoadData();
  } catch (err) {
    if (typeof showToast === 'function') {
      showToast(`Error deleting user: ${err.message}`, 'error');
    } else {
      alert(`Error deleting user: ${err.message}`);
    }
    console.error('[CMS] Error deleting user:', err);
  }
}
window.cmsDeleteUser = cmsDeleteUser;

/**
 * Toggle maintenance mode
 */
async function cmsToggleMaintenance(forceEnable = null) {
  const maintBtn = document.getElementById('cms-btn-maintenance');
  let isEnabling;
  if (typeof forceEnable === 'boolean') {
    isEnabling = forceEnable;
  } else if (maintBtn) {
    isEnabling = (maintBtn.innerText.trim() === 'Enable');
  } else {
    isEnabling = false;
  }
  
  try {
    const response = await apiFetch(`/api/system/maintenance?enable=${isEnabling}`, {
      method: 'POST'
    });
    
    if (!response.ok) throw new Error(response.data?.detail || 'Failed to toggle maintenance mode');
    
    if (typeof applyMaintenanceState === 'function') {
      applyMaintenanceState(isEnabling);
    }

    if (maintBtn) {
      if (isEnabling) {
        maintBtn.innerText = 'Disable';
        maintBtn.classList.replace('btn-secondary', 'btn-danger');
      } else {
        maintBtn.innerText = 'Enable';
        maintBtn.classList.replace('btn-danger', 'btn-secondary');
      }
    }

    if (isEnabling) {
      if (typeof showToast === 'function') {
        showToast("Maintenance Mode ENABLED. Non-admin operations are paused.", "warning");
      }
    } else {
      if (typeof showToast === 'function') {
        showToast("Maintenance Mode DISABLED. System operational.", "success");
      }
    }
  } catch (err) {
    if (typeof showToast === 'function') {
      showToast(`Error toggling maintenance mode: ${err.message}`, 'error');
    } else {
      alert(`Error toggling maintenance mode: ${err.message}`);
    }
    console.error('[CMS] Maintenance mode toggle failed:', err);
  }
}
window.cmsToggleMaintenance = cmsToggleMaintenance;

/**
 * Fetch and populate all active logins across the platform for Super Admin
 */
let cmsSessionsCache = [];

async function cmsFetchSessions() {
  const tbody = document.getElementById('cms-sessions-tbody');
  if (!tbody) return;
  if (typeof renderSkeletonRows === "function") renderSkeletonRows("cms-sessions-tbody", 4);
  else tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading active logins...</td></tr>';

  try {
    const response = await apiFetch('/api/cms/sessions');
    if (!response.ok) throw new Error(response.data?.detail || 'Failed to fetch sessions');

    const sessions = response.data;
    cmsSessionsCache = Array.isArray(sessions) ? sessions : [];

    if (!Array.isArray(sessions) || sessions.length === 0) {
      if (typeof renderEmptyState === "function") renderEmptyState("cms-sessions-tbody", "No active sessions found.");
      else tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No active logins found.</td></tr>';
      return;
    }

    tbody.innerHTML = '';

    sessions.forEach(sess => {
      const tr = document.createElement('tr');

      const isPrimary = boolOrTrue(sess.is_primary_device) || sess.device_tier === 'PRIMARY';
      const tierBadge = isPrimary
        ? '<span class="badge badge-low font-mono" style="color: var(--accent-emerald); border-color: rgba(16, 185, 129, 0.4);"><span class="pulse-dot pulse-dot-emerald" style="display:inline-block; margin-right:4px;"></span>PRIMARY PORTAL</span>'
        : '<span class="badge badge-medium font-mono" style="color: var(--accent-cyan); border-color: rgba(6, 182, 212, 0.4);">SECONDARY</span>';

      const statusBadge = (sess.status === 'ACTIVE' || !sess.status)
        ? '<span class="badge badge-low font-mono">ACTIVE</span>'
        : `<span class="badge badge-critical font-mono">${sess.status}</span>`;

      const loginTime = sess.created_at ? new Date(sess.created_at).toLocaleString() : 'Recent';
      const city = sess.geo?.city || 'Local Network';
      const country = sess.geo?.country || 'US';
      const locationText = `${city}, ${country}`;

      tr.innerHTML = `
        <td>
          <div style="font-weight: 600; color: #fff;">${escapeHtml(sess.user_name || 'User')}</div>
          <code class="font-mono text-cyan" style="font-size: 0.75rem;">${escapeHtml(sess.user_email || '')}</code>
        </td>
        <td>
          <div style="font-weight: 500; font-size: 0.85rem; color: #e2e8f0;">${escapeHtml(sess.device || 'Standard Device')}</div>
          <div style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(sess.session_id || '')}</div>
        </td>
        <td>
          <div style="display: flex; flex-direction: column; gap: 3px; align-items: flex-start;">
            ${tierBadge}
            ${statusBadge}
          </div>
        </td>
        <td>
          <div style="font-size: 0.85rem; color: #fff; font-family: var(--font-mono);">${escapeHtml(sess.ip_address || '127.0.0.1')}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(locationText)}</div>
        </td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(loginTime)}</td>
        <td>
          <div style="display: flex; gap: 0.4rem; align-items: center;">
            <button class="btn btn-secondary btn-sm" onclick="cmsOpenEditSession('${sess.session_id}')" title="Edit session label or authority tier">
              Edit
            </button>
            <button class="btn btn-danger btn-sm" onclick="cmsTerminateSession('${sess.session_id}')" title="Terminate and revoke this session immediately">
              Terminate
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('[CMS] Error fetching sessions:', err);
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-crimson);">Error loading sessions: ${err.message}</td></tr>`;
  }
}
window.cmsFetchSessions = cmsFetchSessions;

/**
 * Terminate a login session by ID (Super Admin privilege)
 */
async function cmsTerminateSession(sessionId) {
  if (!confirm(`Are you sure you want to revoke and terminate session ${sessionId}? This will immediately sign the device out.`)) {
    return;
  }

  try {
    const response = await apiFetch(`/api/cms/sessions/${encodeURIComponent(sessionId)}/terminate`, {
      method: 'POST'
    });

    if (!response.ok) {
      throw new Error(response.data?.detail || 'Failed to terminate session');
    }

    if (typeof showToast === 'function') {
      showToast(`Session ${sessionId} terminated successfully. Device signed out.`, 'success');
    }

    await cmsFetchStats();
    await cmsFetchSessions();
  } catch (err) {
    if (typeof showToast === 'function') {
      showToast(`Error terminating session: ${err.message}`, 'error');
    } else {
      alert(`Error terminating session: ${err.message}`);
    }
    console.error('[CMS] Error terminating session:', err);
  }
}
window.cmsTerminateSession = cmsTerminateSession;

/**
 * Open the Edit Session Modal for a given session ID
 */
function cmsOpenEditSession(sessionId) {
  const session = cmsSessionsCache.find(s => s.session_id === sessionId);
  if (!session) {
    if (typeof showToast === 'function') showToast("Session data not found.", "error");
    return;
  }

  const idInput = document.getElementById('cms-edit-session-id');
  const emailInput = document.getElementById('cms-edit-user-email');
  const labelInput = document.getElementById('cms-edit-device-label');
  const tierSelect = document.getElementById('cms-edit-device-tier');
  const statusSelect = document.getElementById('cms-edit-session-status');

  if (idInput) idInput.value = session.session_id || '';
  if (emailInput) emailInput.value = `${session.user_name || ''} (${session.user_email || ''})`;
  if (labelInput) labelInput.value = session.device || '';
  if (tierSelect) tierSelect.value = (session.device_tier || (session.is_primary_device ? 'PRIMARY' : 'SECONDARY'));
  if (statusSelect) statusSelect.value = session.status || 'ACTIVE';

  if (typeof openModal === 'function') {
    openModal('modal-cms-edit-session');
  }
}
window.cmsOpenEditSession = cmsOpenEditSession;

/**
 * Save modifications made to a login session
 */
async function cmsSaveEditSession(e) {
  if (e && e.preventDefault) e.preventDefault();

  const sessionId = document.getElementById('cms-edit-session-id')?.value;
  const deviceLabel = document.getElementById('cms-edit-device-label')?.value.trim();
  const deviceTier = document.getElementById('cms-edit-device-tier')?.value;
  const status = document.getElementById('cms-edit-session-status')?.value;

  if (!sessionId) return;

  try {
    const response = await apiFetch(`/api/cms/sessions/${encodeURIComponent(sessionId)}/edit`, {
      method: 'POST',
      body: JSON.stringify({
        device: deviceLabel,
        device_tier: deviceTier,
        status: status
      })
    });

    if (!response.ok) {
      throw new Error(response.data?.detail || 'Failed to update session');
    }

    if (typeof closeModal === 'function') {
      closeModal('modal-cms-edit-session');
    }

    if (typeof showToast === 'function') {
      showToast("Login session successfully updated!", "success");
    }

    await cmsFetchSessions();
  } catch (err) {
    if (typeof showToast === 'function') {
      showToast(`Error updating session: ${err.message}`, 'error');
    } else {
      alert(`Error updating session: ${err.message}`);
    }
    console.error('[CMS] Error updating session:', err);
  }
}
window.cmsSaveEditSession = cmsSaveEditSession;

function boolOrTrue(val) {
  return val === true || val === "true" || val === 1;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}


