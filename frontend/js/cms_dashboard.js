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
  await cmsFetchStats();
  await cmsFetchUsers();
}
window.cmsLoadData = cmsLoadData;

/**
 * Fetch and populate top-level stats
 */
async function cmsFetchStats() {
  try {
    const response = await fetch('/api/cms/stats');
    if (!response.ok) throw new Error('Failed to fetch stats');
    
    const data = await response.json();
    
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
  tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading users...</td></tr>';
  
  try {
    const response = await fetch('/api/cms/users');
    if (!response.ok) throw new Error('Failed to fetch users');
    
    const users = await response.json();
    
    if (!Array.isArray(users) || users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No users found.</td></tr>';
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

      const isRootAdmin = user.is_root_admin || user.role === 'ROOT_ADMIN' || user.email === 'demo@awssecurity.io';
      
      tr.innerHTML = `
        <td>
          <div style="display: flex; align-items: center; gap: 0.4rem;">
            <strong>${user.full_name || user.name || 'User'}</strong>
            ${isRootAdmin ? '<span class="badge badge-low font-mono" style="font-size: 0.65rem; color: var(--accent-amber); border-color: rgba(245, 158, 11, 0.4);" title="Root Administrator">👑 Root Admin</span>' : ''}
          </div>
        </td>
        <td><code class="font-mono text-cyan">${user.email}</code></td>
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
    const response = await fetch(`/api/cms/users/${encodeURIComponent(email)}/unlock`, {
      method: 'POST'
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || 'Failed to unlock user');
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
    const response = await fetch(`/api/cms/users/${encodeURIComponent(email)}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || 'Failed to delete user');
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
    const response = await fetch(`/api/system/maintenance?enable=${isEnabling}`, {
      method: 'POST'
    });
    
    if (!response.ok) throw new Error('Failed to toggle maintenance mode');
    
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

