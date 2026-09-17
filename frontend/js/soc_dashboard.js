/**
 * Blue Team SOC (Security Operations Center) Dashboard Controller
 * Manages Animated SVG Risk Gauge, Geo-Velocity Visualizer, Real-Time Event Stream, and Defense Controls.
 */

let socPollingInterval = null;
let currentInspectedEvent = null;
let isFetchingSoc = false;
let lastSocEventsSignature = "";

function initSocDashboard() {
  loadSocMetrics();
  loadSecurityEvents(true);
  initGeoFlightCanvas();

  if (!socPollingInterval) {
    socPollingInterval = setInterval(() => {
      if (document.hidden) return;
      if (AppState.currentTab === "soc-dashboard") {
        loadSocMetrics();
        loadSecurityEvents();
      }
    }, 2500);
  }
}

async function loadSocMetrics() {
  const res = await apiFetch("/api/security/stats");
  if (res.ok && res.data) {
    const stats = res.data;
    
    // Update metric counters
    const totEl = document.getElementById("soc-total-events");
    const blkEl = document.getElementById("soc-blocked-events");
    const mfaEl = document.getElementById("soc-mfa-events");
    const nrmEl = document.getElementById("soc-normal-events");

    if (totEl) totEl.textContent = stats.total_analyzed;
    if (blkEl) blkEl.textContent = stats.blocked_hijacks;
    if (mfaEl) mfaEl.textContent = stats.mfa_challenges;
    if (nrmEl) nrmEl.textContent = stats.normal_allowed;

    // Update SVG Risk Gauge
    updateRiskGauge(stats.avg_risk_score || 0);
  }
}

function updateRiskGauge(score) {
  const needle = document.getElementById("gauge-needle");
  const valueDisplay = document.getElementById("gauge-value-number");
  const statusDisplay = document.getElementById("gauge-status-text");

  if (!needle || !valueDisplay || !statusDisplay) return;

  // Rotation: 0 score = -90deg, 100 score = +90deg
  const angle = -90 + (score / 100.0) * 180;
  needle.style.transform = `rotate(${angle}deg)`;
  valueDisplay.textContent = score.toFixed(1);

  if (score < 40) {
    valueDisplay.style.color = "var(--accent-emerald)";
    statusDisplay.textContent = "LOW RISK • NORMAL BEHAVIOR";
    statusDisplay.style.color = "var(--accent-emerald)";
  } else if (score < 70) {
    valueDisplay.style.color = "var(--accent-amber)";
    statusDisplay.textContent = "ELEVATED RISK • MFA ENFORCED";
    statusDisplay.style.color = "var(--accent-amber)";
  } else {
    valueDisplay.style.color = "var(--accent-crimson)";
    statusDisplay.textContent = "CRITICAL THREAT • SESSIONS BLOCKED";
    statusDisplay.style.color = "var(--accent-crimson)";
  }
}

async function loadSecurityEvents(force = false) {
  const tbody = document.getElementById("soc-events-tbody");
  if (!tbody || isFetchingSoc) return;

  isFetchingSoc = true;
  try {
    const res = await apiFetch("/api/security/events?limit=25");
    if (res.ok && res.data?.events) {
      const events = res.data.events;
      const signature = JSON.stringify(events.map(e => [e.event_id, e.risk_score]));
      if (!force && signature === lastSocEventsSignature) {
        return;
      }
      lastSocEventsSignature = signature;

      if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state-box"><div>No security events recorded yet. Run a simulation to see live detection.</div></td></tr>`;
        return;
      }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-dim);">
          ${new Date(e.timestamp).toLocaleTimeString()}
        </td>
        <td>
          <div style="font-weight: 600;">${e.user_email}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">${e.ip_address}</div>
        </td>
        <td>${e.geo?.city || 'Unknown'}, ${e.geo?.country || 'US'}</td>
        <td>
          <span class="badge ${e.risk_score >= 70 ? 'badge-high' : e.risk_score >= 40 ? 'badge-medium' : 'badge-low'}">
            ${e.risk_score}/100
          </span>
        </td>
        <td>
          <span style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700; color: ${e.action_taken === 'BLOCK_SESSION' ? 'var(--accent-crimson)' : e.action_taken === 'STEP_UP_MFA' ? 'var(--accent-amber)' : 'var(--accent-emerald)'};">
            ${e.action_taken}
          </span>
        </td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="inspectEvent('${e.event_id}')">
            Inspect
          </button>
        </td>
      </tr>
    `).join("");

    // Update flight visualizer with latest event
    if (events[0]) {
      drawFlightVisualizer(events[0]);
    }
  }
} finally {
  isFetchingSoc = false;
}
}

async function inspectEvent(eventId) {
  const res = await apiFetch("/api/security/events?limit=50");
  if (res.ok && res.data?.events) {
    const event = res.data.events.find(e => e.event_id === eventId);
    if (!event) return;

    currentInspectedEvent = event;
    const body = document.getElementById("modal-event-inspect-body");
    if (body) {
      body.innerHTML = `
        <div style="margin-bottom: 1rem;">
          <span class="badge ${event.risk_score >= 70 ? 'badge-high' : event.risk_score >= 40 ? 'badge-medium' : 'badge-low'}">
            Risk Score: ${event.risk_score}/100 • ${event.risk_level}
          </span>
          <h3 style="margin-top: 0.5rem; color: #fff;">${event.action_taken}</h3>
          <p style="font-size: 0.85rem; color: var(--text-muted);">Event ID: <code>${event.event_id}</code> • User: ${event.user_email}</p>
        </div>

        <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 0.4rem;">Explainable AI Factor Attribution:</h4>
        <div style="margin-bottom: 1rem;">
          ${(event.factors || []).map(f => `
            <div style="background: rgba(255,255,255,0.04); padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 0.4rem; border-left: 3px solid ${f.severity === 'CRITICAL' ? 'var(--accent-crimson)' : 'var(--accent-amber)'};">
              <div style="display: flex; justify-content: space-between; font-size: 0.85rem; font-weight: 600;">
                <span>${f.factor}</span>
                <span style="color: var(--accent-amber);">+${f.weight} pts</span>
              </div>
              <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.2rem;">${f.detail}</div>
            </div>
          `).join("") || "<div style='color: var(--text-dim);'>No anomalous factors detected. Normal baseline.</div>"}
        </div>

        <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 0.4rem;">Deep Autoencoder Reconstruction:</h4>
        <div style="font-family: var(--font-mono); font-size: 0.8rem; background: #050811; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; color: #6ee7b7;">
          MSE Reconstruction Error: ${event.autoencoder_loss || 0.0012} (Anomaly threshold: 0.12)
        </div>

        <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 0.4rem;">Raw Telemetry Payload:</h4>
        <pre style="background: #050811; padding: 0.75rem; border-radius: 6px; font-size: 0.75rem; color: #94a3b8; overflow-x: auto;">${JSON.stringify(event, null, 2)}</pre>
      `;
    }
    openModal("modal-event-inspect");
  }
}

// ============================================================================
// HIGH-TECH CYBER WORLD MAP & GEO-VELOCITY FLIGHT VISUALIZER ENGINE
// ============================================================================

const GEO_PRESETS = {
  "Tokyo": { name: "Tokyo", country: "Japan", lat: 35.6762, lon: 139.6503, distKm: 10848, speedKmh: 8500, isAnomaly: true, icon: "🗼" },
  "London": { name: "London", country: "United Kingdom", lat: 51.5074, lon: -0.1278, distKm: 5570, speedKmh: 6200, isAnomaly: true, icon: "🇬🇧" },
  "Sydney": { name: "Sydney", country: "Australia", lat: -33.8688, lon: 151.2093, distKm: 16010, speedKmh: 16000, isAnomaly: true, icon: "🇦🇺" },
  "Philadelphia": { name: "Philadelphia", country: "USA", lat: 39.9526, lon: -75.1652, distKm: 130, speedKmh: 45, isAnomaly: false, icon: "🚗" },
  "Frankfurt": { name: "Frankfurt", country: "Germany", lat: 50.1109, lon: 8.6821, distKm: 6200, speedKmh: 7100, isAnomaly: true, icon: "🏢" }
};

const WORLD_CONTINENTS = [
  // North America
  [
    [-168, 66], [-160, 58], [-140, 60], [-130, 54], [-124, 48], [-117, 32], [-110, 23],
    [-97, 20], [-97, 26], [-82, 23], [-80, 25], [-75, 35], [-70, 42], [-65, 45],
    [-60, 50], [-55, 52], [-60, 60], [-80, 72], [-100, 70], [-140, 70], [-168, 66]
  ],
  // Greenland
  [
    [-45, 60], [-35, 65], [-20, 75], [-30, 83], [-55, 80], [-55, 70], [-45, 60]
  ],
  // South America
  [
    [-77, 8], [-70, 12], [-60, 10], [-50, 0], [-35, -5], [-35, -10], [-40, -22],
    [-50, -30], [-55, -40], [-65, -55], [-75, -50], [-73, -40], [-70, -20], [-80, -5], [-77, 8]
  ],
  // Eurasia (Europe & Asia)
  [
    [-10, 36], [0, 43], [10, 45], [20, 40], [30, 40], [35, 30], [50, 25], [60, 25],
    [70, 22], [80, 10], [85, 20], [90, 22], [100, 15], [105, 10], [108, 22], [120, 25],
    [122, 38], [130, 43], [140, 50], [150, 60], [170, 65], [180, 67], [180, 72],
    [140, 75], [100, 78], [60, 70], [30, 71], [15, 65], [5, 60], [-5, 58], [-5, 50],
    [-10, 43], [-10, 36]
  ],
  // Africa
  [
    [-17, 15], [-17, 21], [-5, 36], [10, 37], [25, 32], [32, 31], [43, 12], [51, 12],
    [45, 0], [40, -10], [35, -25], [28, -34], [18, -34], [12, -20], [9, 5], [0, 6],
    [-15, 12], [-17, 15]
  ],
  // Australia
  [
    [114, -22], [125, -15], [136, -12], [142, -10], [145, -18], [153, -28],
    [150, -37], [140, -38], [130, -32], [115, -34], [114, -22]
  ],
  // Japan
  [
    [130, 32], [135, 34], [140, 36], [141, 41], [145, 44], [142, 45], [140, 42],
    [136, 36], [131, 33], [130, 32]
  ],
  // British Isles
  [
    [-5, 50], [-1, 51], [1, 53], [-2, 57], [-5, 58], [-5, 55], [-6, 51], [-5, 50]
  ]
];

let flightCanvasEngine = {
  canvas: null,
  ctx: null,
  animId: null,
  origin: { name: "New York", country: "USA", lat: 40.7128, lon: -74.0060, label: "New York (Baseline)" },
  dest: { ...GEO_PRESETS["Tokyo"] },
  startTime: Date.now()
};

function initGeoFlightCanvas() {
  const canvas = document.getElementById("geo-flight-canvas");
  if (!canvas) return;

  flightCanvasEngine.canvas = canvas;
  flightCanvasEngine.ctx = canvas.getContext("2d");

  // Resize handler with High-DPI support
  function handleResize() {
    if (!canvas || !canvas.parentElement) return;
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const width = rect.width || canvas.parentElement.clientWidth || 700;
    const height = 340;

    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    flightCanvasEngine.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  handleResize();
  window.removeEventListener("resize", handleResize);
  window.addEventListener("resize", handleResize);

  if (!flightCanvasEngine.animId) {
    runFlightLoop();
  }
}

function selectFlightRoute(cityName, lat, lon, velocityKmh, isAnomaly, btn) {
  const preset = GEO_PRESETS[cityName] || {
    name: cityName,
    country: "Remote",
    lat: lat,
    lon: lon,
    distKm: Math.round(velocityKmh * 1.25),
    speedKmh: velocityKmh,
    isAnomaly: isAnomaly,
    icon: isAnomaly ? "⚡" : "✓"
  };

  flightCanvasEngine.dest = { ...preset, lat, lon, speedKmh: velocityKmh, isAnomaly };
  flightCanvasEngine.startTime = Date.now();

  // Update button active state
  document.querySelectorAll(".flight-route-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");

  // Update tactical HUD
  updateFlightHud(preset);
}
window.selectFlightRoute = selectFlightRoute;

function updateFlightHud(dest) {
  const destEl = document.getElementById("hud-dest-val");
  const distEl = document.getElementById("hud-dist-val");
  const speedEl = document.getElementById("hud-speed-val");
  const badgeEl = document.getElementById("flight-risk-badge");

  const mach = (dest.speedKmh / 1234.8).toFixed(2);
  const latStr = `${Math.abs(dest.lat).toFixed(1)}°${dest.lat >= 0 ? 'N' : 'S'}`;
  const lonStr = `${Math.abs(dest.lon).toFixed(1)}°${dest.lon >= 0 ? 'E' : 'W'}`;

  if (destEl) {
    destEl.textContent = `${dest.icon || '📍'} ${dest.name}, ${dest.country} [${latStr}, ${lonStr}]`;
    destEl.className = dest.isAnomaly ? "hud-stat-value text-crimson" : "hud-stat-value text-emerald";
  }
  if (distEl) {
    distEl.textContent = `${dest.distKm.toLocaleString()} km (${Math.round(dest.distKm * 0.621371).toLocaleString()} mi)`;
  }
  if (speedEl) {
    speedEl.textContent = `${dest.speedKmh.toLocaleString()} km/h (Mach ${mach})`;
    speedEl.className = dest.isAnomaly ? "hud-stat-value font-mono text-crimson" : "hud-stat-value font-mono text-emerald";
  }
  if (badgeEl) {
    if (dest.isAnomaly) {
      badgeEl.className = "badge badge-critical font-mono";
      badgeEl.textContent = `⚡ IMPOSSIBLE FLIGHT: ${dest.speedKmh.toLocaleString()} KM/H`;
    } else {
      badgeEl.className = "badge badge-low font-mono";
      badgeEl.textContent = `✓ NOMINAL COMMUTE: < ${dest.speedKmh} KM/H`;
    }
  }
}

function drawFlightVisualizer(event) {
  if (!event) return;
  const cityName = event.geo?.city || "Tokyo";
  const preset = GEO_PRESETS[cityName];
  const isAnom = (event.risk_score || 0) >= 70;
  const speed = isAnom ? (event.telemetry?.velocity_kmh || 8500) : 45;

  if (preset) {
    flightCanvasEngine.dest = { ...preset, speedKmh: speed, isAnomaly: isAnom };
  } else {
    flightCanvasEngine.dest = {
      name: cityName,
      country: event.geo?.country || "Remote",
      lat: event.geo?.lat || 35.6762,
      lon: event.geo?.lon || 139.6503,
      distKm: event.telemetry?.distance_km || 10848,
      speedKmh: speed,
      isAnomaly: isAnom,
      icon: isAnom ? "⚡" : "✓"
    };
  }
  flightCanvasEngine.startTime = Date.now();
  updateFlightHud(flightCanvasEngine.dest);
}

function runFlightLoop() {
  const canvas = flightCanvasEngine.canvas;
  const ctx = flightCanvasEngine.ctx;

  if (!canvas || !ctx) {
    flightCanvasEngine.animId = requestAnimationFrame(runFlightLoop);
    return;
  }

  // Only render if SOC dashboard is active or tab is visible
  if (document.hidden) {
    flightCanvasEngine.animId = requestAnimationFrame(runFlightLoop);
    return;
  }

  const rect = canvas.getBoundingClientRect();
  const w = rect.width || canvas.width;
  const h = 340;

  // Clear canvas
  ctx.clearRect(0, 0, w, h);

  // 1. Deep Cyber Ocean Gradient
  const oceanGrad = ctx.createRadialGradient(w / 2, h / 2, 40, w / 2, h / 2, w * 0.7);
  oceanGrad.addColorStop(0, "rgba(10, 16, 30, 0.98)");
  oceanGrad.addColorStop(1, "rgba(4, 7, 14, 1.0)");
  ctx.fillStyle = oceanGrad;
  ctx.fillRect(0, 0, w, h);

  // Function to project [lon, lat] onto canvas
  function project(lon, lat) {
    return {
      x: ((lon + 180) / 360) * w,
      y: ((90 - lat) / 180) * h
    };
  }

  // 2. Latitude & Longitude Cyber Graticules
  ctx.lineWidth = 1;
  ctx.strokeStyle = "rgba(56, 189, 248, 0.05)";
  ctx.setLineDash([4, 6]);

  // Meridians every 30 degrees
  for (let lon = -180; lon <= 180; lon += 30) {
    const x = project(lon, 0).x;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }

  // Parallels
  const parallels = [60, 30, 0, -30, -60];
  for (const lat of parallels) {
    const y = project(0, lat).y;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }
  ctx.setLineDash([]);

  // Equator highlight line
  const eqY = project(0, 0).y;
  ctx.beginPath();
  ctx.moveTo(0, eqY);
  ctx.lineTo(w, eqY);
  ctx.strokeStyle = "rgba(255, 255, 255, 0.08)";
  ctx.lineWidth = 1.2;
  ctx.stroke();

  // 3. Cyber Continent Vector Outlines & Landmass Fill
  for (let c = 0; c < WORLD_CONTINENTS.length; c++) {
    const poly = WORLD_CONTINENTS[c];
    if (poly.length < 3) continue;

    ctx.beginPath();
    const startPt = project(poly[0][0], poly[0][1]);
    ctx.moveTo(startPt.x, startPt.y);

    for (let i = 1; i < poly.length; i++) {
      const pt = project(poly[i][0], poly[i][1]);
      ctx.lineTo(pt.x, pt.y);
    }
    ctx.closePath();

    // Landmass fill with glass tint
    ctx.fillStyle = "rgba(56, 189, 248, 0.045)";
    ctx.fill();

    // Landmass perimeter neon glow
    ctx.strokeStyle = "rgba(56, 189, 248, 0.28)";
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }

  // 4. Calculate Origin & Destination Coordinates
  const origPt = project(flightCanvasEngine.origin.lon, flightCanvasEngine.origin.lat);
  const destPt = project(flightCanvasEngine.dest.lon, flightCanvasEngine.dest.lat);
  const isAnom = flightCanvasEngine.dest.isAnomaly;
  const themeColor = isAnom ? "#ef4444" : "#10b981";
  const themeColorRgba = isAnom ? "rgba(239, 68, 68," : "rgba(16, 185, 129,";

  // Great-Circle Arc Geometry
  const midX = (origPt.x + destPt.x) / 2;
  const distCanvas = Math.hypot(destPt.x - origPt.x, destPt.y - origPt.y);
  const arcLift = Math.min(Math.max(distCanvas * 0.35, 45), 110);
  const ctrlY = Math.min(origPt.y, destPt.y) - arcLift;

  // 5. Draw Great-Circle Ballistic Flight Trajectory Arc
  // Ambient glow layer
  ctx.beginPath();
  ctx.moveTo(origPt.x, origPt.y);
  ctx.quadraticCurveTo(midX, ctrlY, destPt.x, destPt.y);
  ctx.strokeStyle = `${themeColorRgba} 0.22)`;
  ctx.lineWidth = 8;
  ctx.stroke();

  // Core dashed trajectory
  ctx.beginPath();
  ctx.moveTo(origPt.x, origPt.y);
  ctx.quadraticCurveTo(midX, ctrlY, destPt.x, destPt.y);
  ctx.strokeStyle = themeColor;
  ctx.lineWidth = 2.4;
  ctx.setLineDash([8, 6]);
  ctx.lineDashOffset = -(Date.now() / 32) % 28;
  ctx.stroke();
  ctx.setLineDash([]);

  // 6. Traveling Photon Energy Packet (Missile / Packet Animation)
  const animCycle = 2200; // ms per cycle
  const t = ((Date.now() - flightCanvasEngine.startTime) % animCycle) / animCycle;

  // Quadratic Bezier Formula: B(t) = (1-t)^2 * P0 + 2(1-t)t * P1 + t^2 * P2
  function getBezierPoint(p0, p1, p2, progress) {
    const u = 1 - progress;
    const tt = progress * progress;
    const uu = u * u;
    return {
      x: uu * p0.x + 2 * u * progress * p1.x + tt * p2.x,
      y: uu * p0.y + 2 * u * progress * p1.y + tt * p2.y
    };
  }

  const curPos = getBezierPoint(origPt, { x: midX, y: ctrlY }, destPt, t);

  // Traveling packet tail streak
  for (let i = 1; i <= 6; i++) {
    const tailT = Math.max(0, t - i * 0.025);
    const tailPos = getBezierPoint(origPt, { x: midX, y: ctrlY }, destPt, tailT);
    ctx.beginPath();
    ctx.arc(tailPos.x, tailPos.y, Math.max(1, 4 - i * 0.5), 0, Math.PI * 2);
    ctx.fillStyle = `${themeColorRgba} ${0.65 - i * 0.1})`;
    ctx.fill();
  }

  // Traveling projectile head
  ctx.beginPath();
  ctx.arc(curPos.x, curPos.y, 5, 0, Math.PI * 2);
  ctx.fillStyle = "#ffffff";
  ctx.shadowColor = themeColor;
  ctx.shadowBlur = 14;
  ctx.fill();
  ctx.shadowBlur = 0;

  // 7. Radar Ping Rings (Concentric Sonar Rings)
  const now = Date.now();
  const pingRadius1 = (now / 24) % 36;
  const pingAlpha1 = 1 - pingRadius1 / 36;
  const pingRadius2 = ((now + 600) / 24) % 36;
  const pingAlpha2 = 1 - pingRadius2 / 36;

  [origPt, destPt].forEach((p, idx) => {
    const isDest = idx === 1;
    const colorRgba = isDest ? themeColorRgba : "rgba(16, 185, 129,";

    // Ring 1
    ctx.beginPath();
    ctx.arc(p.x, p.y, pingRadius1, 0, Math.PI * 2);
    ctx.strokeStyle = `${colorRgba} ${pingAlpha1 * 0.8})`;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Ring 2
    ctx.beginPath();
    ctx.arc(p.x, p.y, pingRadius2, 0, Math.PI * 2);
    ctx.strokeStyle = `${colorRgba} ${pingAlpha2 * 0.6})`;
    ctx.lineWidth = 1.2;
    ctx.stroke();

    // Core Beacon Jewel Dot
    ctx.beginPath();
    ctx.arc(p.x, p.y, 6, 0, Math.PI * 2);
    ctx.fillStyle = isDest ? (isAnom ? "#ef4444" : "#10b981") : "#10b981";
    ctx.shadowColor = ctx.fillStyle;
    ctx.shadowBlur = 12;
    ctx.fill();
    ctx.shadowBlur = 0;

    // Luminous inner highlight
    ctx.beginPath();
    ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = "#ffffff";
    ctx.fill();
  });

  // 8. Ground Node Tactical Labels
  ctx.font = "bold 10px monospace";

  // Origin Label (New York)
  ctx.fillStyle = "#ffffff";
  ctx.fillText("🗽 NEW YORK (BASELINE)", origPt.x - 65, origPt.y + 18);

  // Destination Label
  const destName = flightCanvasEngine.dest.name.toUpperCase();
  const statusTag = isAnom ? "🚨 ANOMALOUS VECTOR" : "✓ NOMINAL";
  ctx.fillStyle = isAnom ? "#ff6b6b" : "#34d399";
  ctx.fillText(`${flightCanvasEngine.dest.icon || '📍'} ${destName} [${statusTag}]`, destPt.x - 75, destPt.y + 18);

  flightCanvasEngine.animId = requestAnimationFrame(runFlightLoop);
}

// Clear All Security & Login Events
async function clearSecurityEvents() {
  if (!confirm("Are you sure you want to clear all recorded login events and security incident history?")) return;
  try {
    const res = await apiFetch("/api/security/events/clear", { method: "POST" });
    if (res.ok) {
      showToast("All security & login events cleared.", "info");
      lastSocEventsSignature = "";
      await loadSecurityEvents(true);
      await loadSocMetrics();
    } else {
      showToast("Failed to clear security events.", "error");
    }
  } catch (err) {
    showToast("Error clearing security events.", "error");
  }
}
window.clearSecurityEvents = clearSecurityEvents;

