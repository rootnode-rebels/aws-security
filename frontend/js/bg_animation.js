// ==========================================================================
// iOS / visionOS LIQUID GLASS ILLUMINATION & OPTICAL CAUSTICS ENGINE
// Aesthetics: 100% Achromatic Monochromatic Obsidian Void with Dynamic Light:
// Overhead Studio Sun, Volumetric Refractive Blooms, Fluid Optical Caustics,
// and Real-Time Specular Cursor Light Reflections across Glass Panels
// ZERO BLUE TINT - PURE LUMINOUS OPTICAL GLASS
// ==========================================================================

class LiquidGlassBackground {
  constructor() {
    this.canvas = document.getElementById('cyber-bg');
    if (!this.canvas) return;

    this.ctx = this.canvas.getContext('2d', { alpha: true });
    this.blooms = [];
    this.caustics = [];
    this.causticRibbons = [];
    this.mouse = { x: -1000, y: -1000, targetX: -1000, targetY: -1000 };
    this.mouseLag = { x: -1000, y: -1000 };
    this.ripples = [];
    this.lastRippleX = -1000;
    this.lastRippleY = -1000;
    this.animId = null;
    this.isPaused = false;
    this.time = 0;

    this.init();

    // Throttled resize
    let resizeTimeout;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => this.resize(), 100);
    }, { passive: true });

    // Smooth interactive liquid lens tracking + ripple generator + card specular updater
    window.addEventListener('mousemove', (e) => {
      this.mouse.targetX = e.clientX;
      this.mouse.targetY = e.clientY;
      if (this.mouse.x === -1000) {
        this.mouse.x = e.clientX;
        this.mouse.y = e.clientY;
        this.mouseLag.x = e.clientX;
        this.mouseLag.y = e.clientY;
      }

      // Spawn subtle expanding liquid surface ripples when moving across the canvas (low frequency)
      const dx = e.clientX - this.lastRippleX;
      const dy = e.clientY - this.lastRippleY;
      if (dx * dx + dy * dy > 3600 && this.ripples.length < 5) {
        this.lastRippleX = e.clientX;
        this.lastRippleY = e.clientY;
        this.ripples.push({
          x: e.clientX,
          y: e.clientY,
          radius: 15,
          maxRadius: 260,
          alpha: 0.16,
          speed: 2.2,
          lineWidth: 22
        });
      }

      // High-performance single-element card specular update via event delegation
      this.updateCardSpecular(e);
    }, { passive: true });

    window.addEventListener('mouseout', () => {
      this.mouse.targetX = -1000;
      this.mouse.targetY = -1000;
    }, { passive: true });

    // Energy saving: Pause animation when tab is inactive
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.isPaused = true;
        if (this.animId) cancelAnimationFrame(this.animId);
      } else {
        this.isPaused = false;
        this.animate();
      }
    });

    this.animate();
  }

  updateCardSpecular(e) {
    if (!e || !e.target) return;
    const card = e.target.closest
      ? e.target.closest('.glass-panel, .cyber-card, .bento-card, .scenario-card, .compliance-card, .portal-hud-bar, .navbar, .alert-card, .portal-section-card')
      : null;
    if (card) {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    }
  }

  resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.width = window.innerWidth;
    this.height = window.innerHeight;
    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.ctx.scale(dpr, dpr);
    this.initLighting();
  }

  initLighting() {
    const w = this.width;
    const h = this.height;

    // 1. Primary Volumetric Refractive Light Pools (Luminous White & Platinum)
    this.blooms = [
      {
        baseX: w * 0.18, baseY: h * 0.22,
        radius: Math.max(w, h) * 0.48,
        speedX: 0.00035, speedY: 0.00028,
        phase: 0, ampX: w * 0.14, ampY: h * 0.12,
        r: 255, g: 255, b: 255, alpha: 0.32
      },
      {
        baseX: w * 0.82, baseY: h * 0.26,
        radius: Math.max(w, h) * 0.52,
        speedX: 0.00028, speedY: 0.00032,
        phase: 1.8, ampX: w * 0.16, ampY: h * 0.14,
        r: 250, g: 250, b: 255, alpha: 0.28
      },
      {
        baseX: w * 0.50, baseY: h * 0.65,
        radius: Math.max(w, h) * 0.56,
        speedX: 0.00030, speedY: 0.00024,
        phase: 3.6, ampX: w * 0.18, ampY: h * 0.15,
        r: 255, g: 255, b: 255, alpha: 0.26
      },
      {
        baseX: w * 0.12, baseY: h * 0.85,
        radius: Math.max(w, h) * 0.42,
        speedX: 0.00038, speedY: 0.00030,
        phase: 5.1, ampX: w * 0.12, ampY: h * 0.10,
        r: 248, g: 248, b: 252, alpha: 0.22
      },
      {
        baseX: w * 0.88, baseY: h * 0.80,
        radius: Math.max(w, h) * 0.45,
        speedX: 0.00032, speedY: 0.00026,
        phase: 2.7, ampX: w * 0.13, ampY: h * 0.12,
        r: 255, g: 255, b: 255, alpha: 0.24
      }
    ];

    // 2. Undulating Fluid Caustic Light Ribbons (Simulating Light Refracting Through Curved Glass)
    this.causticRibbons = [
      { yRatio: 0.25, amp: 65, freq: 0.0018, speed: 0.0004, alpha: 0.14 },
      { yRatio: 0.55, amp: 80, freq: 0.0015, speed: -0.00035, alpha: 0.12 },
      { yRatio: 0.80, amp: 70, freq: 0.0020, speed: 0.00045, alpha: 0.13 }
    ];

    // 3. Ambient Micro-refraction Floating Dust Motes (Neutral Silver Photons)
    this.caustics = [];
    const nodeCount = Math.floor(Math.min(w, 1400) / 65);
    for (let i = 0; i < nodeCount; i++) {
      this.caustics.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        radius: Math.random() * 1.8 + 0.8,
        alpha: Math.random() * 0.35 + 0.15,
        pulseSpeed: Math.random() * 0.018 + 0.008,
        pulseOffset: Math.random() * Math.PI * 2
      });
    }
  }

  init() {
    this.resize();
  }

  animate() {
    if (this.isPaused) return;

    this.time += 1;
    const w = this.width;
    const h = this.height;

    // Smooth dual-phase liquid cursor interpolation
    if (this.mouse.targetX !== -1000) {
      this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.045;
      this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.045;
      if (this.mouseLag.x === -1000) {
        this.mouseLag.x = this.mouse.x;
        this.mouseLag.y = this.mouse.y;
      } else {
        this.mouseLag.x += (this.mouse.x - this.mouseLag.x) * 0.022;
        this.mouseLag.y += (this.mouse.y - this.mouseLag.y) * 0.022;
      }
    }

    this.ctx.clearRect(0, 0, w, h);

    // ========================================================================
    // 1. PRIMARY OVERHEAD STUDIO LIGHT EMITTER (Calm, Deep Ambient Sun)
    // ========================================================================
    const sunRadius = Math.max(w * 0.75, 900);
    const sunPulse = 0.28 + Math.sin(this.time * 0.003) * 0.02;
    const sunGrad = this.ctx.createRadialGradient(
      w * 0.5, -50, 0,
      w * 0.5, -50, sunRadius
    );
    sunGrad.addColorStop(0, `rgba(255, 255, 255, ${sunPulse})`);
    sunGrad.addColorStop(0.30, `rgba(255, 255, 255, ${sunPulse * 0.50})`);
    sunGrad.addColorStop(0.65, `rgba(255, 255, 255, ${sunPulse * 0.15})`);
    sunGrad.addColorStop(1, 'rgba(255, 255, 255, 0)');

    this.ctx.fillStyle = sunGrad;
    this.ctx.beginPath();
    this.ctx.arc(w * 0.5, -50, sunRadius, 0, Math.PI * 2);
    this.ctx.fill();

    // ========================================================================
    // 2. VOLUMETRIC REFRACTIVE LIGHT BLOOMS (Liquid Internal Glow)
    // ========================================================================
    for (let i = 0; i < this.blooms.length; i++) {
      const b = this.blooms[i];
      let x = b.baseX + Math.sin(this.time * b.speedX + b.phase) * b.ampX;
      let y = b.baseY + Math.cos(this.time * b.speedY + b.phase) * b.ampY;

      // Interactive gentle refraction pull towards cursor
      if (this.mouse.targetX !== -1000) {
        const dx = this.mouse.x - x;
        const dy = this.mouse.y - y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 750 && dist > 1) {
          const force = (1 - dist / 750) * 26;
          x += (dx / dist) * force;
          y += (dy / dist) * force;
        }
      }

      const grad = this.ctx.createRadialGradient(x, y, 0, x, y, b.radius);
      grad.addColorStop(0, `rgba(${b.r}, ${b.g}, ${b.b}, ${b.alpha})`);
      grad.addColorStop(0.40, `rgba(${b.r}, ${b.g}, ${b.b}, ${b.alpha * 0.50})`);
      grad.addColorStop(0.75, `rgba(${b.r}, ${b.g}, ${b.b}, ${b.alpha * 0.15})`);
      grad.addColorStop(1, `rgba(${b.r}, ${b.g}, ${b.b}, 0)`);

      this.ctx.fillStyle = grad;
      this.ctx.beginPath();
      this.ctx.arc(x, y, b.radius, 0, Math.PI * 2);
      this.ctx.fill();
    }

    // ========================================================================
    // 3. FLUID HARMONIC CAUSTIC RIBBONS (Light Refracting Through Liquid Glass)
    // ========================================================================
    this.ctx.save();
    for (let r = 0; r < this.causticRibbons.length; r++) {
      const cr = this.causticRibbons[r];
      const baseCy = h * cr.yRatio;
      
      this.ctx.beginPath();
      this.ctx.moveTo(0, baseCy);
      
      const segments = 10;
      const segWidth = w / segments;
      for (let s = 0; s <= segments; s++) {
        const px = s * segWidth;
        const wave1 = Math.sin(this.time * cr.speed + px * cr.freq) * cr.amp;
        const wave2 = Math.cos(this.time * (cr.speed * 1.6) + px * (cr.freq * 2.1) + s) * (cr.amp * 0.35);
        const py = baseCy + wave1 + wave2;

        if (s === 0) {
          this.ctx.moveTo(px, py);
        } else {
          const prevX = (s - 1) * segWidth;
          const prevWave1 = Math.sin(this.time * cr.speed + prevX * cr.freq) * cr.amp;
          const prevWave2 = Math.cos(this.time * (cr.speed * 1.6) + prevX * (cr.freq * 2.1) + (s - 1)) * (cr.amp * 0.35);
          const prevY = baseCy + prevWave1 + prevWave2;
          const cpx = (prevX + px) / 2;
          const cpy = (prevY + py) / 2;
          this.ctx.quadraticCurveTo(prevX, prevY, cpx, cpy);
        }
      }

      // Fast multi-layer optical glow without CPU blur rasterization
      // Layer 1: Wide diffuse atmospheric halo
      this.ctx.strokeStyle = `rgba(255, 255, 255, ${cr.alpha * 0.12})`;
      this.ctx.lineWidth = 64;
      this.ctx.stroke();

      // Layer 2: Medium refractive caustic body
      this.ctx.strokeStyle = `rgba(255, 255, 255, ${cr.alpha * 0.38})`;
      this.ctx.lineWidth = 24;
      this.ctx.stroke();

      // Layer 3: Concentrated luminous core filament
      this.ctx.strokeStyle = `rgba(255, 255, 255, ${cr.alpha * 0.88})`;
      this.ctx.lineWidth = 5;
      this.ctx.stroke();
    }
    this.ctx.restore();

    // ========================================================================
    // 4. SUBTLE INTERACTIVE CYBER CONSTELLATION & PARTICLE DRIFT
    // ========================================================================
    for (let i = 0; i < this.caustics.length; i++) {
      const c = this.caustics[i];

      // Subtle mouse deflection (gentle repulsion without any circular artifacts)
      if (this.mouse.targetX !== -1000) {
        const dx = c.x - this.mouse.x;
        const dy = c.y - this.mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140 && dist > 1) {
          const force = (1 - dist / 140) * 1.8;
          c.x += (dx / dist) * force;
          c.y += (dy / dist) * force;
        }
      }

      c.x += c.vx;
      c.y += c.vy;

      if (c.x < 0) c.x = w;
      else if (c.x > w) c.x = 0;
      if (c.y < 0) c.y = h;
      else if (c.y > h) c.y = 0;

      const currentAlpha = c.alpha * (0.65 + 0.35 * Math.sin(this.time * c.pulseSpeed + c.pulseOffset));

      this.ctx.beginPath();
      this.ctx.arc(c.x, c.y, c.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = `rgba(255, 255, 255, ${currentAlpha})`;
      this.ctx.fill();

      // Subtle delicate connecting filaments between nearby drifting photons
      for (let j = i + 1; j < this.caustics.length; j++) {
        const c2 = this.caustics[j];
        const cdx = c.x - c2.x;
        const cdy = c.y - c2.y;
        const cdistSq = cdx * cdx + cdy * cdy;
        if (cdistSq < 6400) { // < 80px
          const lineAlpha = (1 - Math.sqrt(cdistSq) / 80) * 0.10;
          this.ctx.beginPath();
          this.ctx.moveTo(c.x, c.y);
          this.ctx.lineTo(c2.x, c2.y);
          this.ctx.strokeStyle = `rgba(56, 189, 248, ${lineAlpha})`;
          this.ctx.lineWidth = 0.7;
          this.ctx.stroke();
        }
      }
    }

    this.animId = requestAnimationFrame(() => this.animate());
  }
}

// Global initialization
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new LiquidGlassBackground());
} else {
  new LiquidGlassBackground();
}
