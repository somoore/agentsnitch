// ===========================================================================
// creatures-engine.js — CSS placeholder creature engine (FULL parity port).
// Body behind the render seam in creatures-bridge.js. When Rive lands, this
// file is what gets replaced; the bridge stays the same.
//
// Includes the full creature interaction set with cr- class names:
// mood/glow/snitch, cursor eye-tracking, hover poke, click tickle/pinch + quips,
// and drag-to-yank (pendulum swing, scared face, springy return).
//
// SECURITY: dynamic text (snitch/quip bubbles) uses textContent only — never
// innerHTML — so daemon-derived strings (destinations, names) can't inject markup.
// ===========================================================================

const MOOD_COLOR = { idle: '#6E9BBE', working: '#4F8FD6', reaching: '#E0A23C', caught: '#D9694A', asleep: '#5E6B78' };
const MOOD_LABEL = { idle: 'idle', working: 'working', reaching: 'reaching out', caught: 'caught something', asleep: 'asleep' };

// randomized quip pools — flavored by mood + tickle/pinch
const QUIPS = {
  idle: { tickle: ['heehee!', 'that tickles!', 'hee — stop it', 'oh! hi.', '*giggles*'],
          pinch: ['ow! rude.', 'hey!', 'I felt that.', 'what did I do?', 'pinched!'] },
  working: { tickle: ['heh — I’m working here', 'busy busy!', 'careful, I’m editing', '*snrk* not now'],
             pinch: ['ow! lost my place.', 'I was mid-edit!', 'hey, focus!', 'pinched mid-commit'] },
  reaching: { tickle: ['hee — mid-request!', 'one sec, fetching…', 'tickle later, sending now'],
              pinch: ['ow! dropped a packet.', 'hey, I was connecting!', 'rude — mid-handshake'] },
  caught: { tickle: ['this isn’t funny', 'okay okay I saw it too', 'don’t poke the snitch', '*nervous giggle*'],
            pinch: ['I SAW it leave, okay?!', 'don’t shoot the messenger!', 'ow — I’m just reporting!', 'it wasn’t me, I swear'] },
  asleep: ['…five more minutes', '*yawn* what?', 'huh— who’s there?', 'I’m up, I’m up.'],
};

function earsHTML(species) {
  if (species === 'horn') return '<div class="cr-ear horn l"></div><div class="cr-ear horn r"></div>';
  if (species === 'round') return '<div class="cr-ear round l"></div><div class="cr-ear round r"></div>';
  if (species === 'antenna') return '<div class="cr-antenna"><span class="cr-bulb"></span></div>';
  return '<div class="cr-ear l"></div><div class="cr-ear r"></div>';
}
// Static template only (no interpolated data) — safe innerHTML.
function critterInnerHTML(species) {
  return `${earsHTML(species)}
    <div class="cr-headshape"></div>
    <div class="cr-brow l"></div><div class="cr-brow r"></div>
    <div class="cr-eye l"><div class="cr-pupil"></div><div class="cr-lid"></div></div>
    <div class="cr-eye r"><div class="cr-pupil"></div><div class="cr-lid"></div></div>
    <div class="cr-mouth line"></div>
    <div class="cr-zzz"><span>z</span><span>Z</span><span>Z</span></div>`;
}

const ALL_ENGINES = [];
let DRAG_LAYER = null;
function ensureDragLayer() {
  if (DRAG_LAYER && document.body.contains(DRAG_LAYER)) return DRAG_LAYER;
  DRAG_LAYER = document.createElement('div'); DRAG_LAYER.className = 'cr-draglayer';
  document.body.appendChild(DRAG_LAYER); return DRAG_LAYER;
}

class CSSCreatureEngine {
  constructor(penEl, skin) {
    this.el = penEl; this.skin = skin;
    this.critter = penEl.querySelector('.cr-critter');
    this.glow = penEl.querySelector('.cr-glow');
    this.chipDot = penEl.querySelector('.cr-dot');
    this.mouth = penEl.querySelector('.cr-mouth');
    this.headShape = penEl.querySelector('.cr-headshape');
    this.browL = penEl.querySelector('.cr-brow.l'); this.browR = penEl.querySelector('.cr-brow.r');
    this.pupils = penEl.querySelectorAll('.cr-pupil');
    this.eyes = penEl.querySelectorAll('.cr-eye');
    this.lids = penEl.querySelectorAll('.cr-lid');
    this.bubble = penEl.querySelector('.cr-bubble');
    this._arena = penEl.querySelector('.cr-arena') || this.critter.parentElement;
    this.mood = 'idle';
    ALL_ENGINES.push(this);
    this._wireInteractions();
    this._blinkLoop(); this._saccadeLoop();
  }

  // ---- mood / state ----
  setMood(m) {
    this.mood = m;
    const col = MOOD_COLOR[m] || MOOD_COLOR.idle;
    this.critter.className = 'cr-critter m-' + m;
    if (this.glow) { this.glow.style.setProperty('--mood-color', col); this.glow.style.opacity = (m === 'caught' ? 0.34 : m === 'reaching' ? 0.26 : m === 'asleep' ? 0.05 : 0.18); }
    if (this.chipDot) this.chipDot.style.background = col;
    const sk = (m === 'caught');
    this.browL.style.transform = sk ? 'rotate(16deg)' : 'rotate(0deg)';
    this.browR.style.transform = sk ? 'rotate(-16deg)' : 'rotate(0deg)';
    this.mouth.className = 'cr-mouth ' + (m === 'caught' ? 'grin' : m === 'working' ? 'flat' : m === 'asleep' ? 'sleep' : 'line');
    this.eyes.forEach(e => e.style.transform = (m === 'caught' ? 'scale(1.12)' : 'scale(1)'));
    const asleep = (m === 'asleep');
    this.lids.forEach(l => l.style.transform = asleep ? 'scaleY(1)' : 'scaleY(0)');
    this.el.querySelector('.cr-zzz').classList.toggle('show', asleep);
    this.el.style.opacity = asleep ? 0.7 : 1;
    if (!asleep && m !== 'caught') this.hideSnitch();
  }
  setNet(v) {
    if (!this.glow) return;
    const o = 0.12 + (v / 100) * 0.4;
    if (this.mood !== 'asleep') this.glow.style.opacity = Math.max(o, this.mood === 'caught' ? 0.34 : 0.12);
    this.glow.style.animationDuration = (3.6 - (v / 100) * 2.0).toFixed(2) + 's';
  }
  // SECURITY: textContent only. Remember the standing snitch so quips can restore it.
  snitch(text, meta) {
    if (!this.bubble) return;
    this._standingBubble = { text, meta };
    this.bubble.classList.remove('cr-quip');
    this.bubble.textContent = '';
    const t = document.createElement('div'); t.className = 'cr-bubble-text'; t.textContent = text;
    const m = document.createElement('div'); m.className = 'cr-bubble-meta'; m.textContent = meta || '';
    this.bubble.appendChild(t); this.bubble.appendChild(m);
    this.bubble.classList.add('show');
  }
  hideSnitch() { if (this.bubble) { this.bubble.classList.remove('show'); this._standingBubble = null; } }

  // ---- micro animations ----
  blink() { if (this.mood === 'asleep') return; this.critter.classList.add('blinking'); setTimeout(() => this.critter.classList.remove('blinking'), 240); }
  react() { this.critter.classList.add('cr-react-pop'); setTimeout(() => this.critter.classList.remove('cr-react-pop'), 440); }
  look(x, y) {
    if (this.mood === 'asleep' || this.dragging) return;
    this.pupils.forEach(p => p.style.transform = `translate(calc(-50% + ${x * 10}px), calc(-50% + ${y * 9}px))`);
    this.eyes.forEach(e => { const base = (this.mood === 'caught') ? 1.12 : 1; e.style.transform = `translate(${x * 2}px, ${y * 1.5}px) scale(${base})`; });
    if (this.headShape) this.headShape.style.transform = `translate(${x * 5}px, ${y * 4}px) rotate(${x * 4}deg)`;
  }
  lookAt(px, py) {
    if (this.mood === 'asleep' || this.dragging) return;
    const r = this.critter.getBoundingClientRect(); if (!r.width) return;
    const cx = r.left + r.width / 2, cy = r.top + r.height * 0.42;
    let dx = (px - cx) / 180, dy = (py - cy) / 180;
    const mag = Math.hypot(dx, dy) || 1, clamp = Math.min(1, mag);
    this.look(dx / mag * clamp, dy / mag * clamp); this._cursorDriven = true;
  }

  // ---- hover poke ----
  poke() {
    if (this.dragging) return;
    if (this.mood === 'asleep') { this.lids.forEach((l, i) => { if (i === 0) { l.style.transform = 'scaleY(0.4)'; setTimeout(() => l.style.transform = 'scaleY(1)', 600); } }); return; }
    const moves = ['wiggle', 'boing', 'spin-eyes', 'big-blink', 'blush'];
    const pick = moves[Math.floor(Math.random() * moves.length)];
    if (pick === 'wiggle') {
      this.critter.animate([
        { transform: 'translate(-50%,-50%) rotate(0)' }, { transform: 'translate(-50%,-50%) rotate(7deg)' },
        { transform: 'translate(-50%,-50%) rotate(-7deg)' }, { transform: 'translate(-50%,-50%) rotate(0)' }], { duration: 420, easing: 'ease-in-out' });
    } else if (pick === 'boing') { this.react(); }
    else if (pick === 'spin-eyes') { let n = 0; const iv = setInterval(() => { const a = n * Math.PI / 2; this.look(Math.cos(a) * 0.9, Math.sin(a) * 0.9); if (++n > 4) clearInterval(iv); }, 90); }
    else if (pick === 'big-blink') { this.lids.forEach(l => { l.style.transition = 'transform .12s'; l.style.transform = 'scaleY(1)'; setTimeout(() => l.style.transform = 'scaleY(0)', 150); }); }
    else if (pick === 'blush') { [0, 1].forEach(i => { const b = document.createElement('div'); b.style.cssText = `position:absolute;top:88px;${i ? 'right' : 'left'}:22px;width:16px;height:9px;border-radius:9px;background:#E89B82;opacity:.7;filter:blur(1px);`; this.critter.appendChild(b); setTimeout(() => b.remove(), 900); }); }
  }

  // ---- click: tickle / pinch + quip ----
  tickleOrPinch() {
    if (this.mood === 'asleep') { this._quip(QUIPS.asleep); this.setMood('idle'); this._jiggle(); return; }
    const kind = Math.random() < 0.5 ? 'tickle' : 'pinch';
    if (kind === 'tickle') this._tickle(); else this._pinch();
    const pool = (QUIPS[this.mood] && QUIPS[this.mood][kind]) || QUIPS.idle[kind];
    this._quip(pool);
  }
  _tickle() {
    this.mouth.className = 'cr-mouth grin';
    this.critter.animate([
      { transform: 'translate(-50%,-50%) rotate(0) scale(1)' }, { transform: 'translate(-50%,-52%) rotate(5deg) scale(1.05,.96)' },
      { transform: 'translate(-50%,-50%) rotate(-5deg) scale(.97,1.04)' }, { transform: 'translate(-50%,-52%) rotate(4deg) scale(1.04,.97)' },
      { transform: 'translate(-50%,-50%) rotate(0) scale(1)' }], { duration: 520, easing: 'ease-in-out' }).onfinish = () => this.setMood(this.mood);
    [0, 1].forEach(i => { const b = document.createElement('div'); b.style.cssText = `position:absolute;top:90px;${i ? 'right' : 'left'}:22px;width:16px;height:9px;border-radius:9px;background:#E89B82;opacity:.75;filter:blur(1px);`; this.critter.appendChild(b); setTimeout(() => b.remove(), 900); });
  }
  _pinch() {
    this.critter.animate([
      { transform: 'translate(-50%,-50%) scale(1)' }, { transform: 'translate(-50%,-48%) scale(1.14,.84)' },
      { transform: 'translate(-50%,-50%) scale(.92,1.08)' }, { transform: 'translate(-50%,-50%) scale(1)' }], { duration: 420, easing: 'cubic-bezier(.3,1.5,.5,1)' }).onfinish = () => this.setMood(this.mood);
    this.eyes.forEach(e => { e.style.transform = 'scaleY(.55)'; setTimeout(() => e.style.transform = '', 300); });
  }
  _jiggle() { this.critter.animate([{ transform: 'translate(-50%,-50%) rotate(-4deg)' }, { transform: 'translate(-50%,-50%) rotate(4deg)' }, { transform: 'translate(-50%,-50%) rotate(0)' }], { duration: 380, easing: 'ease-in-out' }); }
  // SECURITY: textContent only.
  _quip(pool) {
    if (!this.bubble || !pool || !pool.length) return;
    const text = pool[Math.floor(Math.random() * pool.length)];
    this.bubble.textContent = text;
    this.bubble.classList.add('show', 'cr-quip');
    clearTimeout(this._quipT);
    this._quipT = setTimeout(() => {
      this.bubble.classList.remove('show', 'cr-quip');
      if (this._standingBubble) this.snitch(this._standingBubble.text, this._standingBubble.meta);
    }, 2200);
  }

  // ---- drag: yank out, dangle scared, springy return ----
  setScared(on) {
    if (on) {
      this.browL.style.transform = 'rotate(-22deg)'; this.browR.style.transform = 'rotate(22deg)';
      this.browL.style.top = '42px'; this.browR.style.top = '42px';
      this.mouth.className = 'cr-mouth scared';
      this.eyes.forEach(e => e.style.transform = 'scale(1.18)');
      if (!this.critter.querySelector('.cr-sweat')) { const s = document.createElement('div'); s.className = 'cr-sweat'; this.critter.appendChild(s); }
    } else { const s = this.critter.querySelector('.cr-sweat'); if (s) s.remove(); }
  }
  startDrag(e) {
    this.dragging = true; this._dragMoved = false;
    this._home = this.critter.getBoundingClientRect();
    this._dragScale = this._home.width / 150 || 1;
    const cs = getComputedStyle(this.critter);
    ['--c-base', '--c-light', '--c-dark'].forEach(v => this.critter.style.setProperty(v, cs.getPropertyValue(v).trim()));
    this.critter.classList.remove('m-idle', 'm-working', 'm-reaching', 'm-caught', 'm-asleep');
    this.critter.style.animation = 'none';
    this.hideSnitch();
    ensureDragLayer().appendChild(this.critter);
    this.critter.classList.add('dragging');
    this._cx = e.clientX; this._cy = e.clientY; this._vx = 0; this._ang = 0; this._angV = 0;
    this._lastT = performance.now();
    this._place(e.clientX, e.clientY, 0);
    this.setScared(true);
    try { this.critter.setPointerCapture(e.pointerId); } catch (_) {}
    this._physics();
  }
  _place(x, y, ang) {
    const s = this._dragScale || 1;
    this.critter.style.left = (x - 75 * s) + 'px';
    this.critter.style.top = (y - 26 * s) + 'px';
    this.critter.style.transformOrigin = '50% 8%';
    this.critter.style.transform = `rotate(${ang}deg) scale(${s})`;
  }
  _physics() {
    if (!this.dragging) return;
    const now = performance.now(); const dt = Math.min(40, now - this._lastT) / 16.7; this._lastT = now;
    const target = Math.max(-32, Math.min(32, -this._vx * 2.4));
    this._angV += (target - this._ang) * 0.14 * dt; this._angV *= Math.pow(0.82, dt); this._ang += this._angV * dt;
    this._vx *= Math.pow(0.86, dt);
    this._place(this._cx, this._cy, this._ang);
    const pv = Math.max(-1, Math.min(1, -this._ang / 24));
    this.pupils.forEach(p => p.style.transform = `translate(calc(-50% + ${pv * 9}px), calc(-50% + 5px))`);
    this._raf = requestAnimationFrame(() => this._physics());
  }
  onDragMove(e) {
    if (!this.dragging) return;
    if (Math.abs(e.movementX) > 0.5 || Math.abs(e.movementY) > 0.5) this._dragMoved = true;
    this._vx = this._vx * 0.5 + (e.movementX || 0) * 0.5;
    this._cx = e.clientX; this._cy = e.clientY;
  }
  endDrag(e) {
    if (!this.dragging) return;
    this.dragging = false;
    if (this._raf) cancelAnimationFrame(this._raf);
    try { this.critter.releasePointerCapture(e.pointerId); } catch (_) {}
    if (!this._dragMoved) { this._returnHome(() => this.tickleOrPinch()); return; }
    this._returnHome(() => { this.setScared(false); this._phew(); this.setMood(this.mood); });
  }
  _returnHome(done) {
    const r = this._home;
    const curX = parseFloat(this.critter.style.left) || r.left, curY = parseFloat(this.critter.style.top) || r.top;
    this.critter.style.left = r.left + 'px'; this.critter.style.top = r.top + 'px';
    const dx = curX - r.left, dy = curY - r.top, a0 = this._ang || 0, s = this._dragScale || 1;
    const tf = (tx, ty, rot) => `translate(${tx}px,${ty}px) rotate(${rot}deg) scale(${s})`;
    const anim = this.critter.animate([
      { transform: tf(dx, dy, a0), offset: 0, easing: 'cubic-bezier(.5,0,.3,1)' },
      { transform: tf(-dx * 0.06, -dy * 0.10, -a0 * 0.25), offset: .55, easing: 'ease-out' },
      { transform: tf(dx * 0.02, dy * 0.03, 6), offset: .72 },
      { transform: tf(0, 0, -4), offset: .85 }, { transform: tf(0, 0, 2), offset: .94 }, { transform: tf(0, 0, 0), offset: 1 }],
      { duration: 560, easing: 'ease-out' });
    let finished = false;
    const finish = () => {
      if (finished) return; finished = true;
      this.critter.classList.remove('dragging');
      this.critter.style.left = ''; this.critter.style.top = ''; this.critter.style.transform = ''; this.critter.style.animation = '';
      this.critter.style.removeProperty('--c-base'); this.critter.style.removeProperty('--c-light'); this.critter.style.removeProperty('--c-dark');
      this._arena.appendChild(this.critter);
      this.pupils.forEach(p => p.style.transform = '');
      if (done) done();
    };
    anim.onfinish = finish; setTimeout(finish, 640);
  }
  _phew() {
    const p = document.createElement('div'); p.className = 'cr-phew go'; p.textContent = 'phew…';
    this.critter.appendChild(p);
    this.browL.animate([{ transform: 'translateX(0)' }, { transform: 'translateX(18px)' }, { transform: 'translateX(0)' }], { duration: 600, easing: 'ease-in-out' });
    setTimeout(() => p.remove(), 1000);
    this._quip(['that was close.', 'phew. back to work.', 'don’t do that again', 'okay. where was I.']);
  }

  // ---- event wiring (per creature) ----
  _wireInteractions() {
    const crt = this.critter; crt.style.cursor = 'grab';
    if (this._arena) this._arena.addEventListener('mouseenter', () => { if (!this.dragging) this.poke(); });
    crt.addEventListener('pointerdown', (e) => { e.preventDefault(); e.stopPropagation(); this.startDrag(e); });
    crt.addEventListener('pointermove', (e) => this.onDragMove(e));
    crt.addEventListener('pointerup', (e) => this.endDrag(e));
    crt.addEventListener('pointercancel', (e) => this.endDrag(e));
  }

  _blinkLoop() { const t = () => { this.blink(); setTimeout(t, 2500 + Math.random() * 3500); }; setTimeout(t, 1000 + Math.random() * 2000); }
  _saccadeLoop() { const t = () => { if (!this._cursorDriven && !this.dragging && this.mood !== 'asleep') this.look((Math.random() * 2 - 1) * 0.5, (Math.random() * 2 - 1) * 0.4); setTimeout(t, 1300 + Math.random() * 1600); }; setTimeout(t, 800); }
}

// global cursor tracking — every creature watches the pointer
let _lastMove = 0;
document.addEventListener('mousemove', e => {
  _lastMove = Date.now();
  ALL_ENGINES.forEach(c => { if (c.el.offsetParent !== null) c.lookAt(e.clientX, e.clientY); });
});
setInterval(() => { if (Date.now() - _lastMove > 1600) ALL_ENGINES.forEach(c => { if (c._cursorDriven) { c._cursorDriven = false; if (c.headShape) c.headShape.style.transform = ''; c.look(0, 0); } }); }, 500);
