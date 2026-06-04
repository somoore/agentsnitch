// ===========================================================================
// creatures-bridge.js — the creature-view integration bridge.
//
// Consumes the app's existing read-only status contract:
//   invoke('get_status') -> { agents[], recent[], summary, active, ... }
//   listen('status-changed', cb)
// derives a per-agent creature STATE, and renders via the CreatureView seam.
//
// The render seam (CreatureView) is where Rive drops in later:
//   today  -> CSS creature (creatures-engine.js)
//   later  -> new rive.Rive({ src:'assets/Snitch.riv' }); machine.setInput(...)
//   (see docs/creature-rive-editor-guide.md and docs/creature-animation-rive-plan.md)
//
// Nothing here couples to the existing UI's render code — agents/hierarchy come
// straight from st.agents, which the app already computes (main/sub + liveness).
// ===========================================================================

// ---- Tauri access (same helpers the app uses) -----------------------------
function getTauri() { return window.__TAURI__ || null; }
async function invoke(cmd, args = {}) {
  const t = getTauri();
  if (t && t.core && t.core.invoke) return t.core.invoke(cmd, args);
  throw new Error('Tauri invoke unavailable (running outside Tauri?)');
}
async function listen(name, cb) {
  const t = getTauri();
  if (t && t.event && t.event.listen) return t.event.listen(name, cb);
  return null;
}

// ---- mood derivation (spec: docs/creature-animation-rive-plan.md §4) ------
// Reduce an agent's recent events into a creature state.
const MOOD = { IDLE: 'idle', WORKING: 'working', REACHING: 'reaching', CAUGHT: 'caught', ASLEEP: 'asleep' };

function isEgressEvent(ev) {
  const tool = String(ev.tool || '');
  if (/^mcp__/i.test(tool) || tool === 'WebFetch' || tool === 'WebSearch') return true;
  return (ev.tags || []).some(t => t === 'external_egress_attempt' || t === 'mcp_tool_use');
}
function isCaughtEvent(ev) {
  if (ev.correlated && ev.reasons) return ev.reasons.includes('after_sensitive_read');
  return false;
}

// Build a map agentId -> { mood, net, lastDestination, caughtSummary }
function deriveCreatureStates(st) {
  const agents = st.agents || [];
  const recent = st.recent || [];
  const byId = {};
  agents.forEach(a => { byId[a.id] = { agent: a, mood: MOOD.IDLE, net: 0, dest: null, caught: null }; });

  // mood precedence: caught > reaching > working > idle (never downgrade)
  const RANK = { idle: 0, working: 1, reaching: 2, caught: 3, asleep: 0 };
  const bump = (s, m) => { if (RANK[m] > RANK[s.mood]) s.mood = m; };

  recent.forEach(ev => {
    const aid = ev.agent && ev.agent.id;
    const s = byId[aid];
    if (!s) return;
    const f = (ev.evidence && ev.evidence.flow) || {};
    const destFromEv = (ev.evidence && ev.evidence.destination) || f.sni || (f.remote || '').split(':')[0] || null;

    if (isCaughtEvent(ev)) {
      bump(s, MOOD.CAUGHT);
      s.caught = ev.summary || 'sensitive read → outbound connection';
      if (destFromEv) s.dest = destFromEv;
      s.net = Math.max(s.net, Math.min(1, Math.log10((f.bytes_out || 0) + 1) / 6));
    } else if (ev.correlated || isEgressEvent(ev)) {
      // a correlated event IS an outbound connection (even if benign) → reaching
      bump(s, MOOD.REACHING);
      if (destFromEv || ev.target) s.dest = s.dest || destFromEv || ev.target;
      s.net = Math.max(s.net, ev.correlated ? Math.min(1, Math.log10((f.bytes_out || 0) + 1) / 6) : 0.5);
    } else {
      bump(s, MOOD.WORKING);
      s.net = Math.max(s.net, 0.2);
    }
  });

  // liveness → asleep (the app already tracks idle via last_seen; mirror it here)
  agents.forEach(a => {
    const s = byId[a.id];
    const idleSecs = Number(a.last_seen_offset || 0);
    if (idleSecs >= 120 && (s.mood === MOOD.IDLE)) s.mood = MOOD.ASLEEP;
  });

  return byId;
}

// hash agent id -> stable identity (color/species) so each agent is a recognizable critter
function hashId(id) { let h = 0; for (const c of String(id)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h; }
const SPECIES = ['horn', 'round', 'antenna', 'ear'];
const HUES = [
  { base: '#C9543A', light: '#EE8A66', dark: '#A8412C' },
  { base: '#3F73B0', light: '#6FA6E0', dark: '#2E588C' },
  { base: '#3F8F6A', light: '#7BC9A2', dark: '#2E6B4E' },
  { base: '#7E5BBE', light: '#A98AD8', dark: '#5E4090' },
  { base: '#B08A3F', light: '#E0BC6F', dark: '#8C6E2E' },
];
function skinFor(id) {
  const h = hashId(id);
  // use independent byte slices so color and species don't correlate / cluster
  return Object.assign({ species: SPECIES[(h & 0xff) % SPECIES.length] }, HUES[((h >> 11) & 0xff) % HUES.length]);
}

// shorten a subagent task name for the tag
function shortName(a) {
  if (a.type !== 'sub') return (a.cwd || '').split('/').pop() || a.name || 'agent';
  return (a.name || a.subagent_type || 'subagent').slice(0, 28);
}
function projectName(a) { return (a.cwd || '').split('/').pop() || a.name; }

// ===========================================================================
// CreatureView — the RENDER SEAM. Swap CSS internals for Rive here later.
// Each instance owns one creature's DOM (or, later, one rive.Rive canvas).
// ===========================================================================
class CreatureView {
  constructor(agent) {
    this.agent = agent;
    this.skin = skinFor(agent.id);
    this.mood = null;
    this.el = this._buildCSS();      // <-- LATER: replace with a <canvas> + rive.Rive
    this._engine = new CSSCreatureEngine(this.el, this.skin); // ported engine
  }

  // ---- RIVE SWAP SEAM -----------------------------------------------------
  // To move to Rive:
  //   1. Bundle Snitch.riv + rive.wasm under ui/dist/assets/ (LOCAL — no CDN;
  //      Tauri CSP needs `wasm-unsafe-eval`, and the file must be a dist asset).
  //   2. In _buildCSS(): create a <canvas>, `new rive.Rive({src, canvas, stateMachines:'Brain', onLoad})`.
  //   3. In apply(): map state -> inputs:
  //        i.mood.value = {idle:0,working:1,reaching:2,caught:3}[state.mood]
  //        i.asleep.value = state.mood==='asleep'
  //        i.netIntensity.value = state.net; (and fire react/spawn triggers)
  //      and set the view model `Skin` (hue/species/scale) once.
  // The bridge below (apply) stays identical — only the body of these methods changes.
  // ------------------------------------------------------------------------
  _buildCSS() {
    const pen = document.createElement('div');
    pen.className = 'cr-pen';
    pen.style.setProperty('--c-base', this.skin.base);
    pen.style.setProperty('--c-light', this.skin.light);
    pen.style.setProperty('--c-dark', this.skin.dark);
    pen.innerHTML = `
      <div class="cr-head">
        <div><div class="cr-name"></div><div class="cr-pid"></div></div>
        <div class="cr-chip"><span class="cr-dot"></span><span class="cr-lbl"></span></div>
      </div>
      <div class="cr-arena">
        <div class="cr-glow"></div>
        <div class="cr-critter">${critterInnerHTML(this.skin.species)}</div>
        <div class="cr-bubble"></div>
      </div>
      <div class="cr-subs"></div>`;
    return pen;
  }

  apply(state) {
    const a = this.agent;
    this.el.querySelector('.cr-name').textContent = a.type === 'sub' ? shortName(a) : projectName(a);
    this.el.querySelector('.cr-pid').textContent = `pid ${a.pid} · ${a.cwd || ''}`;
    if (state.mood !== this.mood) { this.mood = state.mood; this._engine.setMood(state.mood); }
    this._engine.setNet(Math.round((state.net || 0) * 100));
    if (state.mood === 'caught' && state.caught) {
      this._engine.snitch(`"${state.caught}"`, state.dest ? `→ ${state.dest}` : 'just now');
    }
    // chip
    const lbl = { idle: 'idle', working: 'working', reaching: 'reaching out', caught: 'caught something', asleep: 'asleep' }[state.mood];
    this.el.querySelector('.cr-lbl').textContent = lbl;
  }

  setSubcount(n) {
    const subs = this.el.querySelector('.cr-subs');
    subs.textContent = n ? `${n} hatchling${n > 1 ? 's' : ''}` : '';
    subs.style.display = n ? '' : 'none';
  }

  // Tear down the underlying engine (timers/listeners/ALL_ENGINES entry).
  destroy() { if (this._engine && this._engine.destroy) this._engine.destroy(); }
}

// ===========================================================================
// CreaturePen — the registry. Diffs st.agents each tick: spawn/update/despawn.
// ===========================================================================
class CreaturePen {
  constructor(container) { this.container = container; this.views = new Map(); }

  update(st) {
    const states = deriveCreatureStates(st);
    const agents = st.agents || [];
    const mains = agents.filter(a => a.type === 'main');
    const subsByParent = {};
    agents.filter(a => a.type === 'sub').forEach(a => {
      (subsByParent[a.parent_agent_id] = subsByParent[a.parent_agent_id] || []).push(a);
    });

    const seen = new Set();
    // render mains (subagents shown as a count under their parent for now)
    mains.forEach(a => {
      seen.add(a.id);
      let v = this.views.get(a.id);
      if (!v) { v = new CreatureView(a); this.views.set(a.id, v); this.container.appendChild(v.el); v.el.classList.add('cr-spawn'); }
      v.apply(states[a.id] || { mood: 'idle', net: 0 });
      v.setSubcount((subsByParent[a.id] || []).length);
    });

    // despawn creatures whose agent vanished (tear down engine + element)
    for (const [id, v] of this.views) {
      if (!seen.has(id)) {
        v.el.classList.add('cr-despawn');
        v.destroy();
        setTimeout(() => v.el.remove(), 400);
        this.views.delete(id);
      }
    }
  }

  // Tear down every creature (engines, timers, listeners) and empty the stage.
  destroy() {
    for (const v of this.views.values()) { v.destroy(); v.el.remove(); }
    this.views.clear();
  }
}

// ===========================================================================
// boot — controllable start/stop so the hidden easter egg drives it.
// (No auto-boot: the creature view only runs while the overlay is open.)
// ===========================================================================
const CreatureEgg = (() => {
  let pen = null, unlisten = null, timer = null, started = false, gen = 0;

  async function refresh() {
    if (!pen) return;
    try { const st = await invoke('get_status'); pen.update(st); }
    catch (e) { console.warn('[creatures] get_status failed', e); }
  }

  async function start() {
    if (started) return; started = true;
    const myGen = ++gen;               // generation token: abort if stop() runs during awaits
    const container = document.getElementById('creature-stage');
    if (container) container.innerHTML = '';
    pen = new CreaturePen(container);
    let un = null;
    try { un = await listen('status-changed', () => refresh()); } catch (_) {}
    if (myGen !== gen) { if (typeof un === 'function') { try { un(); } catch (_) {} } return; } // closed mid-start
    unlisten = un;
    await refresh();
    if (myGen !== gen) return;         // closed during first refresh; stop() already cleaned up
    timer = setInterval(refresh, 1500); // fallback poll
  }

  function stop() {
    started = false;
    gen++;                             // invalidate any in-flight start()
    if (timer) { clearInterval(timer); timer = null; }
    if (typeof unlisten === 'function') { try { unlisten(); } catch (_) {} unlisten = null; }
    if (pen) { pen.destroy(); pen = null; }
  }

  return { start, stop };
})();

window.CreatureEgg = CreatureEgg;
