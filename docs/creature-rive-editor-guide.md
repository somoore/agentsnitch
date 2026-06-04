# Snitch Creature — Rive Editor Build Guide

> A step-by-step spec for authoring the first AgentSnitch creature in the **Rive
> editor** (rive.app). The goal is a single `.riv` whose inputs/properties exactly
> match the app's data bridge (see `creature-animation-rive-plan.md`), so wiring it
> into the Tauri app later is plug-and-play.
>
> Names in `code font` are **contract names** — they MUST match exactly, because the
> app sets them by string. Do not rename without updating the bridge.

---

## 0. Before you start — the two-channel rule

The creature encodes two independent things, and they must never bleed into each
other:

- **Identity (WHO)** — body **color** + **species variant**. Stable per agent,
  randomized from a hash of the agent id. Driven by **data-binding properties**.
- **Mood / activity (WHAT)** — **face** (brow, eyes, mouth) + **glow ring**. Driven
  by **state-machine inputs** off live events.

So: color does NOT change with risk; the **glow** does. Build accordingly.

---

## 1. Document & artboard setup

1. New file. Create one **Artboard** named `Snitch`, size **256 × 256** (square;
   the app scales it down for hatchlings). Transparent background.
2. Set the origin so the creature sits centered with a little headroom for
   ears/horns and Zzz above.

---

## 2. Draw the creature (layers, bottom → top)

Build these as named groups so the state machine + data binding can target them:

1. `glow` — a soft radial ellipse behind everything, ~210px, low opacity. This is
   the mood/risk aura.
2. `body` — the main blob. Put it under a group named `bodyPivot` so we can
   squash/stretch and bob the whole creature from one transform.
3. `ears` — the species-variant group (see §6). Two shapes (ears/horns), children
   of `bodyPivot` so they move with the body.
4. `eyeWhiteL`, `eyeWhiteR` — fixed eye whites.
5. `pupilL`, `pupilR` — children of a group `pupils`. The pupils translate to "look".
6. `lidL`, `lidR` — eyelids (a shape matching the white, scaleY 0 = open, 1 = shut),
   for blinking.
7. `browL`, `browR` — two short bars above the eyes. Angle carries mood.
8. `mouth` — single shape; we'll swap its form by state (line / grin / flat).
9. `zzz` — three "Z" text/shapes above the head, hidden by default.

Keep everything vector and few-shape; this rig should stay light.

---

## 3. Data-binding properties (identity — set once per agent)

Create a **View Model** named `Skin` with these bindable properties. The app sets
them when a creature spawns.

| Property        | Type   | Bind target                                  | Notes |
|-----------------|--------|----------------------------------------------|-------|
| `hue`           | Number | `body` fill hue (0–360)                       | identity color |
| `bodyShade`     | Color  | (optional) precomputed fill if hue-rotate is awkward | app can send the exact color |
| `glowColor`     | Color  | `glow` fill                                  | risk ramp: calm blue → amber → ember |
| `speciesIndex`  | Number | drives `ears` variant (see §6)               | 0..N-1 |
| `scale`         | Number | `Snitch` root scale                          | 1.0 main, ~0.45 hatchling |

> If hue-rotating a gradient body is fiddly in-editor, prefer `bodyShade` (Color):
> the app computes the per-agent color and just hands it over. Simpler + exact.

---

## 4. State-machine inputs (mood/activity — live)

Create a state machine named **`Brain`** with these inputs (names are the contract):

| Input          | Type    | Meaning |
|----------------|---------|---------|
| `mood`         | Number  | 0 idle · 1 working · 2 reaching · 3 caught |
| `asleep`       | Boolean | session idle |
| `blink`        | Trigger | one blink |
| `react`        | Trigger | startle/lean-in on a new caught event |
| `spawn`        | Trigger | pop/wobble when this creature first appears |
| `lookX`        | Number  | -1..1 pupil horizontal aim |
| `lookY`        | Number  | -1..1 pupil vertical aim |
| `netIntensity` | Number  | 0..1, rolling outbound bytes (log-scaled) |

---

## 5. Animations (timelines to author)

Create these timelines (1s unless noted; loop where marked):

1. `idle` *(loop)* — gentle breathing: `bodyPivot` scaleY 1.0→1.03→1.0; brows
   neutral; mouth = thin line; eyes open.
2. `working` *(loop)* — slightly faster breathing; pupils make small busy darts;
   mouth flat; brow neutral.
3. `reaching` *(loop)* — body leans ~4° toward +X; one ear/antenna perks; pupils
   aim toward look target; glow a touch brighter.
4. `caught` *(loop, short)* — body leans in + tiny recoil; **brows angle down
   (skeptical)**; mouth = open grin; eyes widen (whites scale up a hair).
5. `asleep` *(loop)* — `bodyPivot` translateY bob ±6px slow; eyes → `lid` shut
   (sleepy lines); `zzz` visible and drifting up + fading.
6. One-shots (non-loop): `blinkOnce` (lids scaleY 0→1→0 fast), `reactPop`
   (quick squash-stretch + glow flash), `spawnPop` (scale 0→1 overshoot).

Continuous-driven (no fixed timeline, driven by inputs via constraints — see §7):
pupil position (`lookX/Y`), glow opacity/scale (`netIntensity`).

---

## 6. Species variants (the "go wild" part)

Two viable approaches — pick one for v1:

- **A. Nested artboards (more variety):** make `ears` a nested artboard with N
  variants (round ears, tall ears, single horn, antenna). `speciesIndex` selects
  which is visible. Most distinct; more authoring.
- **B. One rig, blended ears (cheaper, coherent):** keep one ear pair and vary
  ear **shape/rotation/scale** via a 1D blend keyed on `speciesIndex`. Faster,
  reads as the "same species, different individuals."

Recommendation: ship **B** with 3–4 stops first; graduate hero variants to **A**
later. Either way the input/property contract stays the same.

---

## 7. State machine "Brain" — layers & transitions

**Layer 1 — Base mood (blend or transitions on `mood`):**
- States: `Idle`, `Working`, `Reaching`, `Caught`, `Asleep`.
- Use a **1D Blend State** on `mood` (0→Idle, 1→Working, 2→Reaching, 3→Caught) so
  transitions are smooth, not snappy. ~200–300ms blend.
- `Asleep`: a separate state entered when `asleep == true` (transition from Any
  State), exited when `asleep == false`. Asleep overrides the blend.

**Layer 2 — Additive one-shots (fire over any base state):**
- `blink` trigger → play `blinkOnce`, return.
- `react` trigger → play `reactPop`, return.
- `spawn` trigger → play `spawnPop`, return (entry only).

**Constraints (continuous, no transitions):**
- `pupils` group → **Translation constraint** mapped from `lookX`/`lookY`
  (clamp travel to stay inside the whites).
- `glow` → opacity + scale mapped from `netIntensity` (e.g. opacity 0.25→0.6).

---

## 8. Export contract (what the app expects)

- Export a single `Snitch.riv`.
- Artboard: `Snitch` · State machine: `Brain`.
- Inputs present and named exactly per §4.
- View model `Skin` with properties per §3.
- Ship `Snitch.riv` **and** the Rive runtime `.wasm` as **bundled app assets**
  (local-only product: no CDN fetch at runtime).

### App wiring sketch (for reference; not part of editor work)
```js
import { Rive } from '@rive-app/canvas';
const r = new Rive({
  src: 'assets/Snitch.riv',        // bundled, not fetched
  canvas, autoplay: true,
  stateMachines: 'Brain',
  onLoad() {
    const i = Object.fromEntries(r.stateMachineInputs('Brain').map(x => [x.name, x]));
    i.mood.value = 1;              // working
    i.blink.fire();               // one blink
    // view model "Skin": set hue/glowColor/speciesIndex/scale per agent
  },
});
```

---

## 9. First-pass acceptance (when is the rig "done enough")

- [ ] Setting `mood` 0→3 smoothly walks Idle→Working→Reaching→Caught with readable
      faces, and **body color does not change**.
- [ ] `asleep=true` curls + bobs + shows Zzz; `false` wakes cleanly.
- [ ] `blink`, `react`, `spawn` fire over any mood without resetting it.
- [ ] `lookX/lookY` aims pupils; `netIntensity` pulses the glow.
- [ ] `glowColor`, `hue`/`bodyShade`, `speciesIndex`, `scale` change identity
      independently of mood.
- [ ] Reads correctly at hatchling scale (~115px) as well as full size.

Once these pass, the standalone harness (Phase A) can drive it with fake events,
then real session replay, then the live app.
