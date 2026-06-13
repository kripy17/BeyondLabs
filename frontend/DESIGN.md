# BeyondArch Design System

A **neo-brutalist** design language built for a local-first SOC analyst workbench. Combines thick borders, heavy drop shadows, monospace typography, and terminal-inspired UI with modern CSS custom properties and responsive layouts.

---

## Design Principles

| Principle | Description |
|-----------|-------------|
| **Honest materials** | No faux-glass, no rounded corners, no gradients-as-decorations. Borders are solid lines, shadows are sharp offsets, surfaces are flat. |
| **Terminal truth** | The terminal panel (`.neo-case-terminal`) uses a true dark background (`#07080c` / `#050609`) — the only place pure-black backgrounds appear, reserved for "live system" output. |
| **Local-first signal** | Session-only, local parsing, and offline capability are called out explicitly with cyan (`--neo-cyan`) and rose (`--neo-rose`) accents. |
| **Static-first workflow** | The 8-stage pipeline communicates a linear investigation flow. Visual hierarchy follows the investigation path, not decorative whims. |
| **Case-ready output** | The forensic evidence preview uses a file-console metaphor (`.json` headers, dot indicators) to signal structured, exportable results. |

---

## Color System

All colors are defined as CSS custom properties on `.ba-app` and change under `html.dark` / `[data-theme="dark"]`.

### Surface & Ink (Light Mode)

```css
--neo-bg:       #efe9dd;   /* page background */
--neo-bg-2:     #e7dfd1;   /* section background */
--neo-paper:    #fffdf6;   /* card / component surface */
--neo-paper-2:  #f5efe4;   /* card hover / secondary surface */
--neo-paper-3:  #eee5d7;   /* tertiary surface */
--neo-ink:      #050505;   /* primary text (near-black) */
--neo-muted:    #393530;   /* body text */
--neo-subtle:   #686056;   /* secondary text / labels */
--neo-faint:    #9a9081;   /* placeholder / disabled */
--neo-line:     #050505;   /* borders (full black) */
--neo-line-soft: rgba(5, 5, 5, .18);
--neo-invert:   #050505;   /* inverted surface */
--neo-invert-text: #fffdf6;
--neo-shadow:   5px 5px 0 #050505;
--neo-shadow-lg: 9px 9px 0 #050505;
--neo-grid:     rgba(5, 5, 5, .075);
```

### Surface & Ink (Dark Mode)

```css
--neo-bg:       #070a11;   /* deep navy */
--neo-bg-2:     #0b111b;
--neo-paper:    #111822;   /* card surface */
--neo-paper-2:  #151f2d;
--neo-paper-3:  #1d2a3b;
--neo-ink:      #fff4e4;   /* warm off-white text */
--neo-muted:    #d8c9b6;
--neo-subtle:   #a89b8a;
--neo-faint:    #756c5e;
--neo-line:     #f3e6d0;   /* warm light borders */
--neo-line-soft: rgba(243, 230, 208, .20);
--neo-invert:   #f3e6d0;
--neo-invert-text: #070a11;
--neo-shadow:   5px 5px 0 rgba(243, 230, 208, .82);
--neo-shadow-lg: 9px 9px 0 rgba(243, 230, 208, .74);
--neo-grid:     rgba(243, 230, 208, .075);
```

### Accent Palette

| Token | Light | Dark | Usage |
|-------|-------|------|-------|
| `--neo-cyan` | `#00d5ef` | `#22d3ee` | Primary interactive, terminal highlights, primary action borders |
| `--neo-violet` | `#8a2be2` | `#a78bfa` | Primary CTA background, hero glow |
| `--neo-rose` | `#f43f5e` | `#fb7185` | Risk/danger, severity high, finding type |
| `--neo-emerald` | `#10b981` | `#34d399` | Success, completed badges, online status |
| `--neo-amber` | `#f59e0b` | `#fbbf24` | Warning, example output badge, medium severity |
| `--neo-blue` | `#2563eb` | `#60a5fa` | SIEM/logs section accent |

### Color Application Rules

- Accent colors are used **sparingly** — borders, top edges, badges. Never as full-surface fills (except the primary CTA button which uses `--neo-violet`).
- `--neo-cyan` is the "active" color: active pipeline steps, primary terminal buttons, hero glow.
- `--neo-emerald` is the "done" color: completed pipeline badges, active investigation banner.
- `--neo-rose` is the "risk" color: risk badges, severity-high findings, danger buttons.

---

## Typography

### Font Stack

| Role | Font | Weight |
|------|------|--------|
| **Heading display** | `"Space Grotesk", Inter, sans-serif` | 900 (variable via weight) |
| **UI / body** | System sans-serif (inherited from `Inter, system-ui`) | 400 / 850 / 950 |
| **Code / terminal / labels** | `"JetBrains Mono", ui-monospace, SFMono-Regular, monospace` | 400 / 850 / 950 |

### Type Scale

| Element | Size | Line Height | Letter Spacing | Transform |
|---------|------|-------------|----------------|-----------|
| Hero heading (h1) | `clamp(3.6rem, 6.5vw, 6.2rem)` | `.88` | `-.065em` | Uppercase |
| Section heading (h2) | `clamp(1.85rem, 3.2vw, 3rem)` | `.96` | `-.065em` | Uppercase |
| Card heading (h3) | `clamp(1.45rem, 2.3vw, 3rem)` | `.94`–`.98` | `-.055em`–`-.075em` | Uppercase |
| Body / description | `1.05rem` | `1.6` | normal | none |
| Muted body | `.9rem`–`1rem` | `1.45`–`1.56` | normal | none |
| Labels / kickers | `.7rem` | normal | `.1em`–`.16em` | Uppercase |
| Terminal / code | `.66rem`–`.96rem` | normal | `.02em`–`.12em` | Mixed |
| Badge / tag | `.55rem`–`.62rem` | normal | `.06em`–`.12em` | Uppercase |

### Typography Rules

- **Uppercase + heavy weight + tight letter-spacing** is the neo-brutalist signature. Applies to headings, labels, section kickers, button text, tags, and badges.
- **JetBrains Mono** is used for anything "technical": labels, terminal output, code values, tags, step counters, footer metadata.
- **Space Grotesk** is reserved for hero headings and section titles — the only place the geometric display face appears.
- Body text is always sentence-case, normal weight, with generous line-height for readability.

---

## Spacing & Layout

### Grid System

The page uses a single-column stack with constrained width:

```css
.neo-command-deck {
  width: min(1520px, calc(100% - 36px));
  margin: 0 auto;
  display: grid;
  gap: 2.8rem;
}
```

### Section Rhythm

| Element | Top Gutter | Bottom Gutter |
|---------|-----------|---------------|
| Hero | — | 2.8rem grid gap |
| Quick launch | 2.8rem grid gap | 2.8rem grid gap |
| Case scope | `border-top + 1.6rem padding` | 2.8rem grid gap |
| Pipeline | `border-top + 1.6rem padding + 1.6rem margin` | 2.8rem grid gap |
| Library | `border-top + 1.6rem padding + 1.6rem margin` | 2.8rem grid gap |
| Case preview | `border-top + 1.6rem padding + 1.6rem margin` | 2.8rem grid gap |
| Assurance | `border-top + 1.6rem padding + 1.6rem margin` | 2.8rem grid gap |
| Footer | `border-top + 2px` | — |

Sections with `.neo-section` class get `border-top: 2px solid var(--neo-line)` and `padding-top: 1.6rem` for visual separation.

### Card Padding

| Card Type | Padding |
|-----------|---------|
| Hero card | `clamp(2.5rem, 5vw, 4rem)` |
| Terminal | `1.15rem 1.3rem 1.25rem` |
| Pipeline step | `1.1rem .75rem .9rem` |
| Workspace stage | `1.45rem 1.15rem 1.15rem` |
| Workspace card | `1rem` |
| Assurance card | `1.45rem` |
| Case item | `.5rem .6rem` |

---

## Component Patterns

### Neo-Brutalist Card

Every interactive surface follows this pattern:

```css
.neo-card {
  border: 2px solid var(--neo-line);
  background: var(--neo-paper);
  box-shadow: 3px 3px 0 var(--neo-line);  /* or 5px 5px / 9px 9px */
}
```

On hover:
```css
.neo-card:hover {
  transform: translate(-2px, -2px);
  box-shadow: 5px 5px 0 var(--neo-line);
}
```

### Button Variants

| Variant | Background | Border | Shadow | Hover |
|---------|-----------|--------|--------|-------|
| `.neo-btn` (default) | `var(--neo-paper)` | `2px solid var(--neo-line)` | `4px 4px 0` | `translate(2px, 2px)`, `2px 2px 0` |
| `.neo-btn.is-primary` | `var(--neo-violet)` | same | same | darker via `color-mix` |
| `.neo-ql-btn` | `var(--neo-paper-2)` | `2px solid`, left `3px` accent | `3px 3px 0` | `translate(-2px, -2px)`, `5px 5px 0` |
| `.neo-term-btn` | `var(--neo-paper)` | `2px solid` | — | `translate(-1px, -1px)`, `3px 3px 0` |
| `.neo-term-btn.is-primary` | cyan tint | cyan | — | cyan shadow |
| `.neo-evidence-action` | `var(--neo-paper)` | `2px solid` | `3px 3px 0` | `translate(-2px, -2px)`, `5px 5px 0` |

### Badges & Tags

| Pattern | Border | Background | Color | Usage |
|---------|--------|-----------|-------|-------|
| Section kicker | `2px solid var(--neo-line)` | `var(--neo-paper)` | `var(--neo-ink)` | Section headers |
| Card tag | `1px solid var(--neo-line)` | (none) | `var(--neo-ink)` | Tool keywords |
| Done badge | — | `var(--neo-emerald)` | `var(--neo-invert-text)` | Step completed |
| Active badge | — | `var(--neo-cyan)` | `var(--neo-invert-text)` | Recommended next |
| Risk badge | — | `var(--neo-rose)` | `white` | Risk strip label |
| Live badge | `1px solid var(--neo-emerald)` | — | `var(--neo-emerald)` | Live data indicator |
| Example badge | `1px solid var(--neo-amber)` | — | `var(--neo-amber)` | Example output |

---

## Animation & Interaction

### Timing

| Context | Duration | Easing |
|---------|----------|--------|
| Card hover lift | `140ms–170ms` | `ease` or `cubic-bezier(.22, 1, .36, 1)` |
| Card entrance (reveal) | `520ms` | `cubic-bezier(.22, 1, .36, 1)` |
| Terminal sweep | `5.2s` | `ease-in-out infinite` |
| Hero glow | `10s` | `ease-in-out infinite alternate` |
| Line flow | `2.8s–4s` | `linear infinite` |
| Pipeline track line | `4s` | `linear infinite` |
| Dot pulse | `1.8s–2s` | `ease-in-out infinite` |
| Chip breathe | `3s` | `ease-in-out infinite` (removed in v2, kept for reference) |
| Count animation | `≤600ms` | `ease-out` (cubic) |

### Reveal (Scroll Animation)

Elements with `[data-neo-reveal]` class fade in on scroll:

```css
.neo-reveal {
  opacity: 0;
  transform: translateY(20px);
  filter: blur(5px);
  transition: opacity 520ms ease,
              transform 520ms cubic-bezier(.22, 1, .36, 1),
              filter 520ms ease;
}
.neo-reveal.is-visible {
  opacity: 1;
  transform: translateY(0);
  filter: blur(0);
}
```

Child elements can be staggered with `--neo-delay` custom property:
```css
.neo-reveal.is-visible .neo-card {
  animation: neoCardSettle 520ms cubic-bezier(.22, 1, .36, 1) both;
  animation-delay: var(--neo-delay, 0ms);
}
```

### Reduced Motion

All animations are disabled under `prefers-reduced-motion: reduce`. Hover transitions are also removed.

---

## Iconography

- Uses **Lucide Icons** (`lucide-react` v0.483+).
- Icons are rendered at `h-4 w-4` (16px) for inline labels, `h-5 w-5` (20px) for step icons, `h-10 w-10` for visual accent.
- Icons inherit `color: var(--neo-ink)` via the icon neutrality layer, with exceptions:
  - `--neo-emerald` for checkmarks in the assurance list
  - `--neo-cyan` for card icons in workspace library
  - `--neo-rose` for the lock icon in the local-first visual card

---

## Responsive Breakpoints

| Breakpoint | Target | Changes |
|------------|--------|---------|
| `≤1120px` | Tablet landscape | Case scope → 1 column, workspace stage → stacked, output grid → 2-col, pipeline inline line hidden, footer → 1 column |
| `≤760px` | Tablet portrait / mobile | Deck padding reduced, hero card min-height removed, hero heading shrinks, all grids → 1 column, CTAs stack, footer simplified |
| `≤560px` | Small mobile | Pipeline → 1 column, tool grid → 1 column, resume banner stacks, terminal actions stack |

---

## CSS Architecture

### File Structure

```
src/styles/
├── tokens.css           # Theme tokens (--neo-*, --pr-*), dark/light
├── components.css        # Base styles, reset, shared component classes
├── animations.css        # Keyframe-only animations
├── pages.css             # Page-specific styles (homepage neo sections, triage workflow)
└── homepage-additions.css  # Homepage v2 additions (pipeline, case preview, quick launch)
```

### Import Order (in `index.css`)

```css
@import "./styles/tokens.css";
@import "./styles/components.css";
@import "./styles/animations.css";
@import "./styles/pages.css";
@import "./styles/homepage-additions.css";
```

### Naming Conventions

- **`.neo-*`** — Neo-brutalist design system classes (`.neo-hero`, `.neo-card`, `.neo-btn`).
- **`.ba-*`** — App shell / layout classes (`.ba-command-deck`, `.ba-topbar`).
- **`.is-*`** — State modifiers (`.is-active`, `.is-done`, `.is-primary`, `.is-visible`).
- **`.tone-*`** — Color theme modifiers (`.tone-rose`, `.tone-cyan`).
- **`[data-tone]`** — Accent color via attribute selector.

### CSS Custom Properties

- Motion preferences: `--neo-delay` (stagger delay for entrance animations).
- Dynamic hero: `--neo-hero-x`, `--neo-hero-y` (animated gradient positions).
- Theme: `--triage-*` (scoped to triage workflow pages).

---

## Key Components

### Hero Section (`.neo-hero`)

```
┌──────────────────────────────────────────────┐
│  [local://intake]  [no cloud required]        │  ← neo-hero-utility
│                                              │
│          SUSPICIOUS ARTIFACTS                 │  ← h1 (Space Grotesk)
│          TO CASE-READY EVIDENCE.              │
│                                              │
│   A local SOC workbench connecting...        │  ← p (body)
│                                              │
│   [Start Artifact Intake →] [View Case →]    │  ← neo-actions / neo-btn
│                                              │
│   Email Headers  DNS Lookup  IOC Pivot ...   │  ← neo-hero-pills
│                                              │
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   │
│   │ 01 Extract│──│ 02 Score│──│ 03 Package│  │  ← neo-hero-signal
│   └─────────┘   └─────────┘   └─────────┘   │
│                                              │
│   ◉ Active investigation — 3 artifacts ...   │  ← neo-resume-banner
└──────────────────────────────────────────────┘
```

### Terminal Panel (`.neo-case-terminal`)

```
┌──────────────────────────────────────────────┐
│  ● ● ●    beyondarch — live case console     │  ← header with dots
│                              [session-only]  │
├──────────────────────────────────────────────┤
│  $ workspace.load() → case://local           │
│  → storage session-only · backend online     │
│                                              │
│  ┌─────────┬─────────┬─────────┬─────────┐  │
│  │artifacts│ timeline│  notes  │ findings │  │  ← neo-terminal-meter
│  │    3    │    5    │    1    │    2     │  │
│  └─────────┴─────────┴─────────┴─────────┘  │
│                                              │
│  [Resume case]  [Add evidence]               │
└──────────────────────────────────────────────┘
```

### Risk Strip (`.neo-case-risk-strip`)

```
┌──────────────────────────────────────────────┐
│  ┌──────────┐   ┌──────────────────────┐     │
│  │ PROBABLE │   │ Artifacts     │   3  │     │
│  │ PHISHING │   │ Timeline      │   3  │     │
│  │          │   │ Findings      │   2  │     │
│  │   ┌──┐   │   │ Report-ready  │ Yes  │     │
│  │   │74│   │   └──────────────────────┘     │
│  │   └──┘   │                                │
│  └──────────┘                                │
└──────────────────────────────────────────────┘
```

---

## Quick Reference

### When to use which shadow

| Shadow | CSS | Used on |
|--------|-----|---------|
| Small | `2px 2px 0` | Hero signal articles, terminal buttons |
| Medium | `3px 3px 0` | Cards, quick launch buttons, pipeline steps, evidence actions, section kickers |
| Large | `5px 5px 0` | Continue banner, workspace stage |
| Extra large | `9px 9px 0` | Hero card, output console |
| Inset | `inset 0 0 0 11px var(--neo-paper)` | Score ring |

### When to use which border

| Width | Used on |
|-------|---------|
| `1px` | Tags, line-soft separators, card meta borders |
| `2px` | Cards, buttons, containers, section separators |
| `3px` | Left accent on quick launch buttons, corner pseudo-elements (removed in v2) |

### When to use which font

| Font | Used on |
|------|---------|
| Space Grotesk | Hero h1, section h2, assurance h3 |
| JetBrains Mono | Labels, kickers, terminal, code, badges, step numbers, meta, footer |
| Inter / system | Body paragraphs, card descriptions, list items |
