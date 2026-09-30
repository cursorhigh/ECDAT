# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) — Frontend

The operator console. Next.js 16 (App Router) + React 19 + TypeScript + Tailwind.

For the project as a whole see the [root README](../README.md).

---

## Stack

| | |
|---|---|
| Framework | Next.js 16, App Router, React 19 |
| Language | TypeScript 5.7 |
| Styling | Tailwind CSS 3.4, shadcn-style local primitives |
| Server state | TanStack React Query 5.83 |
| Graph | Cytoscape.js 3.34 |
| Charts | Recharts 2.15 |
| Icons | lucide-react |
| Runtime | Node 20+ |

## Getting started

```bash
npm install
npm run dev            # http://localhost:3000
```

The API base URL comes from `NEXT_PUBLIC_API_BASE_URL` (default
`http://127.0.0.1:8000`). Normally the root launcher sets it for you.

```bash
cd .. && ./run.sh --mode browser-dev
```

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Dev server with hot reload |
| `npm run build` | Production build, then stage standalone output |
| `npm run start` | Serve the standalone build (`scripts/start-standalone.mjs`) |
| `npm run lint` | ESLint |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run check:nesting` | Guard against invalid button nesting / block-in-button |
| `npm run check` | All three of the above — **run this before committing** |

There is no unit test runner in this project. Verification is `npm run check` plus
the `check:nesting` guard, which catches a class of accessibility bug that type
checking cannot.

## Layout

```
frontend/
├── app/
│   ├── page.tsx                    redirect to the workspace
│   ├── globals.css                 design tokens — light and dark themes
│   └── (workspace)/
│       ├── layout.tsx              app shell, global risk prompt
│       ├── dashboard/page.tsx
│       ├── scans/page.tsx          discovery: run, watch, findings
│       ├── assets/page.tsx         inventory, graph, dependencies
│       ├── analysis/page.tsx       runs, assessments, CBOM export
│       ├── mitigation/page.tsx     waves, recommendations, remediation rows
│       ├── reports/page.tsx
│       ├── audit/page.tsx          audit history, scan history
│       └── settings/page.tsx       scope, data deletion
├── components/
│   ├── ui/                         primitives: button, card, table, dialog, tooltip…
│   ├── data/                       domain components: graph, risk prompt, CBOM export
│   ├── layout/                     app shell, session scope, theme toggle
│   └── feedback/                   loading / error / empty states, toasts
├── lib/
│   ├── api/client.ts               typed API surface
│   ├── api/types.ts                response types
│   ├── session-context.tsx         active WorkSession
│   ├── theme.tsx                   light/dark
│   └── utils.ts                    formatting helpers
└── scripts/                        standalone build helpers
```

## The pages

| Route | What it is for |
|---|---|
| `/dashboard` | Overview: counts, posture, what needs attention |
| `/scans` | Start discovery; watch a job; inspect findings with search and filters |
| `/assets` | The asset inventory, dependency graph, per-asset detail |
| `/analysis` | Risk runs — summary, per-asset assessments, CBOM export |
| `/mitigation` | Migration waves, linked recommendations, remediation rows |
| `/reports` | Build and export reports |
| `/audit` | Audit trail and scan history |
| `/settings` | Active scan scope, data deletion |

## Things worth knowing before changing this code

**The session scope is the app's organising idea.** Every query is keyed by
`scopeKey` and gated on `ready && hasSession`. Changing scope changes every view.
Do not add a query that fetches before the session resolves — the result is a
flash of false content, such as "No completed scan in this session" appearing
before a real scan loads.

**Loading states are shaped like what they replace.** There is a
`check:nesting` guard and a table-shaped skeleton rather than a generic spinner,
because a loader that does not match the content it stands in for makes the layout
jump when the content lands. Prefer a purpose-built skeleton to
`LoadingState` when the content has a recognisable shape.

**Bounded scroll regions are deliberate.** Every large table has a `max-h-*` with
an internal scroll and a sticky header. Removing the cap puts the page controls out
of reach, which is the specific problem the caps solve.

**Tooltips are informational, not decorative.** `NavTooltip` is anchored, flips,
and clamps to the viewport; `Tooltip` follows the cursor. Prefer `NavTooltip` on
fixed controls. Native `title` is used only for values truncated inside a cell,
where the full text is the thing being revealed.

**The risk context prompt is deliberate, not automatic.** It opens only when
someone presses *Start analysis*. Parked runs from unattended discovery continue on
the last-used context without interrupting anyone.

## Theming

`app/globals.css` holds the tokens. Light and dark are separate token blocks; a
component never branches on theme, it uses `bg-card`, `text-muted-foreground`,
`border-border` and so on.

Light-theme values are contrast-checked, not chosen by eye. The important ones:

| Token | Contrast on page | Note |
|---|---|---|
| `--muted-foreground` | 5.9:1 | Was 4.9:1; used by ~100 labels and captions |
| `--foreground` | 15:1 | |
| `--primary` | 9.7:1 | Deep teal, not black |
| `--border` | 1.88:1 | Was 1.30:1 and effectively invisible |

If you change a token, re-check the ratios rather than trusting the visual — that
is how the light theme ended up unreadable in the first place.

## Offline / air-gapped deployment

See [`../ECDAT_Offline_Frontend_and_Packaging_Guide.md`](../ECDAT_Offline_Frontend_and_Packaging_Guide.md).

In short: `npm run build` produces a self-contained standalone server under
`.next/standalone`. It has no runtime CDN dependency, and `outputFileTracingRoot`
is pinned so asset paths resolve regardless of where the folder is copied.

## Known limitations

- **No unit tests.** Verification is `npm run check` and manual review. There is no
  test runner configured.
- **`npm run build` fails if a server is already running** (`EBUSY` on
  `.next/standalone`). Stop the preview server first.
- **`next start` serves a built bundle with no hot reload.** Rebuild and restart to
  see changes.
- **No client-side route guards on auth.** There is no authentication, so nothing
  here can assume a logged-in user.
- **Some tables render large result sets** — a page can hold several thousand
  findings. Scrolling is bounded and the API is paginated, but there is no
  virtualisation.
