# ECDAT — Offline-First Frontend, Desktop, and Deployment Specification

**Purpose:** This is the implementation brief for the coding agent building ECDAT's frontend and packaging. The agent may not be able to view design references or screenshots, so all visual direction and behavior is described explicitly below.

**UI inspiration:** https://github.com/jakubkrehel/skills/blob/main/README.md

The referenced repository describes a collection of interface-design skills covering UI quality, typography, color systems, accessibility, layout, product writing, and review. Use those principles as a design-review framework: improve alignment, spacing, readable type, semantic colors, accessible controls, concise product copy, and consistency. Do not merely copy a screenshot or create a generic admin template.

---

## 1. Product objective

Build ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) as a polished, fully offline-capable application for discovering cryptographic assets, analyzing risk, prioritizing migration, planning mitigation, and producing reports/CBOMs.

The existing Django backend is implemented and exposes APIs for:

1. Sessions
2. Discovery and scan jobs
3. External scanner finding ingestion
4. Asset inventory and statistics
5. Analysis and awaiting-context decisions
6. Mitigation planning
7. Reporting and CBOM
8. Audit history

**Do not replace the backend or invent a second implementation of its core logic.** Inspect the repository and preserve existing working behavior. Adapt the backend only where offline packaging requires it, and keep such changes modular and tested.

## 2. Hard requirements

- The complete desktop workflow must work with networking disabled.
- No cloud API, remote authentication, CDN, remotely hosted font, telemetry, or online license validation may be required.
- Bundle all runtime dependencies, frontend assets, required scanner tools, rules, and any mandatory model files.
- No runtime downloads or package installation.
- No secrets embedded in frontend JavaScript or publicly inspectable assets.
- Local desktop backend binds to loopback by default; never expose it to the LAN by default.
- All displayed operational data must come from the backend. No fabricated KPIs, scans, findings, risks, scores, progress, or AI assessments.
- Clearly show unavailable/optional capabilities rather than pretending they are active.
- Support session isolation and make the active scope visible.
- Preserve data across normal application restarts and upgrades.
- Build and test native artifacts for each declared OS/architecture; do not claim universal compatibility without testing.

## 3. Recommended stack

Use these defaults unless the repository already has a sound equivalent:

- Frontend: React + TypeScript + Vite
- Desktop shell: Tauri 2
- Styling: Tailwind CSS
- Accessible UI primitives: shadcn/ui or a coherent accessible component system
- Routing: React Router
- API/server state: TanStack Query
- Forms: React Hook Form + Zod
- Charts: Recharts
- Tables: TanStack Table
- Tests: Vitest, React Testing Library, and Playwright where practical
- Backend: existing Django REST API
- Desktop persistence: SQLite only after verifying Django model, transaction, and concurrency compatibility
- Workers: preserve existing infrastructure where feasible; if Redis/Celery is a required online/server dependency, design and test a local desktop-compatible execution path rather than silently assuming a database queue is equivalent.

Keep frontend code reusable so the same build can run in a browser against a configured local or self-hosted backend.

## 4. Target architecture

Desktop mode:

    User
      |
      v
    Tauri desktop shell
      |-- React/Vite frontend assets bundled locally
      |-- native directory/file selection
      |-- controlled backend process lifecycle
      |
      v
    Local Django API (loopback only)
      |-- session and authentication
      |-- discovery / normalization / parsing / correlation
      |-- analysis and risk reasoning
      |-- mitigation
      |-- reporting and CBOM
      |-- audit
      |
      +--> local workers / scanners
      |
      +--> persistent local database and application data

Browser mode:

    Browser frontend --> configured Django API

In browser mode, a remote server cannot access a user's local filesystem just because the user enters a path. Local scanning requires desktop mode, an agent, a deliberate upload, or a directory mounted into the server environment.

## 5. Visual design direction (text-only specification)

Create a high-quality, professional cybersecurity product interface. The design should feel calm, precise, technical, and trustworthy—not like a neon gaming dashboard and not like a generic template filled with decorative cards.

### 5.1 Overall composition

- Default to a dark theme, with a user-selectable light theme if feasible.
- Use a deep blue-charcoal application background, slightly lighter sidebar and surfaces, subtle borders, and restrained teal/green as the primary action/accent color.
- Reserve amber/orange for warnings and elevated risk, red for critical/error states, and blue for informational states. Never rely on color alone; include text labels and/or icons.
- Keep the layout spacious but information-dense enough for a security analyst.
- Use a fixed or sticky left navigation sidebar on desktop, a compact top bar, and a scrollable main content area.
- Avoid excessive gradients, glows, glassmorphism, huge hero sections, oversized rounded cards, and gratuitous animation.
- Use consistent spacing tokens (e.g. 4, 8, 12, 16, 24, 32 px), consistent radii, and aligned card/table edges.
- Use subtle hover and focus states. Motion should be short and functional; respect reduced-motion preferences.
- Provide responsive layouts. On narrow windows, collapse the sidebar into a drawer and allow tables to adapt or scroll horizontally without clipping essential actions.

### 5.2 Typography

- Use a locally bundled, appropriately licensed sans-serif font, with system fallbacks.
- Use a clear hierarchy: page title, section title, card label, body text, metadata.
- Use tabular numerals for KPI values, counts, timestamps, and progress.
- Keep body copy readable and concise. Avoid all-caps paragraph text and tiny low-contrast labels.
- Truncate long paths, identifiers, hashes, and algorithm names carefully; expose the full value through a tooltip, copy action, or detail view.
- Use monospace only for code, hashes, identifiers, paths, and technical values where it improves scanning.

### 5.3 Color and status semantics

Define centralized design tokens rather than scattering literal colors across components. Include tokens for:

- App background
- Sidebar background
- Surface / elevated surface
- Primary and secondary text
- Muted text
- Borders and separators
- Primary action
- Focus ring
- Success, informational, warning, danger
- Risk categories, if the backend defines categories

Risk color mapping must follow the backend's actual categories and thresholds. Do not invent risk thresholds in the frontend.

### 5.4 Components and interaction polish

- Buttons must have clear primary, secondary, destructive, and disabled states.
- Inputs must have labels, help text where useful, validation, focus indication, and error messages.
- Tables must have aligned columns, sensible row height, sorting/filter affordances, empty states, and loading states.
- Dialogs must have clear titles, descriptions, cancel/confirm actions, and keyboard behavior.
- Use contextual icons consistently; do not use an icon without an understandable label or accessible name.
- Provide skeletons or restrained loading indicators, not fake values.
- Every page must support loading, empty, error, and populated states.
- Include copy-to-clipboard affordances for IDs, paths, and hashes when useful.
- Confirm potentially destructive actions.
- Avoid dead buttons, decorative controls that do nothing, and placeholder links in production.

### 5.5 Design review

Use the inspiration repository's stated themes as a checklist during review:

- UI quality and consistency
- Typography hierarchy and wrapping
- Semantic color system and contrast
- Accessibility and keyboard use
- Layout, grouping, alignment, and reading order
- Product copy consistency
- Review the completed screens and fix findings before calling the UI done

Reference: https://github.com/jakubkrehel/skills/blob/main/README.md

## 6. Navigation and information architecture

Use this primary navigation:

1. **Dashboard**
2. **Discovery & Scans**
3. **Cryptographic Assets**
4. **Risk Analysis**
5. **Mitigation & Migration**
6. **Reports & CBOM**
7. **Audit Trail**
8. **Settings**

The app shell should contain:

- ECDAT product mark/name
- Sidebar navigation with active-page indication
- Top bar with current page/breadcrumb as appropriate
- Active session/scope selector
- Backend/worker health indicator
- Explicit **Offline** indicator in desktop mode
- Optional global search only if it searches real supported data
- User/application menu with version and diagnostics

Do not add features to navigation unless implemented and backed by real functionality.

## 7. Page specifications

### 7.1 Dashboard

Purpose: give the analyst an accurate overview of the selected scope.

Include, when supported by real API fields:

- Cryptographic asset count
- Urgent remediation count
- Quantum-vulnerable count
- HNDL-exposed count
- Recent scans and statuses
- Risk distribution
- Vulnerability/migration-priority breakdown
- Recent analysis and mitigation activity
- Recent audit events
- Quick actions: New Scan, Import Findings, Start Analysis, Generate Report

Use `GET /api/reporting/overview/`, `GET /api/stats/`, and other relevant endpoints after inspecting their actual schemas.

Do not display sample counts in production. If the API has no value, show an honest empty/unavailable state.

### 7.2 Discovery & Scans

Provide two workflows.

**Local folder scan**
- In desktop mode, select a directory through a native directory picker.
- Let the user choose supported `scan_type`, `source_type`, and options based on backend validation.
- Show the selected directory and a confirmation before starting.
- Submit the scan and display job ID, session, state, and progress.
- Poll status until a terminal state.
- Show useful failure information and logs/diagnostics where safe.
- Provide cancel only if the backend supports cancellation.

**External scanner ingestion**
- Let the user select a supported local findings file or enter findings through a supported form.
- Validate file type/structure before submitting.
- Explain validation errors.
- Submit through the existing ingestion endpoint and display the resulting job/session.

API:
- `POST /api/start-scan/`
- `POST /api/run-demo-scan/`
- `POST /api/scan-data/`
- `GET /api/scans/{id}/`
- `GET /api/scans/?ordering=created_at`

The demo scan must be clearly labeled as demo data.

### 7.3 Cryptographic Assets

Include:
- Search and supported filters
- Sorting and pagination
- Asset name/type/source and other real backend attributes
- Detail view/drawer
- Related findings and scan provenance where available
- Related assessments and mitigation references where available
- Supported export actions

API:
- `GET /api/assets/?search=...`

Inspect the backend for actual fields and query parameters. Do not assume unsupported filters exist.

### 7.4 Risk Analysis

Include:
- Selection of a completed scan
- Supported options such as `max_findings`
- Job ID, status, and progress
- Awaiting-context resolution form when the backend requests it
- Assessments
- Executive summary
- Summary rows, including risk and migration priority if returned
- CBOM information
- Honest failure/cancelled states

API:
- `POST /api/analysis/start/`
- `GET /api/analysis/awaiting/`
- `GET /api/analysis/{id}/`

Respect backend state transitions. Never label a queued, running, or awaiting-context analysis as completed. Follow the backend's documented behavior when a start request resolves context for an existing run.

### 7.5 Mitigation & Migration

Include:
- Generate a plan from a completed analysis
- Plan status/progress
- Urgent assets and migration priorities
- Per-asset remediation guidance
- Blast radius and effort information
- Quantum-vulnerability and HNDL information when present
- Plan detail and export
- Overview across plans within the selected scope

API:
- `POST /api/mitigation/run/{analysis_id}/generate/`
- `GET /api/mitigation/{id}/`
- `GET /api/mitigation/overview/`

Do not create a fake “mark remediated” action unless the backend has a supported mutation endpoint.

### 7.6 Reports & CBOM

Include:
- Reporting overview
- Full report generation/retrieval
- Asset snapshot export
- Raw and normalized CSV export
- CBOM viewing/export where supported
- Session scope and generation time
- Progress/error feedback if generation is asynchronous

API:
- `GET /api/reporting/overview/`
- `GET /api/reports/full.json`
- `GET /api/reports/assets.json`
- `GET /api/reports/raw.csv`
- `GET /api/reports/normalized.csv`

The supplied API guide says the full report response may contain base64 PDF data and metadata (`filename`, `mime`, `format`, `scope`). Verify actual behavior. Decode safely and save using a native file dialog in desktop mode. Do not assume the response shape without checking serializers/views.

### 7.7 Audit Trail

Include:
- Action
- Message
- Actor
- Session ID
- Timestamp
- Supported filters and pagination/limit
- Empty state
- Read-only presentation unless the backend explicitly supports mutation

API:
- `GET /api/session/audit/?limit=200`

### 7.8 Settings

Include:
- App version/build
- Backend and worker health
- Database/data directory
- Report/export directory
- Scanner and ruleset versions/status
- Optional local AI model status
- Logs and diagnostics
- Session management
- Local API configuration only if needed and safely exposed
- Import/export of supported configuration
- Theme selection if implemented

Do not include cloud setup as a required step.

## 8. API contract and session behavior

All API calls must use a centralized typed client. Inspect the README and backend code for the actual envelope, authentication middleware, serializer fields, and error format.

Documented request convention:
- Write endpoints accept `{\"data\": ...}`-wrapped or raw bodies where supported.
- API key header for automation: `X-API-Key: ecdat_<prefix>_<secret>`
- Session header: `X-ECDAT-Session: <id>`
- Session cookie: `ecdat_session_id`

Documented endpoints:

### Session
- `POST /api/session/create/`
- `GET /api/session/info/`
- `GET /api/session/audit/?limit=200`

### Discovery
- `POST /api/start-scan/`
- `POST /api/run-demo-scan/`
- `POST /api/scan-data/`
- `GET /api/scans/{id}/`
- `GET /api/scans/?ordering=created_at`
- `GET /api/assets/?search=...`
- `GET /api/stats/`

### Analysis
- `POST /api/analysis/start/`
- `GET /api/analysis/awaiting/`
- `GET /api/analysis/{id}/`

### Mitigation
- `POST /api/mitigation/run/{analysis_id}/generate/`
- `GET /api/mitigation/{id}/`
- `GET /api/mitigation/overview/`

### Reporting
- `GET /api/reporting/overview/`
- `GET /api/reports/full.json`
- `GET /api/reports/assets.json`
- `GET /api/reports/raw.csv`
- `GET /api/reports/normalized.csv`

Error conventions from the provided API guide:
- `400`: invalid request, missing field, wrong state, or invalid JSON
- `401`: missing, invalid, or revoked API key
- `404`: object absent or outside scope
- `409`: duplicate queued/conflicting state

Use these conventions only after confirming actual backend responses.

Session requirements:
- Keep the active session visible.
- Make “All data” visually distinct from a specific session.
- Require clear user intent before switching scope.
- Attach the correct session context to requests.
- Invalidate/refetch session-dependent data after scope changes.
- Do not silently fall back to All data after an error.
- Keep session creation and reuse behavior aligned with backend rules.

Security:
- Do not ship a privileged API key in the frontend bundle.
- Keep automation API credentials separate from desktop GUI authentication.
- Use a secure local authentication/credential strategy, or a narrowly scoped local IPC bridge, after reviewing Tauri and Django security boundaries.
- Do not assume CORS alone secures a local service.
- Validate origin/host, request authorization, and filesystem operations appropriately.

## 9. Asynchronous job system

Implement reusable job handling for scan, analysis, and mitigation.

Requirements:
- Submit once and retain the returned job identifier.
- Poll using a configurable, restrained interval with backoff where appropriate.
- Stop polling on terminal states.
- Display queued/running/awaiting-context/completed/cancelled/failed states only when supported by the backend.
- Handle transient connection failures without creating duplicate jobs.
- Recover job display after frontend refresh by reloading from the API where possible.
- Preserve job/session association.
- Show clear retry guidance, but retry a write only when it is safe and idempotent or the backend confirms no job was created.
- Use backend-reported progress; do not fabricate percentage values.

## 10. Offline runtime and packaging

### 10.1 Desktop startup lifecycle

On launch:
1. Resolve app installation path and writable data directory.
2. Load local configuration.
3. Initialize or migrate the local database as appropriate.
4. Start the bundled Django backend.
5. Start required local workers/scanners.
6. Wait for a health/readiness check.
7. Open/enable the UI only when ready.
8. Show useful diagnostics if startup fails.
9. Avoid duplicate backend instances and handle port collisions safely.
10. Shut down child processes gracefully on app exit.

Use loopback binding by default. Do not expose the local API on all interfaces.

### 10.2 Runtime and data separation

Do not write persistent data into a temporary extraction directory or a read-only install directory.

Separate:
- Application binaries/resources
- Configuration
- Database
- Scan artifacts
- Reports/exports
- Logs
- Rules and models

Document platform-appropriate data locations and allow supported backup/export operations. Do not delete user data on upgrade/uninstall without an explicit, clearly explained action.

### 10.3 Python/backend packaging

Package the backend and dependencies so customers do not need to install Python, pip, venv, Django, Node, or npm.

Evaluate PyInstaller or another suitable bundling method against the actual project. Start with a folder-based bundle if it simplifies native libraries, data files, migrations, scanner binaries, and debugging. A single-file launcher/installer can be considered later.

Do not assume packaging Django alone also packages its database, migrations, static assets, subprocesses, scanners, or worker dependencies.

### 10.4 Database and queue

SQLite is a candidate for a single-user desktop mode, but only after testing:
- model compatibility
- transactions and migrations
- concurrent reads/writes
- worker access
- database locking and recovery

Inspect whether the backend currently requires PostgreSQL, Redis, or Celery. If so:
- Preserve the existing supported server mode.
- For desktop mode, either bundle the required service(s) or implement a local-compatible queue/worker adapter.
- Do not claim a replacement is equivalent until retry, failure, locking, duplicate prevention, and lifecycle semantics are tested.

### 10.5 Windows outputs

Produce a Windows-native build, such as:
- Installer (`.msi` or `.exe`, depending on chosen Tauri bundler)
- Optional portable folder/archive

The user should launch ECDAT from a shortcut or executable without manually starting Django or opening a terminal.

### 10.6 Linux outputs

Produce native builds for explicitly tested target distributions/architectures. Candidate formats:
- `.deb`
- `.rpm`
- AppImage
- portable `.tar.gz`

A Windows executable is not a Linux-native build. Build and test separately for each OS/architecture. Document dependencies and supported targets.

### 10.7 Browser/self-hosted output

Build the same frontend for browser use against a configured API base URL. Browser mode must clearly communicate that filesystem scanning requires a local agent, upload, mounted path, or desktop edition. Do not imply a remote server can inspect the browser user's drive.

## 11. Local AI and rules

Inspect the current analysis pipeline.

- If it calls a cloud model, replace the mandatory dependency with deterministic local analysis, a bundled local model, or a clearly optional local AI pack.
- Never claim AI reasoning occurred if it did not.
- Do not download models on first launch.
- Include model licensing, version, hardware requirements, and offline installation instructions.
- Ensure baseline discovery, analysis, and reporting work without optional AI if that is a supported product mode.
- Ruleset updates should be importable from a signed or otherwise validated offline package if updates are required.

## 12. Suggested repository layout

Adapt to the existing repository rather than moving files unnecessarily.

    ecdat/
    ├── frontend/
    │   ├── src/
    │   │   ├── app/
    │   │   ├── components/
    │   │   │   ├── layout/
    │   │   │   ├── tables/
    │   │   │   ├── charts/
    │   │   │   ├── dialogs/
    │   │   │   └── feedback/
    │   │   ├── features/
    │   │   │   ├── dashboard/
    │   │   │   ├── discovery/
    │   │   │   ├── assets/
    │   │   │   ├── analysis/
    │   │   │   ├── mitigation/
    │   │   │   ├── reports/
    │   │   │   ├── audit/
    │   │   │   └── settings/
    │   │   ├── lib/
    │   │   │   ├── api/
    │   │   │   ├── schemas/
    │   │   │   ├── errors/
    │   │   │   └── formatting/
    │   │   ├── hooks/
    │   │   ├── stores/
    │   │   └── styles/
    │   ├── public/assets/
    │   └── package.json
    ├── desktop/
    │   ├── src/
    │   ├── capabilities/
    │   ├── icons/
    │   └── tauri.conf.json
    ├── backend/                 # existing Django project
    ├── packaging/
    │   ├── windows/
    │   ├── linux/
    │   ├── scripts/
    │   └── manifests/
    └── docs/
        ├── architecture.md
        ├── offline-deployment.md
        ├── development.md
        └── troubleshooting.md

## 13. Implementation phases

### Phase 0 — Audit
- Inspect repository and report current frontend/backend structure.
- Map endpoints to actual serializers and response schemas.
- Identify external dependencies and all internet access paths.
- Identify the current database and queue requirements.
- List blockers to true offline operation.
- Produce an implementation plan before destructive changes.

### Phase 1 — Frontend foundation
- Create or adapt React/Vite application.
- Implement design tokens, theme, shell, sidebar, top bar, responsive layout.
- Implement typed API client, session state, errors, loading/empty states.
- Add route protection/guards only as supported by actual authentication.

### Phase 2 — Product pages
- Implement dashboard, scans, assets, analysis, mitigation, reports, audit, settings.
- Use real backend data.
- Implement job lifecycle and session-aware queries.
- Verify every button and form has a real action.

### Phase 3 — Offline desktop runtime
- Add Tauri integration and native file/directory selection.
- Add backend/worker launcher and health checks.
- Add local data directories and migration behavior.
- Implement safe local authentication and process shutdown.
- Remove mandatory runtime internet dependencies.

### Phase 4 — Packaging
- Create Windows installer and optional portable package.
- Create Linux package(s) for named supported targets.
- Bundle required runtime resources and produce dependency manifests.
- Include version/build metadata and diagnostics.

### Phase 5 — QA and design review
- Run unit, integration, and end-to-end tests.
- Test with networking disabled.
- Test on clean supported OS installations.
- Review UI for typography, spacing, color contrast, accessibility, responsive behavior, empty/error states, and consistency.
- Fix issues and document any remaining limitations.

## 14. Acceptance checklist

Do not mark complete until applicable checks are actually run and their results recorded.

### Offline behavior
- [ ] Application launches with network adapters disabled or outbound network blocked.
- [ ] No essential CDN, remote font, cloud API, telemetry, authentication, license, or download dependency remains.
- [ ] Required frontend assets and runtime dependencies are bundled.
- [ ] Startup errors are understandable and logged safely.

### Discovery and sessions
- [ ] User can create/select a session.
- [ ] Session ID is correctly retained and attached to requests.
- [ ] User can select a local directory through the desktop UI.
- [ ] A real scan completes or returns a truthful error.
- [ ] Job state and progress reflect backend data.
- [ ] Session isolation is tested.

### Analysis and mitigation
- [ ] Analysis can start from a completed scan.
- [ ] Awaiting-context behavior works if applicable.
- [ ] Assessment and summary fields render from actual API data.
- [ ] Mitigation plan can be generated and retrieved.
- [ ] Unsupported actions are not shown as functional.

### Reports and persistence
- [ ] Supported PDF/JSON/CSV outputs export correctly.
- [ ] CBOM output is preserved according to backend schema.
- [ ] Data survives normal restart.
- [ ] Worker/backend shutdown and restart behavior is tested.
- [ ] Upgrade behavior preserves user data.

### Packaging and security
- [ ] Windows artifact installs and launches on a clean supported environment.
- [ ] Linux artifact builds and launches on each claimed target.
- [ ] Local backend binds to loopback by default.
- [ ] No privileged API secret is present in frontend assets.
- [ ] Tauri permissions are minimal and justified.
- [ ] Filesystem operations are constrained to user-authorized paths.

### UI quality
- [ ] All pages have loading, empty, error, and populated states.
- [ ] Keyboard navigation and visible focus work.
- [ ] Contrast and status labels are accessible.
- [ ] Layout works at narrow and wide window sizes.
- [ ] No dead buttons, fake metrics, or placeholder production data remain.
- [ ] Final design review issues are resolved or documented.

## 15. Final response expected from the coding agent

When finished, report:

1. What was implemented.
2. Files/modules created or changed.
3. Actual build commands for Windows and Linux.
4. Actual tests run and their results.
5. Which offline checks were performed and how.
6. Remaining limitations or unimplemented features.
7. Required manual steps, if any.
8. Confirmation of whether any external network access remains, based on code inspection and testing—not assumption.

Never claim success for a build, test, or offline verification that was not actually performed.
