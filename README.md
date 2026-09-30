# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

> **Problem Statement 26164 · Smart India Hackathon 2026 · Blockchain & Cybersecurity**

| | |
|---|---|
| **Problem Statement ID** | 26164 |
| **Problem Statement Title** | Enterprise Cryptographic Discovery & Analysis Tool (ECDAT) |
| **Theme** | Blockchain & Cybersecurity |
| **PS Category** | Software |
| **Team ID** | 123202 |
| **Team Name** | Your Team |

> ⚠️ **Before submitting, replace `Your Team` with your registered team name.** It
> was left as a placeholder in the brief.

---

## The problem

An organisation can hold thousands of cryptographic assets it does not have an
inventory of: certificates in a trust store, keys referenced from code, libraries
pulled in by a dependency tree, algorithms embedded in binaries, cloud key vaults
and HSM-backed services. Nobody can say what exists, what depends on what, or what
would still be safe the day a cryptographically relevant quantum computer exists.

Inventory tools exist, but they answer a narrower question. They list what is
present. They do not correlate it, grade it against a quantum threat model, or turn
it into a sequenced plan. Teams end up doing that correlation by hand in
spreadsheets, which is exactly the work that never gets done.

## What ECDAT does

ECDAT takes a target — a folder, an image, a dependency tree — and carries it
end to end:

1. **Discover.** Several scanners run over the same target in a single job,
   producing raw findings: every certificate, key, algorithm reference, library and
   protocol it can see, each with the file it came from.
2. **Normalise and correlate.** Findings are deduplicated into assets, then linked
   into a graph — asset depends on library, certificate issued by authority, key
   referenced by configuration — so impact can be reasoned about rather than
   counted.
3. **Assess.** Each asset is graded by two agents:
   - **MOSCA** — cryptographically significant algorithms, measuring how hard an
     asset is to harvest and break.
   - **HNDL** — *harvest now, decrypt later*, weighing data that must stay
     confidential for years against when the algorithm is expected to fall.
4. **Produce a bill of materials.** A CBOM in CycloneDX or ECDAT's own richer
   native format, carrying validation status and confidence per asset.
5. **Plan the migration.** Assets are grouped into sequenced migration waves with
   concrete replacements (FIPS 203 ML-KEM, FIPS 204 ML-DSA, AES-256-GCM) and a
   per-asset remediation action.

Every step is auditable: the audit trail records what was scanned, what was
decided, and by which actor, and it survives deletion of the data itself.

## How it runs

```
Discovery  →  Normalise  →  Correlate  →  Graph  →  Assess (MOSCA + HNDL)  →  CBOM  →  Waves
  scan         dedup        links         nodes      per-asset grading     export   sequencing
```

**Scopes are hard boundaries.** Scans never share data. Every asset, finding, run
and report belongs to a `WorkSession`, and selecting a different scan changes what
every view shows. Deleting a scan's data keeps its audit trail.

## Repository layout

| Path | What lives there |
|---|---|
| `backend/` | Django 5 + DRF API, scanners, ML agents, workers. See [`backend/README.md`](backend/README.md). |
| `frontend/` | Next.js 16 + React 19 console. See [`frontend/README.md`](frontend/README.md). |
| `run.sh` / `run.ps1` | One-command launcher for the whole stack. |
| `backend/schema/contracts/` | The payload contracts segments exchange. |
| `backend/docs/` | API reference, calling flow, ERD, segment rules. |
| `ECDAT_Offline_Frontend_and_Packaging_Guide.md` | Offline/air-gapped deployment. |

## Quick start

Requires **Python 3.12+** and **Node 20+**.

```bash
git clone <repo-url> ECDAT
cd ECDAT

# Backend
cd backend
python -m venv venv
source venv/Scripts/activate     # Windows (Git-Bash/WSL); Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env             # optional; sensible defaults apply without it
python manage.py migrate

# Frontend
cd ../frontend
npm install

# Run everything
cd .. && ./run.sh
```

`run.sh` asks which UI mode to use, migrates, starts the API on `127.0.0.1:8000`,
starts a background worker, waits for the backend to report healthy, then opens the
UI on `localhost:3000`. On Windows use `run.ps1`.

Non-interactive examples:

```bash
./run.sh --mode browser-dev         # Next dev server with hot reload
./run.sh --mode browser-preview     # production build, served
./run.sh --mode backend-only        # API and worker only
./run.sh --mode browser-preview --rebuild
```

Full flag list: `./run.sh --help`.

### Verifying it works

```bash
curl http://127.0.0.1:8000/api/health/          # {"status": "ok", ...}
cd frontend && npm run check                     # lint + typecheck + JSX nesting
cd ../backend && python manage.py test           # 578 tests
```

## Configuration

Settings come from the environment, read through `.env` at the backend root. Every
variable is optional — the app runs with no configuration at all.

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | insecure dev value | **Set this in any deployment.** |
| `DJANGO_DEBUG` | `1` | `0` for production |
| `DJANGO_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Comma-separated |
| `ECDAT_FRONTEND_ORIGINS` | localhost:3000 | CORS allowlist |
| `ECDAT_REQUIRE_API_KEY` | auto | `1`/`0` to force `X-API-Key` on `/api/` |
| `ECDAT_QUEUE_ASYNC` | `0` | `1` routes jobs through the huey worker |
| `ECDAT_AUTO_ANALYSE` | `1` | `0` disables staging analysis after a scan |
| `ECDAT_AUTO_CONTEXT_TIMEOUT` | `60` | Seconds an unattended context prompt waits |
| `GEMINI_API_KEY*` | — | Per-agent keys: `MOSCA`, `HNDL`, `CBOM`, `MITIGATION`, `SYNTHESIS`, `FINAL`, or plain `GEMINI_API_KEY` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | — | Alternative provider |
| `GEMINI_MODEL` | provider default | |
| `ECDAT_MITIGATION_OFF` | unset | `1` disables the mitigation workstream |
| `ECDAT_CHROMIUM` | — | Chromium path for container image scanning |
| `HUEY_IMMEDIATE` / `HUEY_DB` | — | Queue behaviour and location |

**Without an LLM key the agents fall back to deterministic rule-based providers**,
so the whole pipeline runs offline and testably. Every key is per-agent, so the
noisiest workstream can be budgeted or disabled independently.

## Testing

```bash
cd backend && python manage.py test          # 578 tests
cd frontend && npm run check                 # eslint, tsc, JSX-nesting guard
```

See [Known limitations](#known-limitations) — the suite is not currently green.

## Known limitations

Stated plainly, because a claim of completeness that isn't true is worse than a
short list.

- **The test suite is not green.** 578 tests, of which 10 fail and 3 error. All 13
  are pre-existing and outside the happy path. The 3 errors are missing optional
  dependencies — the ML stack (`joblib`, `pytest`, `src.predict`) is not listed in
  `requirements.txt`; installing it would clear two of them. The 10 failures are in
  mitigation document generation, the report builder, one discovery library test and
  one crypto invariant. Verified as failing at `HEAD` with no local changes.
- **Authentication is optional and off by default.** The API key gate
  (`ECDAT_REQUIRE_API_KEY`) auto-enables only when `DEBUG=0`. With it off, audit
  `actor` is a *claimed* value, not a verified identity.
- **The audit trail is append-only by convention, not by enforcement.** SQLite
  `DROP TABLE` bypasses the immutability triggers.
- **Cloud and HSM discovery are declared but not credentialed.** `cloud` and `hsm`
  source types exist in the model; scanning them needs authorised accounts that are
  deliberately not in the repository.
- **Secrets have been exposed in git history.** A real `.env` and a populated
  SQLite database were committed before `.gitignore` covered them. Any key in that
  history must be treated as compromised and rotated. History has not been
  rewritten.
- **`DJANGO_SECRET_KEY` falls back to a hardcoded insecure value.** Fine for
  development, not for anything else.

## Licence

*(To be stated. Add the licence the team intends to submit under.)*

## Acknowledgements

Built for **Smart India Hackathon 2026** —
Problem Statement **26164**, *Enterprise Cryptographic Discovery & Analysis Tool
(ECDAT)*, under the **Blockchain & Cybersecurity** theme, Software category.
Team ID **123202**.
