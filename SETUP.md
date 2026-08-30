# ECDAT — Setup & Run

Enterprise Cryptographic Discovery & Analysis Tool (MVP, Discovery + Dashboard).

## Prerequisites

- Python 3.12+
- Node.js 18+ (for the Tailwind CSS build)
- Git (optional)

## Environment

Copy the template if you have no `.env` yet (a `.env` already exists in the working tree with sensible defaults):

```powershell
Copy-Item .env.example .env
```

Key variables (see `.env`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `DJANGO_SECRET_KEY` | dev key | Django secret (change in prod) |
| `DJANGO_DEBUG` | `1` | Debug mode; `0` for live |
| `DJANGO_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Used only when `DJANGO_DEBUG=0` |
| `ECDAT_DEMO_MODE` | `1` | Enables demo datasets & seed command |

## 1. Create & activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

## 2. Install dependencies

```powershell
pip install -r requirements.txt
```

## 3. Install frontend build tooling (Tailwind CSS)

The dashboard uses Tailwind CSS compiled by the Tailwind CLI. Install the
dev dependency and build the stylesheet:

```powershell
npm install
npm run build
```

Output: `dashboard/static/dashboard/css/tailwind.css` (already generated in
the working tree). 

> **Important:** If you edit any Django template or JS, re-run `npm run build`
> before loading the page so new utility classes are included. During
> development you can auto-rebuild with `npm run watch`.

## 4. Run migrations

```powershell
.\venv\Scripts\python.exe manage.py makemigrations
.\venv\Scripts\python.exe manage.py migrate
```

> `makemigrations` only needed if you change the models; fresh clones just need `migrate`.

## 5. Seed demo data (optional)

Creates a demo `ScanJob` that runs the demo scanner through the full pipeline
(ingest → normalize → classify → correlate) so the dashboard is populated.

```powershell
.\venv\Scripts\python.exe manage.py seed_demo
```

You can also trigger it from the UI later using the **Run Discovery** button.

## 6. Run the server

```powershell
.\venv\Scripts\python.exe manage.py runserver
```

Open: <http://127.0.0.1:8000/>

## What you can do in the UI

| Page | Path | What it shows |
|------|------|---------------|
| Overview | `/` | KPIs, charts (family, source), recent scans, latest audit |
| Discovery & Inventory | `/discovery/` | Crypto asset inventory + raw findings + scan history |
| Asset Graph | `/graph/` | Correlation graph of assets (ECharts force layout) |
| Audit Log | `/audit/` | Full audit trail |

Click **Run Discovery** in the top bar to re-run the demo pipeline (HTMX POST to `/api/run-demo-scan/`).

## API

DRF endpoints under `/api/` (browsable API):

- `/api/scans/`
- `/api/raw-findings/`
- `/api/normalized-findings/`
- `/api/assets/`
- `/api/relations/`
- `/api/stats/` (aggregate widget data)

## Reports / Exports

- `/reports/assets.csv` · `/reports/assets.json`
- `/reports/raw.csv`
- `/reports/normalized.csv`

## Common commands

```powershell
# run checks
.\venv\Scripts\python.exe manage.py check

# rebuild the Tailwind stylesheet (also after template edits)
npm run build

# create a superuser (for /admin)
.\venv\Scripts\python.exe manage.py createsuperuser

# wipe + reseed demo data
Remove-Item db.sqlite3; .\venv\Scripts\python.exe manage.py migrate; .\venv\Scripts\python.exe manage.py seed_demo
```

## Configuration : PostgreSQL (optional, production)

1. Install the driver: `pip install psycopg2-binary`
2. Fill the `DB_*` variables in `.env` and uncomment them (plus `DB_ENGINE`).
3. Migrate as above.

For the local demo the bundled SQLite (`db.sqlite3`) is sufficient.
