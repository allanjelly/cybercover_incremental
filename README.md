# Cybercover incremental Nuclei scanning

`cybercover_nuclei` is a self-contained Artemis module. For each `host:port` target it stores
the last successful scan date and installed `nuclei-templates` release in PostgreSQL. The client
does not pass dates or versions:

```json
{
  "targets": ["example.com"],
  "enabled_modules": ["cybercover_port_scanner", "nuclei-router", "cybercover_nuclei"]
}
```

`cybercover_port_scanner` and `nuclei-router` are required for domain/IP targets because Artemis
does not enable dependencies automatically. Do **not** also enable `port_scanner` or
`nuclei-module`; that would run duplicate port and Nuclei scans.

## Port discovery only when needed

`cybercover_port_scanner` subclasses the stock `PortScanner` and consumes the same DOMAIN/IP tasks.
For every (client, host) - the client is `original_target`, the host is the DOMAIN/IP of the task:

- no stored endpoints, or they were discovered before the newest nuclei-templates release (the
  newer of the installed and the latest GitHub release): the stock scanner runs (naabu +
  fingerprintx). The resulting SERVICE endpoints (`host`, `port`, `service`, `ssl`) replace the
  stored list in `cybercover_endpoints` and the release is stored in `cybercover_discovery_state`.
  If the scan fails nothing is stored, so discovery repeats.
- stored endpoints from the current release: no network scan. The stored endpoints are emitted as
  the same SERVICE tasks, so `nuclei-router` and `cybercover_nuclei` run as usual.

Ports opened between releases are therefore discovered only after the next release. A DNS lookup
is not repeated on replay. If the state cannot be read, full discovery runs.

## Daily incremental workflow

1. The worker checks GitHub's latest `nuclei-templates` release. If a newer release exists than
   the mounted local templates, it runs `nuclei -update-templates` under Artemis' template lock.
   The installed release is verified before proceeding.
2. It fetches `main/.new-additions` once per UTC day and installed release. The snapshot is
   cached in Artemis Redis for 30 days.
3. For an existing target on the same release, it compares today's list with the cached list
   from that target's last scan date. Only paths newly present in today's list are selected.
   If the old daily snapshot has expired or Redis lost it, the worker scans today's full list
   rather than risk skipping additions.
4. For a first scan or a release transition, the worker also reads the installed release's
   `.new-additions` list, the same source used by Nuclei's `-nt`. Changes listed in today's
   `main/.new-additions` are fetched from GitHub and cached per file for 30 days. When a path
   occurs in both lists, the downloaded `main` version takes precedence.
5. Before starting Nuclei, the worker keeps only `high` and `critical` templates and excludes
   any template in `headless/` or containing a `headless` section, including mixed-protocol
   templates. A stricter Artemis severity threshold, such as `critical_only`, still applies;
   a lower threshold cannot enable medium, low, info or unknown templates. Artemis' tag
   exclusions also apply. The selected files are passed explicitly, without `-nt`, so the
   release list cannot bypass these filters. This policy affects only the incremental module.
6. If filtering leaves no templates, the worker records a successful no-eligible-templates
   result without starting Nuclei. After a successful scan or no-eligible result, it stores the
   installed release and current scan time. Lookup, invalid template metadata, missing release
   files or scan errors do not advance the state. If any Nuclei run fails, the task is marked
   as an error and any partial findings are retained.

The cached custom YAML files are held in a temporary directory only for the duration of a scan;
their contents are shared across customers through Redis. Installed-release templates are read
from their original locations, while changes from `main` use temporary files.
A full scan should still be scheduled separately every two weeks to catch anything missed by
the best-effort daily incremental workflow.

The database table is `cybercover_scan_state` in Artemis' PostgreSQL (`POSTGRES_CONN_STR`). It
is created automatically with separate SQLAlchemy metadata, outside Artemis' Alembic migrations.
State is currently per endpoint (`host:port`), not per business-level customer record.

## Deployment

1. Apply `artemis-docker-compose.patch` (adds the `karton-cybercover-nuclei` and
   `karton-cybercover-port-scanner` services) and place
   this package's `cybercover/` directory next to the compose file (or set `CYBERCOVER_DIR`).
2. Keep the module out of full scans by adding `cybercover_nuclei` to `MODULES_DISABLED_BY_DEFAULT`
   in `.env` (also `cybercover_port_scanner`). This variable replaces Artemis' default list, so repeat it:
   `MODULES_DISABLED_BY_DEFAULT=admin_panel_login_bruter,dangling_dns_detector,example,humble,leak_scanner,ssh_bruter,xss_scanner,cybercover_nuclei,cybercover_port_scanner`
3. Restart `karton-cybercover-nuclei` daily before the scan window. Artemis refreshes its in-memory
   template lists when the worker starts.
4. Optional: `CYBERCOVER_GITHUB_TOKEN` (a read-only token) raises GitHub API rate limits.

The Nuclei HTML reporter ignores results from this module (it accepts only `nuclei` and
`nuclei-module`), but `/api/task-results?only_interesting=false` returns them.

## Tests

Importing Artemis needs Redis, a writable `/data` and a Karton config. Run
`python -m pytest tests` with `PYTHONPATH=.:<Artemis checkout>`.
