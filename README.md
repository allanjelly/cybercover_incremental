# Cybercover incremental Nuclei scanning

`cybercover_nuclei` is a self-contained Artemis module. For each `host:port` target it stores
the last successful scan date and installed `nuclei-templates` release in PostgreSQL. The client
does not pass dates or versions:

```json
{
  "targets": ["example.com"],
  "enabled_modules": ["port_scanner", "nuclei-router", "cybercover_nuclei"]
}
```

`port_scanner` and `nuclei-router` are required for domain/IP targets because Artemis does not
enable dependencies automatically. Do **not** also enable `nuclei-module`; that would run a
second Nuclei scan.

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
4. For a first scan or a release transition, it also obtains Nuclei's native `-nt` template
   list. Changes listed in today's `.new-additions` are fetched from GitHub `main`, cached per
   file for 30 days, and passed to Nuclei as explicit template paths.
5. After a successful scan (or a successful no-change result), it stores the installed release
   and current scan time. Lookup or scan errors do not advance the state.

The cached custom YAML files are held in a temporary directory only for the duration of a scan;
their contents are shared across customers through Redis. Nuclei release transitions are
handled by native `-nt`; subsequent daily changes from `main` are scanned as custom templates.
A full scan should still be scheduled separately every two weeks to catch anything missed by
the best-effort daily incremental workflow.

The database table is `cybercover_scan_state` in Artemis' PostgreSQL (`POSTGRES_CONN_STR`). It
is created automatically with separate SQLAlchemy metadata, outside Artemis' Alembic migrations.
State is currently per endpoint (`host:port`), not per business-level customer record.

## Deployment

1. Apply `artemis-docker-compose.patch` (adds the `karton-cybercover-nuclei` service) and place
   this package's `cybercover/` directory next to the compose file (or set `CYBERCOVER_DIR`).
2. Keep the module out of full scans by adding `cybercover_nuclei` to `MODULES_DISABLED_BY_DEFAULT`
   in `.env`. This variable replaces Artemis' default list, so repeat it:
   `MODULES_DISABLED_BY_DEFAULT=admin_panel_login_bruter,dangling_dns_detector,example,humble,leak_scanner,ssh_bruter,xss_scanner,cybercover_nuclei`
3. Restart `karton-cybercover-nuclei` daily before the scan window. Artemis refreshes its in-memory
   template lists when the worker starts.
4. Optional: `CYBERCOVER_GITHUB_TOKEN` (a read-only token) raises GitHub API rate limits.

The Nuclei HTML reporter ignores results from this module (it accepts only `nuclei` and
`nuclei-module`), but `/api/task-results?only_interesting=false` returns them.

## Tests

Importing Artemis needs Redis, a writable `/data` and a Karton config. Run
`python -m pytest tests` with `PYTHONPATH=.:<Artemis checkout>`.
