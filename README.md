# Cybercover incremental Nuclei scanning

`cybercover_nuclei` is a self-contained Artemis module (a subclass of the stock `Nuclei`
module). No Artemis source file is changed. For every scanned `host:port` it keeps the
`nuclei-templates` release it was last scanned with and runs only the templates added or
modified since then. The client passes nothing about dates or versions:

```json
{
  "targets": ["example.com"],
  "enabled_modules": ["port_scanner", "nuclei-router", "cybercover_nuclei"]
}
```

`port_scanner` and `nuclei-router` are required for domain/IP targets, because Artemis does not
enable dependencies automatically. Do **not** also enable `nuclei-module`: it would run the same
scan a second time.

## How a scan works

1. The worker takes the `host:port` of each `NUCLEI_TARGET` task.
2. It reads the last scanned templates version of each target from the `cybercover_scan_state`
   table (same PostgreSQL as Artemis, `POSTGRES_CONN_STR`; the table is created automatically
   and is not touched by Artemis' migrations). A target seen for the first time starts from the
   release before the installed one (`GET /releases`, cached in Redis).
3. It asks GitHub for `compare/<last version>...<installed version>` and keeps the added and
   modified template files (cached in Redis; targets with the same version share one lookup).
4. It runs the standard Nuclei scan with only those templates. If nothing changed, the task
   gets an OK result "No new templates" and no scan is run.
5. After a successful scan it stores the installed version for the target. If the scan or the
   lookup fails, the stored version is not moved, so nothing is lost.

If the gap is too large for the GitHub compare API (it returns at most 300 files), that target
gets a **full scan** and the version is then updated. Custom templates and workflows are not
part of incremental scans. Each task result carries `payload_persistent.templates_version`
(the installed release) and `templates_after_version` (the baseline, `null` for a full scan).

Nuclei-templates releases come out about every 2-3 weeks, so most daily scans find nothing new.

## Deployment

1. Apply `artemis-docker-compose.patch` (adds the `karton-cybercover-nuclei` service) and place
   this package's `cybercover/` directory next to the compose file (or set `CYBERCOVER_DIR`).
2. Keep the module out of full scans: add `cybercover_nuclei` to `MODULES_DISABLED_BY_DEFAULT` in
   `.env`. The variable replaces Artemis' default list, so repeat it:
   `MODULES_DISABLED_BY_DEFAULT=admin_panel_login_bruter,dangling_dns_detector,example,humble,leak_scanner,ssh_bruter,xss_scanner,cybercover_nuclei`
3. The worker updates templates only when it starts: restart `karton-cybercover-nuclei` daily
   before the scan window so that new releases are picked up.
4. Optional: `CYBERCOVER_GITHUB_TOKEN` (a read-only token) raises the GitHub API rate limit.

The Nuclei HTML reporter ignores results of this module (it accepts only `nuclei` and
`nuclei-module`), but `/api/task-results` returns them.

## Tests

Importing Artemis needs Redis, a writable `/data` and a karton config; see the commands used in
the repository history. Run `python -m pytest tests` with `PYTHONPATH=.:<Artemis checkout>`.
