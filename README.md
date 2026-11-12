# Cybercover incremental Nuclei scanning

Two self-contained Artemis modules for cheap daily scans between the monthly full scans:

- `cybercover_port_scanner` - port discovery only when needed (otherwise stored ports are replayed);
- `cybercover_nuclei` - runs only nuclei templates added since the customer's last incremental scan.

**Full scan** (monthly): the standard Artemis request, only targets. These two modules are disabled by
default (see Deployment), so the stock `port_scanner` and `nuclei-module` run:

```json
{"targets": ["example.com"]}
```

**Incremental scan** (daily): the same targets, enabling exactly these three modules. Artemis does not
enable dependencies automatically, so `nuclei-router` is required; do **not** also enable
`port_scanner` or `nuclei-module` (duplicate scans):

```json
{
  "targets": ["example.com"],
  "enabled_modules": ["nuclei-router", "cybercover_port_scanner", "cybercover_nuclei"]
}
```

The client does not pass dates or versions; all state is kept per customer in PostgreSQL. The customer
("client") is the `original_target` Artemis records for every task derived from a requested target,
so customers sharing a host (e.g. shared hosting) never share state.

## Port discovery only when needed

`cybercover_port_scanner` subclasses the stock `PortScanner` and consumes the same DOMAIN/IP tasks.
For every (client, host), in this order:

1. **Adopt the full scan.** If Artemis' stock `port_scanner` completed a scan of the same (client,
   host) more recently than the stored endpoints and within the age limit - typically the monthly
   full scan - its result is adopted: no network scan. The age limit counts from that scan.
2. **Replay.** Stored endpoints from the current nuclei-templates release (the newer of the installed
   and the latest GitHub release) and younger than `CYBERCOVER_PORT_DISCOVERY_MAX_AGE_DAYS`
   (default 7) are replayed: no network scan.
3. **Discover.** Otherwise the stock scanner runs (naabu + fingerprintx). The resulting SERVICE
   endpoints replace the stored list. If the scan fails nothing is stored, so discovery repeats.

Replayed and adopted endpoints are emitted as the same SERVICE tasks, so `nuclei-router` and
`cybercover_nuclei` run as usual. The task result is `OK` with
`{host: {port: {"service", "ssl", "source"}}}`, where `source` is `replayed` (own earlier discovery)
or `full_scan` (adopted); reporters must not present these as new findings. A newly discovered result
has the stock format and status. A port opened since the last discovery is found within the age
limit at the latest. If GitHub is unreachable, the last release seen in the past 30 days is used, so
the version does not flip back to the installed release. If the state cannot be read, full discovery
runs. A DNS lookup is not repeated on replay.

## Daily incremental workflow

1. The worker checks GitHub's latest `nuclei-templates` release. If a newer release exists than
   the mounted local templates, it runs `nuclei -update-templates`. It holds the same template lock
   as Artemis' `nuclei-module` (both update the shared templates volume) and skips the update if the
   other module installed the release meanwhile. The installed release is verified before proceeding.
2. It fetches `main/.new-additions` once per UTC day and installed release. The snapshot is
   cached in Artemis Redis for 30 days. The snapshot date is fixed when a batch starts.
3. For an existing customer endpoint on the same release, it compares today's list with the
   snapshot used by that endpoint's last successful scan (stored with the state, so a scan running
   past midnight UTC does not skip later additions). Only paths newly present are selected.
   If the old snapshot has expired or Redis lost it, the worker scans today's full list
   rather than risk skipping additions.
4. For a first scan or a release transition, the worker also reads the installed release's
   `.new-additions` list, the same source used by Nuclei's `-nt`. Templates listed in today's
   `main/.new-additions` are fetched from GitHub and cached per file for 30 days. When a path
   occurs in both lists, the downloaded `main` version takes precedence.
5. Before starting Nuclei, the worker keeps only `high` and `critical` templates and excludes
   any template in `headless/` or containing a `headless` section, including mixed-protocol
   templates. A stricter Artemis severity threshold, such as `critical_only`, still applies;
   a lower threshold cannot enable medium, low, info or unknown templates. Artemis' tag
   exclusions also apply. The selected files are passed explicitly, without `-nt`, so the
   release list cannot bypass these filters. This policy affects only the incremental module.
6. Broken input is skipped, not fatal, so one bad file never blocks every customer: invalid entries
   in a `.new-additions` list, templates with invalid YAML or metadata, files listed by the release
   but missing on disk, and batches the installed Nuclei engine cannot load at all (e.g. templates
   from `main` needing a newer engine). Each is logged and counted in the Prometheus metric
   `cybercover_templates_skipped_total{reason}`. The Nuclei engine version is logged per batch.
7. If filtering leaves no templates, the worker records a successful no-eligible-templates
   result without starting Nuclei. After a successful scan or no-eligible result, it stores the
   installed release and the snapshot date. A failed GitHub lookup, a missing release
   `.new-additions` file, or a failed Nuclei run does not advance the state; if any Nuclei run
   fails, the task is marked as an error and any partial findings are retained.
8. Findings from templates downloaded from `main` carry the template's repository path in
   `template` (as for installed templates), not the temporary file path. Homepage links are crawled
   only if a selected template is on Artemis' homepage-links template list.

The cached custom YAML files are held in a temporary directory only for the duration of a scan;
their contents are shared across customers through Redis. Installed-release templates are read
from their original locations, while templates from `main` use temporary files.

**Limits.** `.new-additions` lists only *new* templates: templates modified in `main` (e.g. improved
matchers) are not rescanned until the next full scan, which must still run monthly. A template
skipped as invalid is not retried incrementally either. No restart of the worker is needed when a
release is published: it updates the templates itself before the next batch.

**State tables** in Artemis' PostgreSQL (`POSTGRES_CONN_STR`), created automatically with separate
SQLAlchemy metadata, outside Artemis' Alembic migrations:

- `cybercover_scan_state_v2` - per (client, host, port): release and snapshot date of the last scan.
  Endpoints without a row are treated as first scans. When upgrading from an earlier version, drop
  the obsolete `cybercover_scan_state` table (keyed by `host:port` only):
  `DROP TABLE IF EXISTS cybercover_scan_state;`
- `cybercover_discovery_state`, `cybercover_endpoints` - per (client, host): discovered endpoints,
  their release and discovery time.

## Deployment

1. Clone this repository as `cybercover_incremental` inside the Artemis directory (next to
   Artemis' `docker-compose.yaml`) and run `./scripts/start` (or `--mode=development`). No Artemis
   file is modified: Artemis' `scripts/find_docker_compose_files` automatically includes every
   `*/docker-compose.yml`, so this repo's `docker-compose.yml` adds the `karton-cybercover-nuclei`
   and `karton-cybercover-port-scanner` services (the same mechanism Artemis-modules-extra uses).
   Development mode generates `docker-compose.dev.yml` from it. To mount the code from elsewhere,
   set `CYBERCOVER_DIR` in `.env` (default `./cybercover_incremental/cybercover`).
2. Keep the module out of full scans by adding `cybercover_nuclei` to `MODULES_DISABLED_BY_DEFAULT`
   in `.env` (also `cybercover_port_scanner`). This variable replaces Artemis' default list, so repeat it:
   `MODULES_DISABLED_BY_DEFAULT=admin_panel_login_bruter,dangling_dns_detector,example,humble,leak_scanner,ssh_bruter,xss_scanner,cybercover_nuclei,cybercover_port_scanner`
3. Optional: `CYBERCOVER_GITHUB_TOKEN` (a read-only token) raises GitHub API rate limits.
4. Optional: `CYBERCOVER_PORT_DISCOVERY_MAX_AGE_DAYS` (default `7`) - how old stored ports may be
   before they are rediscovered.

The Nuclei HTML reporter ignores results from this module (it accepts only `nuclei` and
`nuclei-module`), but `/api/task-results?only_interesting=false` returns them.

## Upgrading Artemis

The modules subclass stock Artemis modules and rely on some of their internals, so an Artemis
upgrade can break them without any Artemis file having been modified. Last verified against Artemis
commit `8a79b34` (`certpl/artemis:latest` of 2026-11-12). After pulling a new Artemis version or image:

1. Run the test suite against the new image (`ARTEMIS_BUILD_IMAGE=<new image> tests/run_in_docker.sh`).
2. Check that these internals still exist and behave as described; review their diff since the last
   verified commit (`git diff 8a79b34 -- artemis/modules/nuclei.py artemis/modules/port_scanner.py ...`):
   - `artemis.modules.nuclei`: `Nuclei.run_multiple` (scans the template list once per category, then
     repeats it for homepage links), `Nuclei._scan(templates, scan_using, targets, ...)`, `_get_links`,
     `NUCLEI_TEMPLATES_LOCATION`, `ScanUsing`, and the module-level
     `check_output_log_on_error_with_stderr` (temporarily wrapped to detect failed Nuclei runs, which
     the stock `_scan` swallows);
   - `artemis.modules.port_scanner`: `PortScanner.run_multiple` and `add_task`, and the shape of its
     task result (read from `task_result` to adopt full-scan ports);
   - `artemis.resource_lock.ResourceLock` and the `nuclei-module` identity (the shared template lock);
   - `artemis.db.TaskResult` columns (`receiver`, `target_string`, `status`, `task`, `result`,
     `created_at`), and `original_target` in the task's `payload_persistent`.
3. Run one full and one incremental scan of a test target and check the worker logs (template
   update, adopted or replayed ports, number of selected templates).
4. Check that `MODULES_DISABLED_BY_DEFAULT` in `.env` still contains Artemis' current default list
   plus the two Cybercover modules (see Deployment).

## Tests

Importing Artemis needs Redis, PostgreSQL, a writable `/data` and a Karton config. The script
below runs the suite in the Artemis image with throwaway Redis/PostgreSQL
(`tests/test-stack.compose.yaml`, separate from Artemis' compose files) and removes them afterwards:

```sh
tests/run_in_docker.sh                 # whole suite
tests/run_in_docker.sh tests -k port   # any pytest arguments
```

`ARTEMIS_BUILD_IMAGE` selects the image (default `certpl/artemis:latest`).
