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

An **empty** port list (the host was down or filtered during that scan) is never replayed or adopted:
the next incremental scan runs discovery again, so a host with no open ports costs one quick port scan
per day instead of being skipped for the whole age limit. One endpoint is kept per port: when the IPs
of a domain expose the same port with different fingerprints, the TLS variant is kept. Each host's
endpoints are stored separately, so a failure for one host does not affect the others.

**Hosts from the full scan (subdomains).** With `enabled_modules`, Artemis disables subdomain
enumeration, so an incremental scan would only reach the requested targets. Once per analysis and
client, the module therefore adds a DOMAIN task for every domain of the client that the stock
`port_scanner` scanned in the last `CYBERCOVER_FULL_SCAN_HOSTS_MAX_AGE_DAYS` (default 40) - in
practice the subdomains found by the last monthly full scan, at most `CYBERCOVER_FULL_SCAN_HOSTS_LIMIT`
(default 500). Like Artemis' subdomain enumeration it skips domains that no longer resolve or show a
placeholder page. These hosts then go through adopt, replay or discover like the requested target,
and `cybercover_nuclei` scans them. If the host lookup or adding a host fails, the other hosts are
still added and a retry of the task tries again; this also happens when the module falls back to
plain discovery. Subdomains that appeared after the full scan are found by the
next full scan. The full scan's results must still exist, so raise Artemis' archiver age (see
Deployment).

Replayed and adopted endpoints are emitted as the same SERVICE tasks, so `nuclei-router` and
`cybercover_nuclei` run as usual. The task result is `OK` with
`{host: {port: {"service", "ssl", "source"}}}`, where `source` is `replayed` (own earlier discovery)
or `full_scan` (adopted); reporters must not present these as new findings. A newly discovered result
has the stock format and status. A port opened since the last discovery is found within the age
limit at the latest; the stock scanner caches port results per IP for 24 hours, so stored or adopted
ports can be up to a day older than their timestamp. If GitHub is unreachable, the last release seen in the past 30 days is used, so
the version does not flip back to the installed release. If the state cannot be read, full discovery
runs. A DNS lookup is not repeated on replay.

## Daily incremental workflow

1. The worker checks GitHub's latest `nuclei-templates` release. If a newer release exists than
   the mounted local templates, it runs `nuclei -update-templates`. It holds the same template lock
   as Artemis' `nuclei-module` (both update the shared templates volume) and skips the update if the
   other module installed the release meanwhile. The installed release is verified before proceeding.
2. It fetches `main/.new-additions` once per UTC day and installed release. The snapshot is
   cached in Artemis Redis for 30 days. The snapshot date is fixed when a batch starts. Only the
   first worker's snapshot of a day is stored (Redis `SET NX`); other workers use that one, so all
   scans of a day use the list the next day's diff starts from.
3. For an existing customer endpoint on the same release, it compares today's list with the
   snapshot used by that endpoint's last successful scan (stored with the state, so a scan running
   past midnight UTC does not skip later additions). Only paths newly present are selected.
   If the old snapshot has expired or Redis lost it, the worker scans today's full list
   rather than risk skipping additions.
4. For a first scan or a release transition, the worker also reads the installed release's
   `.new-additions` list, the same source used by Nuclei's `-nt`. A release's list contains only
   what was added since the previous release, so when an endpoint's last scan was more than one
   release ago (e.g. v10.5.0 -> v10.5.2), the lists of the releases in between are added too (release
   list from the GitHub API, each release's `.new-additions` from GitHub, cached); their templates
   are read from the installed templates, and ones removed upstream since are skipped. If the
   releases in between cannot be determined (e.g. GitHub unreachable), the state is not advanced.
   A release that has no `.new-additions` file at all (GitHub answers 404; a release without new
   templates has an empty file) is skipped with a warning and counted as `release_without_list` in
   `cybercover_templates_skipped_total`, so it cannot block the endpoints scanned before it; its
   templates wait for the next full scan. A release list cached earlier the same day is fetched again
   if it does not reach the installed release. Release templates are read
   under the template lock shared with `nuclei-module`, so a template update cannot remove them
   while they are read. Templates listed in today's `main/.new-additions` are fetched from GitHub
   and cached per file for 30 days. When a path occurs in both lists, the downloaded `main` version
   takes precedence.
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
   fails, the task is marked as an error and any partial findings are retained. When Artemis retries
   a batch because a task returned an error (`SLOW_MODULE_NUM_RETRIES` above 1), tasks already
   completed in the first try are not scanned or saved again. An unexpected exception in one group of
   endpoints of a batch fails only that group; and when Artemis marks a whole batch as failed (e.g. a
   timeout), tasks completed earlier in the batch keep their results.
8. Findings from templates downloaded from `main` carry the template's repository path in
   `template` (as for installed templates), not the temporary file path. Homepage links are crawled
   only if a selected template is on Artemis' homepage-links template list.

The cached custom YAML files are held in a temporary directory only for the duration of a scan;
their contents are shared across customers through Redis. Installed-release templates are read
from their original locations, while templates from `main` use temporary files.

**Limits.** `.new-additions` lists only *new* templates: templates modified in `main` (e.g. improved
matchers) are not rescanned until the next full scan, which must still run monthly. Scan state is
kept per (client, host, port), not per scheme: a second HTTP/HTTPS target on the same port in a later
batch of the same day counts as already scanned. A template
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
   Artemis' `docker-compose.yaml`) and start Artemis at a pinned image (see "Starting Artemis" below).
   No Artemis file is modified: Artemis' `scripts/find_docker_compose_files` automatically includes
   every `*/docker-compose.yml`, so this repo's `docker-compose.yml` adds the
   `karton-cybercover-nuclei` and `karton-cybercover-port-scanner` services (the same mechanism
   Artemis-modules-extra uses). To mount the code from elsewhere, set `CYBERCOVER_DIR` in `.env`
   (default `./cybercover_incremental/cybercover`).
2. Keep the module out of full scans by adding `cybercover_nuclei` to `MODULES_DISABLED_BY_DEFAULT`
   in `.env` (also `cybercover_port_scanner`). This variable replaces Artemis' default list, so repeat it:
   `MODULES_DISABLED_BY_DEFAULT=admin_panel_login_bruter,dangling_dns_detector,example,humble,leak_scanner,ssh_bruter,xss_scanner,cybercover_nuclei,cybercover_port_scanner`
3. Optional: `CYBERCOVER_GITHUB_TOKEN` (a read-only token) raises GitHub API rate limits.
4. Optional: `CYBERCOVER_PORT_DISCOVERY_MAX_AGE_DAYS` (default `7`) - how old stored ports may be
   before they are rediscovered.
5. Set Artemis' archiver age for non-interesting results above the full-scan interval, e.g. 40 days:
   `AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING=3456000`. Artemis' default (15 days) removes the full
   scan's port results, which the incremental scan uses to find the client's subdomains, and the
   module errors the reports service uses for completeness. Optional:
   `CYBERCOVER_FULL_SCAN_HOSTS_MAX_AGE_DAYS` (default `40`; keep it at or below the archiver age) and
   `CYBERCOVER_FULL_SCAN_HOSTS_LIMIT` (default `500`).
6. `docker-compose.yml` also disables three stock services by putting them in the
   `cybercover-disabled` profile, which is never activated, so they are not started:
   - `karton-api_scanner`: the module was removed upstream, but its service is still in Artemis'
     compose file.
   - `karton-shodan_vulns`: needs `SHODAN_API_KEY`, which requires a paid plan for commercial use.
     Its CVEs are inferred from service banners and Artemis has no reporter for it.
   - `karton-removed_domain_existing_vhost`: needs a passive DNS source, and CIRCL gives access only
     to trusted partners.

   On an existing installation, `compose up` does not remove containers of these services that are
   already running; `./ops stop` removes them (and `./ops status` lists them as not part of the
   compose files). To run one of them anyway, add `--profile cybercover-disabled` to the compose
   command.

The Nuclei HTML reporter ignores results from this module (it accepts only `nuclei` and
`nuclei-module`), but `/api/task-results?only_interesting=false` returns them.

## Starting Artemis

Do not use Artemis' `./scripts/start` in either mode:

- `--mode=production` pulls `certpl/artemis:latest`, an uncontrolled upgrade to whatever CERT-Polska
  built last;
- `--mode=development` builds an unpinned image locally, mounts the whole Artemis checkout over `/opt`
  in every Artemis-based container (these services included) and publishes PostgreSQL on port 5432 on
  all interfaces. It is meant for developing Artemis itself.

Start, stop and check Artemis with [cybercover_ops](https://github.com/allanjelly/cybercover_ops)
(`./ops start`, `./ops stop`, `./ops status`), cloned into the Artemis directory like this repository.
It runs every component at the versions pinned in its lock file.

Development of these modules needs no special mode: their code is mounted read-only
from this checkout, so a change takes effect after `docker compose -p artemis restart <service>`.
For the database, use `docker compose -p artemis exec postgres psql -U postgres artemis`.

## Checking, stopping and restarting

After starting, wait a few minutes and check that no container restarts. A momentary
`docker ps --filter status=restarting` is not enough: a container in a restart loop is only sometimes
in the restarting state. Check the restart counters instead; this must print nothing:

```sh
docker inspect -f '{{.Name}} {{.RestartCount}}' $(docker ps -aq) | awk '$2>0'
```

For a container listed there, `docker logs --tail=40 <name>` shows why it fails.

To stop everything (Artemis, Artemis-modules-extra and these services, including containers of
inactive profiles and the one-off `karton-logger-run-*` container), from the Artemis directory:

```sh
docker compose -p artemis down --remove-orphans
```

**Emergency stop**, when the server barely responds and `down` hangs (e.g. many containers in restart
loops):

1. Stop the restart loops: `docker update --restart=no $(docker ps -aq)`.
2. `docker kill $(docker ps -q)`, then `docker compose -p artemis down --remove-orphans`.
3. If `docker` commands hang too: `sudo systemctl restart docker`, check `docker ps` and repeat step 2
   if containers came back. Last resort: reboot.
4. Never add `-v` to `down` and never run `docker system prune --volumes`: the volumes hold the
   database and the Nuclei templates.
5. Fix the cause, then start again (see "Starting Artemis"); recreating the containers restores
   their `restart: always` policy.

## Upgrading Artemis

The modules subclass stock Artemis modules and rely on some of their internals, so an Artemis
upgrade can break them without any Artemis file having been modified (example: Artemis `2fee327d`
removed nuclei workflows and changed `Nuclei._scan`; this repository supports both versions since
`e7e884b`). Last verified against Artemis `e5e0167` (and `8a79b34`).

Upgrades go through cybercover_ops (`./ops update`), which, before anything is applied:

- runs this repository's suite (`tests/run_in_docker.sh`) on the candidate's code and image, including
  `tests/test_compat.py`: every `artemis` import and `Config` setting of the package must resolve, and
  the stock methods the modules override or call (`Nuclei._scan`, `run_multiple`, `_get_links`,
  `check_output_log_on_error_with_stderr`, `PortScanner.run_multiple`, `add_task`,
  `add_task_if_domain_exists`, `save_task_result`, `ResourceLock`, the `nuclei-module` identity, the
  `TaskResult` columns) must accept the arguments they pass;
- checks the configuration: `MODULES_DISABLED_BY_DEFAULT` in `.env` must contain Artemis' current default
  list plus the two Cybercover modules; `artemis/modules/api_scanner.py` must still be absent (our
  `docker-compose.yml` disables its service); `AUTOARCHIVER_MIN_AGE_SECONDS_NOT_INTERESTING` must cover
  `CYBERCOVER_FULL_SCAN_HOSTS_MAX_AGE_DAYS`;
- shows the diff of Artemis' `env.example`, to apply to `.env` by hand (the tests use their own
  configuration). Example: with SQLAlchemy 2.1 (Artemis `911150e1`), `POSTGRES_CONN_STR` must start
  with `postgresql+psycopg2://`.

What remains manual after an upgrade: one full and one incremental scan of a test target, checking the
worker logs (template update, adopted or replayed ports, number of selected templates). To test this
repository by hand against another image: `ARTEMIS_BUILD_IMAGE=<image> tests/run_in_docker.sh`.

## Tests

Importing Artemis needs Redis, PostgreSQL, a writable `/data` and a Karton config. The script
below runs the suite in the Artemis image with throwaway Redis/PostgreSQL
(`tests/test-stack.compose.yaml`, separate from Artemis' compose files) and removes them afterwards:

```sh
tests/run_in_docker.sh                 # whole suite
tests/run_in_docker.sh tests -k port   # any pytest arguments
```

`ARTEMIS_BUILD_IMAGE` selects the image (default `certpl/artemis:latest`).
