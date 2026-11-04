# Cybercover incremental Nuclei scanning

This package adds the `cybercover_nuclei` Artemis module. It runs only the templates added or
modified after a given `nuclei-templates` release. The caller keeps the state: pass the
`covered_until` version returned by the previous scan as `after_version`.

```json
{
  "targets": ["example.com"],
  "enabled_modules": ["port_scanner", "nuclei-router", "cybercover_nuclei"],
  "module_runtime_configurations": {
    "cybercover_nuclei": {
      "after_version": "v10.5.0"
    }
  }
}
```

In the matching `/api/task-results` item the module stores
`task.payload_persistent.covered_until` - the templates release (e.g. `v10.5.1`) that was
installed during the scan. Use it as the next scan's `after_version`. A full scan (the
stock `nuclei-module`) does not return a version; take the first `after_version` from the
installed release, or run an incremental scan once to obtain it.

- If `after_version` is the same as or newer than the installed release, no templates are
  selected and the installed version is returned, so the next call retries from it.
- The lookup is a single GitHub `compare/<after_version>...<installed>` call. GitHub returns
  at most 300 files there, so larger gaps fail with an ERROR result: run a full scan.
  Incremental scans are meant to run daily, full scans every ~2 weeks.
- `change_type` may be `added` or `added_or_modified` (the default). Custom templates and
  workflows are not included.
- Results are cached through Artemis' module Redis cache. Set `CYBERCOVER_GITHUB_TOKEN` to a
  read-only token for higher API rate limits.
- The worker updates templates only on start; restart `karton-cybercover-nuclei` daily
  before the scan window so new releases are picked up.

Apply `artemis-docker-compose.patch` to Artemis' `docker-compose.yaml`, and place this
package's `cybercover/` directory next to that compose file (or set `CYBERCOVER_DIR`).
