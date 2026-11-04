# Cybercover incremental Nuclei scanning

This package adds the `cybercover_nuclei` Artemis module. For an incremental scan, pass
`module_runtime_configurations.cybercover_nuclei.after` as the last `covered_until` date
returned by the previous scan:

```json
{
  "targets": ["example.com"],
  "enabled_modules": ["cybercover_nuclei"],
  "module_runtime_configurations": {
    "cybercover_nuclei": {
      "after": "2026-11-01"
    }
  }
}
```

In the matching `/api/task-results` item, the module stores
`task.payload_persistent.covered_until` as a UTC date. It is the commit date of the
installed `nuclei-templates` release, not the scan date or GitHub's current date.

Use that value for the next scan's `after`. If the installed release predates `after`,
the module selects no templates and returns the older `covered_until`; passing it on the
next call retries the uncovered interval rather than advancing past templates that have
not yet been installed. Re-scans can overlap by a day because `after` has date precision.

`after` must be a date within the previous 30 days. `change_type` may be `added` or
`added_or_modified` (the default). Custom templates and workflows are not included.

The GitHub compare result is cached through Artemis' module Redis cache. Set
`CYBERCOVER_GITHUB_TOKEN` to a read-only token for higher API rate limits.

Apply `artemis-docker-compose.patch` to Artemis' `docker-compose.yaml`, and place this
package's `cybercover/` directory next to that compose file (or set `CYBERCOVER_DIR`).
