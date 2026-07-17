# Vendored third-party JavaScript

These libraries are committed to the repository so that:
1. We can audit them as part of our security posture (see ADR-0003)
2. Builds are reproducible without external network access
3. There is no runtime npm dependency

All files are unmodified upstream releases. Replace using the URL listed below; verify the size matches before committing.

| File | Library | Version | License | SHA-256 |
|------|---------|---------|---------|---------|
| `htmx.min.js` | HTMX | 1.9.12 | BSD-2-Clause | `449317ade7881e949510db614991e195c3a099c4c791c24dacec55f9f4a2a452` |
| `alpine.min.js` | Alpine.js | 3.14.1 | MIT | `358d9afbb1ab5befa2f48061a30776e5bcd7707f410a606ba985f98bc3b1c034` |
| `chart.umd.min.js` | Chart.js | 4.4.6 | MIT | `9653a0813db743bbe78332a3896e28c7bc7546e4fff51e7e979e908d1f0471d1` |

Source URLs (for re-download):
- `https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js`
- `https://unpkg.com/alpinejs@3.14.1/dist/cdn.min.js`
- `https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js`

Verify with `sha256sum` after download — must match the hashes above.

## Updating

```bash
# pin the version below, then:
curl -fL -o htmx.min.js       https://unpkg.com/htmx.org@<version>/dist/htmx.min.js
curl -fL -o alpine.min.js     https://unpkg.com/alpinejs@<version>/dist/cdn.min.js
curl -fL -o chart.umd.min.js  https://cdn.jsdelivr.net/npm/chart.js@<version>/dist/chart.umd.min.js
```

Then update the version + size columns above and commit in a single `chore: bump vendored js` commit.

## License texts

Full license texts live in the upstream repos linked above. We respect each license; specifically, all three permit redistribution under the GPL-3.0 umbrella of MobInspect.
