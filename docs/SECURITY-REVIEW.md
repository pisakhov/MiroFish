# Private experiment security review

## Decision: deployment blocked

Baseline upstream commit: `7657031ac01184afe2cb220f5ee3545573b5e843`.
Fork: https://github.com/pisakhov/MiroFish

This is a partial source/dependency review, not a penetration test or security certification. No application was deployed; no provider credentials were used. Origin/nationality is not evidence of malicious behavior. The review has not established malicious behavior, nor audited every dependency for it.

## Confirmed source findings and initial mitigations

- API factory lacked authentication. Added fail-closed, single-operator HTTP Basic authentication, constant-time comparison, minimum 32-character password, and debug rejection. HTTPS and a private authenticated gateway are required for any future remote use. `/health` is intentionally public and returns no private state. This is NOT multi-user authorization.
- Wildcard CORS removed. Mutations require `X-MiroFish-Request: 1`; cross-site fetches are rejected. Frontend uses same-origin API requests.
- Filesystem identifiers and platform values were interpolated into paths. Added boundary validation for route/query/form/JSON identifiers, repeated query values and nested batch requests. Storage-level realpath confinement and symlink tests remain required; this is not a complete traversal remediation.
- Request-body logging removed. API HTTP 5xx bodies are replaced with generic errors. Other error paths, background state, logs and streamed output still need review for leakage.
- Default Compose referenced an unpinned upstream image and published both ports broadly. It now builds local source, binds ports to loopback, drops capabilities, denies privilege escalation, and bounds resources. It remains DEVELOPMENT ONLY: the existing Dockerfile runs development servers as root.
- Environment files no longer override injected environment values. The public example has blank credentials and an explicit provider configuration.

## Dependency evidence

Full scanner results are in `docs/security-evidence/`. Python analysis used a frozen `uv.lock` export with no dependency installation/resolution by pip-audit. Platform-specific markers mean this is not a complete multi-platform image scan.

- Python: pip-audit reported **337 known vulnerability findings in 30 packages**, with no packages explicitly skipped by the scanner. Counts represent package/advisory matches, not proven reachable exploits. Includes Flask/Werkzeug, document parsers, model tooling and transitive packages. Some fixes require major-version upgrades conflicting with the older pinned AI stack. Blind upgrades are unsafe.
- Root npm lock: initially 2 critical affected-package entries; compatible lock updates yield **0 reported vulnerabilities**.
- Frontend npm lock: initially 7 high and 1 moderate affected-package entries; compatible lock updates yield **0 reported vulnerabilities**.
- A clean scan only means no matches in the queried database, not absence of vulnerabilities.

## English-only status

Frontend locale loading/default/fallback is English-only; persisted Chinese selections are ignored. Backend translation lookup and language instructions are English-only. HTML metadata and environment example are translated. Original license and attribution remain unchanged.

NOT COMPLETE: upstream Chinese comments, internal model prompts, hardcoded API/log strings, README-ZH, unused locale assets and illustrations remain. Translate prompts with behavior tests rather than deleting them. English runtime settings do not guarantee every visible string or generated response is English.

## Required release gates

1. Triage Python advisories for reachability and upgrade/replace the pinned OASIS/CAMEL stack as needed. Record justified exceptions; do not silently waive findings.
2. Add storage-level path confinement, simulation/IPC authorization and log/stream sanitization. Single operator only; no untrusted tenants.
3. Run full backend regression tests with authenticated clients and fake providers, plus real factory/auth integration tests. Existing upstream API tests need explicit credentials/header fixtures and adjusted generic-error expectations.
4. Finish English translation of hardcoded strings and model instructions; test locale completeness and UI rendering.
5. Replace root/development-server Dockerfile with tested non-root production servers and immutable build inputs; scan the final image and produce an SBOM.
6. Configure Dokploy TLS/private access covering UI AND API, no directly published backend, login throttling, restricted storage/network, and resource quotas. A gateway must strip any trusted identity headers if later used.
7. Review outbound traffic. Source uses configured OpenAI-compatible endpoints and Zep Cloud; frontend loads Google Fonts. Dependency-level network behavior is not yet audited. Use non-sensitive synthetic data and restricted-budget keys.
8. Prove the actual deployed image's unauthenticated/CSRF/traversal controls and authenticated UI flow. No live evidence exists yet.

## Reproduction

```sh
uv venv /tmp/mirofish-security-venv
uv pip install --python /tmp/mirofish-security-venv/bin/python flask pytest pip-audit
/tmp/mirofish-security-venv/bin/python -m pytest -q backend/tests/test_security_boundary.py
npm ci --prefix frontend --ignore-scripts
npm run build --prefix frontend
npm audit --prefix frontend
npm audit
uv export --project backend --frozen --no-dev --no-emit-project --no-hashes -o /tmp/mirofish-requirements.txt
/tmp/mirofish-security-venv/bin/pip-audit -r /tmp/mirofish-requirements.txt --no-deps --disable-pip
```

The 23 boundary tests use a minimal Flask app to avoid importing the AI stack; they do not prove full application integration. Python audit is expected to fail until the dependency gate is resolved.
