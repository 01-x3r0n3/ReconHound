# ReconHound — Project Context

Authoritative implementation context distilled from the Master Project
Specification v2.0. This file is the persistent reference for all future
work on this repository. Read it before implementing any module.

---

## 1. Identity

- **Name:** ReconHound
- **One-line description:** A modular Python-based attack-surface discovery
  and reconnaissance framework that unifies fragmented recon workflows into
  one correlated, stateful, evidence-driven, adaptive pipeline.
- **Core loop:** `Discover → normalize → correlate → understand → decide
  what to investigate next → discover again → prioritize → report.`
- The value of ReconHound is **not** "runs many scanners." It is
  **correlation + state + evidence + adaptive reconnaissance + decision
  transparency**.

## 2. Architecture authority (binding rules)

- The architecture in the spec is **locked by default**.
- Do not silently redesign, remove, merge, or replace architectural
  components (the 23 modules, the asset graph, evidence/confidence model,
  etc.).
- May raise technical problems, contradictions, security concerns, or
  improvement ideas — but must **stop and explain** proposed architectural
  changes and their consequences, then **wait for explicit approval** before
  making them.
- Implementation details are free to choose as long as they stay compatible
  with the approved architecture.

## 3. Development discipline

- Build **one module at a time**, in the defined build order (§9).
- Test each module standalone before moving to the next.
- Do not implement multiple modules simultaneously unless explicitly told to.
- Preserve existing working functionality; never silently remove features
  to make an implementation easier.
- Maintain inter-module compatibility strictly through the central data
  model (`surface_mapper.py`) and correlation architecture.
- Prefer clear, maintainable, testable Python over clever complexity.

## 4. What ReconHound is / is not

**Is:** recon framework, attack-surface discovery, infra mapping, web/API
recon, OSINT aggregation, network recon, technology intelligence, JS
intelligence, correlation/orchestration engine, risk prioritization,
professional reporting.

**Is not / must never do:** exploit SQLi/XSS/SSRF/RCE or other vulns,
steal credentials, provide persistence, operate against unauthorized
targets. ReconHound discovers surface (parameters, endpoints, reflection
points, object IDs) — it never exploits it.

## 5. Tech stack

- Python 3.10+, Linux/Kali, **CLI only** (no GUI, no web dashboard).
- Terminal UX: Rich, ASCII banner, colored output, progress bars, status
  indicators, tables.
- Core libs: `dnspython`, `python-whois`, `requests`, `rich`, `argparse`,
  `socket`, `ssl`, `threading`, `asyncio`, `beautifulsoup4`, `re`, `json`.
- Output formats: JSON (machine-readable) and HTML (professional report).

## 6. Core architectural philosophy

**Correlation over isolation.** Every module follows:

```
Module → Discovery → Normalize → Store evidence → Update asset graph
       → Correlate → Determine new attack surface → Trigger next recon
       → Update graph again
```

The system behaves like an investigator, not a script runner.

### Dynamic/adaptive reconnaissance

Discoveries trigger further discoveries automatically, e.g.:
- Certificate SAN → new hostname → DNS resolution → HTTP probe → tech fingerprint
- JS file → API reference → endpoint → parameter → new attack surface
- WordPress detected → WordPress-specific enumeration triggered
- GraphQL detected → endpoint/schema/doc discovery → query/mutation mapping
- API endpoint → version detection → doc discovery → method discovery → parameter inventory

## 7. Central asset graph

Unified relationship graph (owned by `surface_mapper.py`):

```
Organization
└── Domain
    └── Subdomain
        └── IP
            └── Port
                └── Service
                    └── Technology
                        └── URL
                            └── Endpoint
                                └── Parameter
                                    └── JavaScript
                                        └── API
                                            └── Finding
```

Also tracked: DNS, WHOIS, ASN, TLS certs/SANs, Wayback historical assets,
GitHub code intel, Shodan/Censys data, vhosts, cloud infra, third-party
services, HTTP behavior, JS references, API relationships.

Independent discoveries describing the same underlying asset **must be
merged**, not duplicated.

## 8. Evidence, confidence, negative-result & conflict models

**Evidence model:** every finding stores evidence list + source module +
timestamp, not just a conclusion. Distinguish Observation / Evidence /
Inference / Confidence, all traceable to the producing module.

**Confidence model:** LOW / MEDIUM / HIGH. Multiple independent converging
signals raise confidence; a single weak signal should generally stay LOW.
Never present insufficient evidence as certainty.

**Negative-result memory:** track check state per (asset, check): Not
checked / Checked and not found / Found / Found with uncertainty. Used to
avoid unnecessary repeated expensive checks across modules.

**Conflict detection:** when modules disagree, preserve and surface the
conflict (with possible explanations) instead of silently picking one
answer. Example: version-dependent CVE checks should be suspended pending
resolution of a fingerprint conflict.

## 9. Attack-surface paths, decision queue, risk engine

- **Attack-surface paths:** explain discovery chains as a tree, e.g. domain
  → subdomain (via cert SAN) → endpoint (via endpoint_discovery) →
  parameter (via crawler) → JS reference (via js_analyzer) → new asset.
- **Decision queue with justification:** every significant orchestrator
  action is logged with an explicit `[REASON: ...]`, not just "running X".
- **Risk engine:** scores relationships, not isolated findings. Several
  MEDIUM/LOW signals converging on one asset can combine into CRITICAL;
  the engine must explain *why* a score was produced.

## 10. The 23 modules

Format: `name.py` — Phase — Purpose — key responsibilities — output feeds.

1. **passive_recon.py** — Passive — Initial infra intel. DNS (A/AAAA/CNAME/MX/TXT/NS/SOA), WHOIS, TLS cert discovery + SAN extraction, ASN/IP-range intel, org infra mapping, email security posture (SPF/DMARC/DKIM/MX). **Must persist every discovery immediately to `output/pending_assets.json`.** → `surface_mapper.py`
2. **passive_intel.py** — Passive — External intel DBs. Shodan + Censys integration, historical services, exposed infra, hosts/ports/banners/certs. No direct target interaction. → `surface_mapper.py`
3. **code_leak.py** — Passive — Public repo intel. GitHub Search API, API keys/tokens, internal URLs, config files, DB connection strings, credentials, hardcoded infra refs. → `surface_mapper.py`
4. **osint_engine.py** — Passive — OSINT/digital footprint. Email harvesting (search engines + CT logs), email pattern inference, naming-convention inference, inferred employee lists, Google dorking, HIBP breach correlation, DNS history, reverse IP intel, paste intel, job-posting tech-stack inference, ASN neighbor analysis. **Inferred data must be clearly marked as inferred, not fact.** → `surface_mapper.py`
5. **wayback_intel.py** — Passive — Historical web intel. Wayback Machine API, historical URLs/deleted paths/old endpoints/params, diff against current surface, flag removed-but-maybe-still-accessible assets. → `surface_mapper.py`
6. **surface_mapper.py** — Continuous — **Central asset graph, normalization, correlation, and state. The brain of ReconHound, not an afterthought.** Normalizes all module outputs, dedupes multi-source assets, maintains the unified graph, subdomain-takeover detection, dangling-CNAME detection, vhost relationship mapping, evidence storage, confidence tracking, conflict detection/preservation, negative-result memory, attack-surface path construction, discovery state tracking (discovered/queued/investigated/completed/failed), triggers orchestrator on new reconnaissance opportunities.
7. **active_recon.py** — Active — Network-level recon. TCP scanning (raw sockets), IPv6 scanning, UDP scanning (53/161/500/623), service detection, banner grabbing, protocol-specific enumeration: SMTP VRFY/EXPN (25/587), SNMP community strings (161), FTP anon login (21), SSH fingerprinting (22), IPMI exposure → auto CRITICAL (623), DB exposure → auto CRITICAL (3306/5432). OS fingerprinting via TTL/TCP-window. Cross-host pattern detection (same unusual port across many IPs = org pattern). → `surface_mapper.py`
8. **tech_fingerprint.py** — Active — Technology ID. CMS (WordPress/Drupal/Joomla/Magento), frameworks (Django/Flask/FastAPI/Laravel/Express/Next.js/React/Angular/Vue), servers (Nginx/Apache/IIS/Caddy), WAFs (Cloudflare/Akamai/AWS WAF/F5/Imperva). Signals: headers, cookies, HTML, JS, URLs, error pages, favicon hashes, known paths. Should trigger downstream recon automatically. Evidence+confidence required per detection. → `surface_mapper.py`
9. **vhost_scanner.py** — Active — Virtual-host discovery via Host-header variation against discovered IPs; surfaces hidden apps not visible via DNS; each discovered vhost triggers web recon. Key differentiator. → `surface_mapper.py`
10. **endpoint_discovery.py** — Active — Web/API attack-surface enumeration. Dir/file enumeration with tech-aware wordlists (WordPress/Laravel/Django path lists), API endpoint discovery (`/api/`, `/api/v1/`, `/api/v2/`, `/graphql/`), parameter discovery (query/body/path/header/form) with full parameter intelligence (name/location/method/endpoint/type/source), historical + JS parameter correlation, recursive endpoint discovery. → `surface_mapper.py`
11. **api_recon.py** — Active — Dedicated API recon. API version discovery (all identifiable versions, not just current), Swagger/OpenAPI discovery (`/swagger.json`, `/openapi.yaml`, `/api-docs`), GraphQL detection + authorized schema introspection, REST vs GraphQL vs gRPC detection, API doc discovery, deprecated endpoint detection, HTTP method discovery, auth-method fingerprinting (Bearer/API-Key/Basic/OAuth/JWT). → `surface_mapper.py`
12. **crawler.py** — Active — Recursive in-scope web app discovery. Follows internal links, collects URLs/forms/parameters, classifies forms (auth/search/upload/user-input/admin), extracts JS refs (sends to js_analyzer), WebSocket detection, GraphQL indicator detection, HIGH-priority flag for file-upload surfaces. **Strict scope enforcement.** → `surface_mapper.py`, `js_analyzer.py`
13. **js_analyzer.py** — Active — Deep client-side intel. Downloads + analyzes JS files, extracts API URLs/routes/internal endpoints/external service refs, config-value detection, secret-indicator flagging (for manual verification, never confirmed), source-map detection + `.js.map` parsing + original-source reconstruction, client-side sources/sinks/data-flows/postMessage/localStorage mapping, WebSocket endpoint detection, correlates JS refs to API endpoints via surface_mapper/api_recon. Key differentiator. → `surface_mapper.py`
14. **supply_chain.py** — Active — Third-party supply-chain mapping. External JS inventory, analytics/tracking, CDN resources, CSP analysis, third-party trust map, subdomain-to-third-party DNS relationships, categorization (payment/analytics/CDN/auth providers), risk assessment of third-party relationships. Key differentiator. → `surface_mapper.py`
15. **exposure_scan.py** — Active — Sensitive resource/info exposure. Exposed `.git`, `.env`, backups, archives, DB dumps, config files, debug pages, admin panels, `robots.txt`, `sitemap.xml`, cloud misconfig (S3/GCS/Azure Blob) incl. authorized live listability checks, error-page intel (stack traces, framework versions, internal paths), per-endpoint HTTP OPTIONS discovery. → `surface_mapper.py`
16. **http_analyzer.py** — Active — HTTP security posture. Security headers (CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy), cookie flags (HttpOnly/Secure/SameSite), CORS (origin reflection/null origin/wildcards), auth surfaces (login/logout/password-reset/OAuth/SSO/MFA indicators), JWT detection + algorithm inspection (no exploitation), cache intelligence, host-header behavior, redirect-chain mapping, WAF signal detection. → `surface_mapper.py`
17. **ssl_analyzer.py** — Active — TLS/cert intelligence. Cert validity/expiration, TLS version detection (flag TLS 1.0/1.1 as outdated), cipher-suite analysis, hostname validation, SAN extraction (feeds new hostnames back to surface_mapper), cert-chain analysis, self-signed detection. → `surface_mapper.py`
18. **screenshot.py** — Active — Visual asset triage. Screenshots of discovered web interfaces organized by subdomain; enables rapid visual identification of login pages/admin panels/default pages.
19. **vuln_intel.py** — Intelligence — Technology-to-CVE mapping. Consumes versions from tech_fingerprint.py and active_recon.py, queries NVD + public vuln DBs, maps versions to known CVEs. Output style: "Detected Nginx 1.18.0 — MAY be affected by CVE-XXXX." **Never claim "confirmed exploitable" without actual evidence.** Detection ≠ confirmed vulnerability. → `risk_engine.py`
20. **risk_engine.py** — Intelligence — Relationship-based prioritization. Scores CRITICAL/HIGH/MEDIUM/LOW/INFO, consumes the asset graph + relationships (not isolated findings), cross-module correlation (e.g. 6 converging signals on one asset, deprecated API + leaked cred in code_leak, missing HSTS + self-signed cert + outdated TLS → combined higher severity). Produces prioritized investigation queue with explanation per score. Severity guide: CRITICAL = exposed creds, listable buckets, RCE-class CVEs, IPMI exposure, exposed DB ports; HIGH = admin panels, major misconfig, deprecated APIs w/ known CVEs; MEDIUM = missing security headers, outdated TLS, SNMP defaults; LOW = minor informational; INFO = technology observations. Severity is a prioritization assessment, not proof of exploitability.
21. **report_generator.py** — Output — Professional reporting. HTML report: executive summary, target asset inventory, technology stack, attack-surface paths, risk-ranked findings (CRITICAL first) with evidence, supply-chain dependency map, vuln intel section, raw-data appendix. Also machine-readable JSON export.
22. **core/orchestrator.py** — Core — Adaptive execution coordination. Controls full execution flow across phases, implements decision queue w/ justification, routes data between modules via surface_mapper.py, reacts to surface_mapper triggers (new discovery → schedule next action), coordinates threading/async, rate limiting, delay management, resume capability, graceful per-module failure isolation. Execution modes: `--full-scan`, `--passive-only`, `--active-only`, `--module [name]`.
23. **reconhound.py** — Entry point — CLI. ASCII banner, Rich terminal output, colored/professional output, progress indicators, argparse handling, starts orchestrator with parsed args, graceful keyboard-interrupt with save-before-exit.

CLI usage examples:
```
reconhound --target example.com --full-scan
reconhound --target example.com --passive-only
reconhound --target example.com --module js_analyzer
reconhound --target example.com --output /reports/report.html
reconhound --target example.com --threads 10 --timeout 30
```

## 11. Folder structure

```
reconhound/
│
├── reconhound.py
│
├── passive_recon.py
├── passive_intel.py
├── code_leak.py
├── osint_engine.py
├── wayback_intel.py
├── surface_mapper.py
├── active_recon.py
├── tech_fingerprint.py
├── vhost_scanner.py
├── endpoint_discovery.py
├── api_recon.py
├── crawler.py
├── js_analyzer.py
├── supply_chain.py
├── exposure_scan.py
├── http_analyzer.py
├── ssl_analyzer.py
├── screenshot.py
├── vuln_intel.py
├── risk_engine.py
├── report_generator.py
│
├── core/
│   └── orchestrator.py
│
├── wordlists/
│   ├── subdomains.txt
│   ├── directories.txt
│   ├── api_endpoints.txt
│   ├── wordpress_paths.txt
│   ├── laravel_paths.txt
│   └── django_paths.txt
│
├── plugins/
│   ├── js_plugins/
│   ├── fingerprint_plugins/
│   └── exposure_plugins/
│
├── output/
│   ├── pending_assets.json
│   └── reports/
│
├── requirements.txt
├── README.md
└── context.md
```

Additional project-management files (tests, docs, config, CI, packaging,
dev tooling) may be added when needed, as long as they don't alter the
approved architecture.

## 12. Core design principles (12)

1. **Crash-safe persistence** — write discoveries to `pending_assets.json`
   immediately where applicable.
2. **Modular independence** — each module should work standalone as well as
   within the full pipeline where practical.
3. **Correlation over isolation** — `surface_mapper.py` is the central
   intelligence layer.
4. **Evidence-driven** — every important finding has evidence, source,
   confidence, timestamp.
5. **Adaptive discovery** — new findings can trigger relevant next actions
   automatically.
6. **Negative-result memory** — completed checks are remembered, not
   unnecessarily repeated.
7. **Conflict preservation** — contradictions are preserved and flagged,
   never silently hidden.
8. **Decision transparency** — every significant orchestrator action has a
   recorded justification.
9. **Professional terminal experience** — Rich, colors, ASCII banner,
   progress bars, status indicators, useful tables.
10. **Strict scope enforcement** — never intentionally scan outside the
    defined target scope.
11. **Exception handling everywhere** — meaningful diagnostics, no silent
    failures; one module's failure must not unnecessarily break unrelated
    pipeline work.
12. **Plugin architecture** — `/plugins/` provides extensibility without
    requiring unnecessary core-module modification.

## 13. Build order

Build and test **one module at a time**, in this order:

1. `passive_recon.py`
2. `active_recon.py`
3. `http_analyzer.py`
4. `ssl_analyzer.py`
5. `endpoint_discovery.py`
6. `crawler.py`
7. `exposure_scan.py`
8. `surface_mapper.py`
9. `wayback_intel.py`
10. `vuln_intel.py`
11. `risk_engine.py`
12. `report_generator.py`
13. `orchestrator.py`
14. `reconhound.py`
15. `passive_intel.py`
16. `code_leak.py`
17. `tech_fingerprint.py`
18. `js_analyzer.py`
19. `screenshot.py`
20. `osint_engine.py`
21. `api_recon.py`
22. `vhost_scanner.py`
23. `supply_chain.py`

Note: `surface_mapper.py` is architecturally central (§10) but is built at
step 8 — earlier modules (1–7) must be implementable/testable standalone
before the central graph exists. API-credential dependencies (Shodan,
Censys, GitHub, HIBP, NVD, etc.) should not block development of modules
that can be built/tested independently of those credentials.

## 14. Current status

- Architecture: complete and **locked** (changes require explicit approval).
- Module count: 23.
- Implementation: **not started**.
- **Current implementation target: `passive_recon.py`.**

## 15. Implementation workflow (per assigned module)

1. Read the relevant architectural requirements for that module.
2. Inspect the existing project before modifying anything.
3. Determine the module's dependencies and interfaces.
4. Produce an implementation plan before substantial implementation, if the
   task is complex.
5. Don't touch unrelated modules unless required by the approved task.
6. Don't silently change the architecture — if a change looks necessary:
   explain the problem, the proposed change, its consequences, and wait for
   explicit approval.
7. Implement only the approved scope.
8. Test the module independently.
9. Verify error handling.
10. Verify evidence/state are persisted correctly where applicable.
11. Verify outputs conform to the central data model.
12. Review the implementation against the spec.
13. Report what was implemented, what was tested, and any limitations.

## 16. Security and scope rules

- Intended for authorized security testing, research, and defensive
  security work only.
- All active recon must operate only against explicitly authorized targets.
- Enforce target scope wherever technically possible; never intentionally
  expand scans to unrelated systems.
- Clearly distinguish passive intelligence from active interaction.
- No exploitation functionality, no credential theft, no persistence
  functionality.
- Clearly distinguish vulnerability intelligence (possible CVE match) from
  confirmed exploitation.
- Require manual verification where automated evidence is insufficient.

## 17. Final principle

ReconHound's value is not "how many scanners it launches." It is the
ability to turn fragmented observations into an evolving, explainable
understanding of an attack surface, via the loop:

```
DISCOVER → NORMALIZE → STORE EVIDENCE → UPDATE ASSET GRAPH → CORRELATE
→ IDENTIFY NEW ATTACK SURFACE → MAKE EXPLAINABLE DECISION → INVESTIGATE
→ DISCOVER AGAIN → PRIORITIZE → REPORT
```

This loop must be preserved throughout all 23 modules.
