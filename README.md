<p align="center">
  <img src="assets/crt.watch-logo.svg" alt="crt.watch logo" width="720">
</p>

# crt.watch — self-hosted SSL/TLS certificate and service monitoring

<p align="center">
  <a href="https://github.com/brightcolor/crt.watch/releases"><img alt="Latest release" src="https://img.shields.io/github/v/tag/brightcolor/crt.watch?label=release&sort=semver"></a>
  <a href="https://github.com/brightcolor/crt.watch/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/brightcolor/crt.watch/ci.yml?branch=main&label=ci"></a>
  <a href="https://github.com/brightcolor/crt.watch/pkgs/container/crt-watch"><img alt="Container image" src="https://img.shields.io/badge/image-ghcr.io-2496ed?logo=docker&logoColor=white"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/brightcolor/crt.watch"></a>
  <img alt="Self-hosted" src="https://img.shields.io/badge/self--hosted-single%20container-6366f1">
</p>

**Know a certificate is expiring before a customer tells you.** crt.watch watches TLS
certificates, the services behind them, and the logins that depend on them — expiry
windows, chain problems, hostname mismatches, weak protocols, STARTTLS on mail
servers, DNS drift, and SSL Labs grades — then alerts you through email, chat or
webhooks well before anything breaks.

One Docker container, SQLite on disk, no external dependencies. Similar in operating
style to Uptime Kuma, but built around certificates rather than HTTP status codes.

[**Live instance**](https://crt.watch) · [Quick start](#quick-start) · [Features](#features) · [REST API](#rest-api) · [Prometheus](#prometheus)

**What it checks:** SSL/TLS certificate expiry · certificate chains and trust · hostname
and SAN mismatches · TLS protocol versions and cipher suites · STARTTLS on SMTP, IMAP,
POP3 and FTP · implicit TLS on SMTPS, IMAPS, POP3S, LDAPS and FTPS · HTTP and HTTPS
endpoints · SSH banners · service logins · DNS resolution drift · SSL Labs assessments

The codebase is deliberately simple and compact. It also shows the signs of a fast AI-assisted build, so review the security and operational defaults before exposing it beyond a trusted network.

## Stack Decision

- Backend: Node.js with TypeScript and Express
- Frontend: React with Vite, Bootstrap 5.3/AdminLTE, Bootstrap Icons, and a design token layer that defines every radius, tint, control size and type step in one place
- Look: the bright color house style. `werkbank.css` dresses the application — onyx rail, paper ground with white panels, yellow as the action colour, Anton in capitals on headings — and `auftritt.css` dresses the public front page with hard edges and full colour fields. Anton, Atkinson Hyperlegible and IBM Plex Mono ship with the image; nothing is fetched from a font service at run time
- Database: SQLite via better-sqlite3 (WAL mode, incremental page writes) through a small repository layer, with a structure that can later be adapted for PostgreSQL
- Worker: in-process scheduler with bounded concurrent checks
- Addresses: the public surface lives at the root (`/`, `/login`, `/register`), the application under `/app`; the front page is rendered on the server so crawlers and first-time visitors receive content, not an empty div
- Deployment: one Docker image served on port `8080`

This stack keeps the application easy to self-host while still supporting real TLS checks, background jobs, API endpoints, and a modern UI.

## Features

- Dashboard with OK, warning, critical, down, paused, and unknown status counts
- Public frontpage that explains crt.watch before operators sign in, controlled by `FRONT_PAGE_ENABLED`
- Dark, colorful dashboard with a contextual health header, grouped checklist rows, color-coded multi-select status filters, and monitor cloning
- Workspace switcher in the sidebar showing the current organization and team, every organization you belong to with your role, and how much of the plan's monitor allowance is used
- Collapsible AdminLTE sidebar that can shrink to icon-only navigation while keeping labels available on hover
- Live-refreshing UI views that update visible status, monitor details, operations, reports, users, organizations, and settings without a manual reload
- Dashboard problem chips that show certificate, TLS, DNS, SSL Labs, and service issues directly in the monitor overview
- SaaS-ready organization model with tenant-scoped monitors, teams, notification providers, settings, public registration, invite links, and role-based memberships
- Super admin user management with UI-controlled public registration, user creation, password rotation, platform roles, organization assignment on creation, and support impersonation
- Dynamic browser favicon that glows green when healthy and blinks red when attention is required
- Monitor types for HTTPS, custom TCP TLS, SMTPS, IMAPS, POP3S, LDAPS, implicit FTPS, XMPP TLS, SMTP STARTTLS, IMAP STARTTLS, POP3 STARTTLS, and explicit FTP AUTH TLS
- Service health checks for HTTP, HTTP login flows, raw TCP ports, DNS records, SSH, FTP, SMTP, IMAP, and POP3 banners
- TCP, FTP, SMTP, IMAP, and POP3 service checks can use Auto, STARTTLS, SSL/TLS, or Plain transport security from the web UI
- Plain service health checks are clearly separated from secure transport checks so certificate fields are only shown when certificate data is collected
- Optional service login checks for HTTP Basic/Form, SSH password auth, and FTP, SMTP, IMAP, and POP3 credentials over STARTTLS, direct SSL/TLS, or explicitly allowed plaintext
- Per-monitor alert grace period before failed checks create notifications
- Label-based application rollups where one service can contain multiple checks
- Label inputs support chip mode, paste-friendly text mode, Enter/comma commits, and reliable blur commits before moving to another field
- Prometheus-compatible metrics at `/metrics`, for the operator's bearer token or a signed-in member of an organization
- SSL Labs-style TLS security grading with a compact A-F score per TLS result, including secure service checks on the dashboard overview
- Optional intensive TLS assessment that probes supported TLS versions and flags deprecated protocol support, weak cipher patterns, missing forward secrecy, small certificate keys, and incomplete chains
- TLS grading explains persisted score deductions and deterioration alerts include the concrete reason for a grade drop
- Optional external Qualys SSL Labs v4 assessments for public HTTPS hosts on port `443`, cached per host within the organization for at least 24 hours
- Manual SSL Labs trigger from Operations or eligible monitor detail pages, with the resulting grade stored in monitor history
- Configurable notifications when a monitor's TLS grade or score deteriorates compared with the previous check
- Flapping detection for monitors that repeatedly bounce between healthy and failed states
- Incident timelines for monitors and public status pages
- Public status page subscriptions through email or webhook callbacks
- Certificate Transparency watch for detecting newly issued certificates on watched domains
- Auto-discovery suggestions for common web and mail endpoints from a domain
- Discovery results can be accepted one by one or imported all at once; MX-derived suggestions receive `mail` and `mx` labels
- Backup and restore UI for portable, non-secret JSON exports
- Certificate detail view with CN, SANs, issuer, serial number, SHA256 fingerprint, validity, chain, TLS version, and cipher suite
- DNS resolution details in monitor views, including fresh resolved IPs, authoritative nameservers, and comparison against Cloudflare, Quad9, and Google public resolvers on every check
- Hostname mismatch, self-signed, expiry, weak TLS protocol, chain trust, and fingerprint-change detection
- Optional DNS resolution change alerts based on uncached resolver comparisons
- Historical check results per monitor
- Manual "check now" action and automatic periodic scheduler
- Global and per-monitor warning and critical expiry thresholds
- Notification channels for SMTP email, Pushover, generic webhooks, Discord, Slack, Telegram, Gotify, ntfy-compatible endpoints, Microsoft Teams, Mattermost, Matrix, PagerDuty, and Opsgenie
- Alert deduplication with resend interval, route-specific escalation delay, recovery messages, quiet hours, and per-monitor grace periods
- Personal user alert preferences for warning, recovery, and info events while critical alerts stay controlled by organization admin routes
- Certificate change alerting can be controlled globally and per monitor
- Enforced monitor and label-based maintenance windows that keep checks running while suppressing notifications
- Incident acknowledgement, assignment, notes, and delivery visibility for alert troubleshooting
- API tokens with read-only or read/write scopes for automation
- Custom public status pages with slugs, titles, descriptions, logos, hostname hiding, subscriptions, and incident timelines; a monitor is public only while a published status page of its organization shows it
- Public status page subscriptions require double opt-in before email or webhook incident updates are enabled
- Scheduled auto-discovery jobs for common web and mail endpoints
- Availability reports with check counts, incident counts, availability percentage, and MTTR
- Scheduled SQLite database backups with UI download and retention controls
- Passport-based local user login with bcrypt password hashes, secure sessions, CSRF token header, first-run admin setup protected by a setup code from the server log, organization self-registration, and optional GitHub OAuth strategy configuration
- Hardened defaults: a Content Security Policy on every page, rate limits for requests and for failed sign-in and two-factor attempts, webhook, chat and email notifications restricted to public addresses, `/metrics` behind a token, client addresses from `X-Forwarded-For` only for named proxies, and a container that runs as an unprivileged user
- Organizations are kept apart throughout: lists, incidents, deliveries, subscriptions, channels, restores and metrics stay inside the organization of the signed-in member
- Optional TOTP-based two-factor authentication per user, set up from the Profile page with one-time backup codes and enforced as a second login step
- Audit log for organization and team management actions, viewable by owners and admins on the Operations page
- Admin-only user management with visible validation for password length and duplicate email addresses
- Organization roles for `owner`, `admin`, `member`, and `viewer`; existing self-hosted installs are migrated into a default organization and default team
- Encrypted storage for monitor login secrets, SMTP settings, and notification provider secrets using `SESSION_SECRET`
- JSON monitor import/export and CSV exports for certificate summary and check history
- REST API under `/api`
- Dark, bright, and auto color modes with a Discord-like neutral gray default and no decorative color accent outside status signals
- AdminLTE 4.0.0-based operator interface with sidebar navigation, status center, global monitor search, Bootstrap-style cards, and responsive admin forms
- Maintenance windows can be built with datetime pickers and still support text rules for recurring windows
- Status pills, rows, dashboard cards, and status center counters use clear green, yellow, red, and gray signal colors
- Cleaner responsive form layouts with aligned labels and controls
- UI and public status dates use leading zeroes for day and month
- Reverse-proxy aware deployment settings

## Screenshots

Screenshots are not committed yet. Start the app and open `http://localhost:8080` to capture:

- Dashboard
- Monitor detail page
- Monitor form
- Notification channel settings

## Quick Start

For a fresh Linux server with Docker already installed, run:

```bash
curl -fsSL https://raw.githubusercontent.com/brightcolor/crt.watch/main/scripts/quickstart.sh | sudo bash
```

The script clones the current GitHub repository into `/opt/crt.watch`, creates `/opt/crt.watch/.env` with generated secrets, creates a local `data` bind-mount directory, pulls the published GHCR image, and starts the stack with Docker Compose.

If the repository is private, use a GitHub token that can read the repository:

```bash
curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" https://raw.githubusercontent.com/brightcolor/crt.watch/main/scripts/quickstart.sh | sudo bash
```

Optional overrides:

```bash
curl -fsSL https://raw.githubusercontent.com/brightcolor/crt.watch/main/scripts/quickstart.sh | sudo CRTWATCH_PORT=8080 bash
```

To publish crt.watch on a different host port, set `CRTWATCH_PORT`:

```bash
curl -fsSL https://raw.githubusercontent.com/brightcolor/crt.watch/main/scripts/quickstart.sh | sudo CRTWATCH_PORT=8888 bash
```

For manual installs, use `HOST_PORT=8888` in `.env` and keep `PORT=8080` unless you intentionally want to change the internal application port too.
Persistent data is mounted from `DATA_DIR`, which defaults to `./data` relative to the Compose project directory.

Manual setup:

1. Copy the environment file:

```bash
cp .env.example .env
```

2. Edit `.env` and set at least:

```bash
SESSION_SECRET=use-a-long-random-secret
BASE_URL=http://localhost:8080
```

3. Create the data directory for the container user. The image runs as the unprivileged user `node` (uid 1000, gid 1000), which needs to own `DATA_DIR`:

```bash
mkdir -p data
sudo chown 1000:1000 data
```

4. Start crt.watch:

```bash
docker compose up -d
```

5. Open:

```text
http://localhost:8080
```

### First-run setup

As long as no administrator account exists, every page of crt.watch leads to the setup screen at `/setup`, where you create the first administrator. The setup asks for a setup code that only the operator sees. The code is in the server log of the current start:

```bash
docker compose logs crt-watch | grep -A1 "not set up yet"
```

or print it inside the container:

```bash
docker compose exec crt-watch node apps/api/dist/cli.js setup-code
```

Enter the code together with the administrator's email address, an organization name and a password (at least `PASSWORD_MIN_LENGTH` characters, 12 by default). The account is signed in right away, becomes platform administrator and owner of the new organization, and the setup is recorded in that organization's audit log. A new code replaces the old one at every start. During the setup the API, `/api/health`, `/metrics`, the public status pages and the static files stay reachable, and public registration waits until the setup is done.

Once an administrator exists, the setup is closed: `/setup` answers 404, the command reports that there is nothing to print, and registration never makes anybody an administrator. Further administrators are created by an administrator on the Users page.

The public marketing frontpage is enabled by default. Disable it with `FRONT_PAGE_ENABLED=false` when crt.watch should open directly on the sign-in screen. Public organization signup is controlled separately with `PUBLIC_REGISTRATION_ENABLED`; invitation links keep working even when public signup is disabled.

For local development, the Vite frontend runs on `http://localhost:5173` and proxies `/api`, `/metrics`, and `/public` to the API server on `http://localhost:8080`.

## Example Monitors

- `example.com`, port `443`, type `HTTPS`
- `smtp.example.com`, port `465`, type `SMTPS`
- `mail.example.com`, port `993`, type `TCP TLS`
- `ldap.example.com`, port `636`, type `LDAPS`
- `ftp.example.com`, port `21`, type `FTP explicit TLS`
- `smtp.example.com`, port `587`, type `SMTP STARTTLS`
- `imap.example.com`, port `143`, type `IMAP STARTTLS`
- `pop3.example.com`, port `110`, type `POP3 STARTTLS`
- `app.example.com`, port `443`, type `HTTP login check`
- `ssh.example.com`, port `22`, type `SSH banner`
- `example.com`, port `53`, type `DNS record check`

Use the same label on related monitors to model one application with multiple checks, for example `mail` on DNS, SMTP STARTTLS, IMAP STARTTLS, and webmail login monitors.

## Service Checks

crt.watch can monitor certificate-focused targets and general service availability from the same monitor list.

- HTTP checks validate the status code and can optionally require a response substring.
- HTTP login checks support Basic Auth or form POST checks. Login credentials are encrypted at rest and masked in API/UI responses.
- TCP checks validate that a port accepts connections.
- DNS checks validate record resolution and can require an expected value.
- SSH, FTP, SMTP, IMAP, and POP3 checks validate the protocol banner or capability response.
- Service login checks can validate credentials. SSH uses the SSH protocol; plain FTP, SMTP, IMAP, and POP3 login tests require explicit plaintext approval on the monitor and do not collect X.509 certificate data. Prefer TLS or STARTTLS variants for credential-bearing checks and certificate details.
- STARTTLS checks for SMTP, IMAP, and POP3 can optionally validate login credentials after the TLS upgrade.
- FTP, SMTP, IMAP, POP3, and TCP service monitors have a Transport Security selector.
- `Auto` tries the best secure transport for the selected port, keeps certificate details when successful, and falls back to plain checks only when no secure transport works.
- `STARTTLS / explicit TLS` requires a protocol upgrade and fails the check if the server does not offer it.
- `SSL/TLS` requires an implicit TLS handshake on the configured port.
- `Plain` verifies availability or credentials only and never collects X.509 certificate details.
- STARTTLS and direct SSL/TLS FTP, SMTP, IMAP, and POP3 checks can optionally validate login credentials after the TLS session is established.
- Direct SSL/TLS checks remain available for SMTPS, IMAPS, POP3S, LDAPS, implicit FTPS, and custom TLS ports.
- Explicit TLS upgrade checks are available for SMTP, IMAP, POP3, and FTP.
- External SSL Labs assessments are an optional extra for public HTTPS hosts on port `443`. SSL Labs does not replace the local TLS/STARTTLS checks and is not used for private hosts, SMTP, IMAP, POP3, FTP, or arbitrary STARTTLS ports.

Checks reach public addresses only, with the same address check as notifications: a monitor's host is checked when the monitor is saved and before every check, and every connection a check opens, including each redirect of an HTTP check, uses only addresses that pass. Loopback, private, link-local, carrier-grade NAT, multicast and reserved ranges are refused, also in their IPv4-mapped, NAT64 and 6to4 forms. To monitor hosts in your own network, list their addresses or networks in `MONITOR_ALLOWED_NETWORKS`, or allow every internal target with `ALLOW_PRIVATE_TARGETS=true` on an instance where every user who can create monitors is trusted. HTTP checks follow at most `MONITOR_MAX_REDIRECTS` redirects within the monitor's timeout and look for the expected text in the first `MONITOR_HTTP_BODY_LIMIT_KB` of the response. See [Security Settings](#security-settings).

The DNS details of a monitor query the authoritative nameservers of its zone on the addresses that pass the same check, with the same settings. When every address of those nameservers is internal, the DNS details say so and skip the comparison with authoritative DNS.

Besides the monitor's timeout, which ends every wait without an answer, two limits end a check's conversation with the service: the STARTTLS negotiation, the banner and a login read at most `MONITOR_PROTOCOL_READ_LIMIT_KB` each, and all connections of one check — TLS handshake, STARTTLS negotiation, banner, login and the probes of the intensive TLS assessment — end after `MONITOR_CHECK_DEADLINE_SECONDS` together. A slow service therefore keeps the scheduler busy for that long at most, and the message of the check names the setting to raise.

The scheduler looks for due monitors every `SCHEDULER_INTERVAL_SECONDS` and checks up to `CHECK_CONCURRENCY` of them at a time; the same run removes old results and runs scheduled discovery and backups. When a step fails, crt.watch writes the reason to its log with a reference, runs the remaining steps and tries the failed one again at the next run.

Keep `SESSION_SECRET` stable after first deployment. It is used to decrypt stored service-login passwords and provider secrets.
Monitor JSON exports mask stored secrets and are suitable for moving monitor definitions, not for full secret-bearing backups.

## Notification Setup

Notification providers are configured in the Settings page. Global SMTP settings live in the UI, while recipients are assigned per monitor or through notification routes. This keeps server/provider credentials separate from the people, rooms, chat IDs, or webhook targets that should receive a specific alert.

Routes can match labels, severity, and provider targets. Each route can also define an escalation delay, so a route can notify a primary recipient immediately and a second recipient only after the problem remains unresolved for a configured time.

Users can configure personal alert preferences for non-critical events in Settings. Personal preferences use the organization's verified notification providers but can set the user's own recipient target, such as an email address, chat ID, or room ID. Critical alerts intentionally ignore personal preferences and always follow the organization admin-defined monitor recipients and notification routes.

Webhook payloads include monitor ID, monitor name, host, port, status, severity, message, days remaining, validity dates, issuer, SHA256 fingerprint, local TLS grade, optional SSL Labs grade, resolved addresses, DNS resolver mismatches, check time, and the monitor URL. Subscribers of public status pages receive what the page shows, see [Public Status And Badges](#public-status-and-badges).

Webhook and chat notifications, including the opt-in for status page webhook subscriptions, go to public addresses only, and so does email: the SMTP host of the organization's SMTP settings or of an email channel passes the same check. crt.watch checks the address each connection actually uses, after DNS resolution and again for every redirect, and refuses loopback, private, link-local (including the cloud metadata endpoint `169.254.169.254`), carrier-grade NAT, multicast and reserved ranges. To deliver to a service in your own network, such as Gotify, ntfy, Mattermost or Matrix on a LAN address, or a mail relay on the Docker host or in your LAN, list its address or network in `NOTIFICATION_ALLOWED_NETWORKS`, or allow all internal targets with `ALLOW_PRIVATE_NOTIFICATION_TARGETS=true` on an instance where every user is trusted. See [Security Settings](#security-settings).

The Test button of a channel sends a real message with the stored settings, so it is available to organization owners and admins, the same roles that save channels.

## REST API

API routes need a signed-in session or an API token in the `Authorization: Bearer` header; sign-in, registration, the first-run setup, `/api/auth/config` and `/api/health` are open. Requests that change something send their body as JSON (`Content-Type: application/json`). With the session cookie they also send the session's CSRF token in the `X-CSRF-Token` header, which `/api/auth/me` returns; requests with an API token need no CSRF token.

- `GET /api/monitors`
- `POST /api/monitors`
- `GET /api/monitors/{id}`
- `PUT /api/monitors/{id}`
- `DELETE /api/monitors/{id}`
- `POST /api/monitors/{id}/check`
- `GET /api/monitors/{id}/results`
- `GET /api/status`
- `GET /api/alerts`
- `GET /api/incidents`
- `GET /api/subscriptions`
- `POST /api/notification-channels/test`
- `POST /api/discover`
- `POST /api/discovery/import`
- `GET /api/reports/availability`
- `GET /api/deliveries`
- `GET /api/api-tokens`
- `GET /api/audit-log`
- `GET /api/settings/ct-watch`
- `PUT /api/settings/ct-watch`
- `GET /api/settings/maintenance`
- `GET /api/settings/tls-policy`
- `GET /api/settings/ssl-labs`
- `POST /api/ssl-labs/trigger`
- `GET /api/settings/status-pages`
- `GET /api/settings/discovery`
- `GET /api/settings/backups`
- `POST /api/ct-watch/check`
- `POST /api/backups/run`
- `GET /api/export/monitors.json`
- `POST /api/export/monitors.json`
- `GET /api/export/backup.json`
- `POST /api/export/restore`
- `GET /api/export/certificates.csv`
- `GET /api/export/history.csv`

## Public Status And Badges

An organization decides what the public sees by publishing status pages in Operations. An enabled status page shows the organization's monitors that carry all of its labels, or all of its monitors when it has no labels. Public status pages, badges and status page subscriptions show published monitors only; everything else stays inside the organization. A disabled page publishes nothing, and an organization that is suspended publishes nothing either.

A published page answers under its slug, and under its labels joined with `+`:

```text
/public/status/public-prod.html     the page with the slug public-prod
/public/status/public-prod          the same page as JSON
/public/status/prod.html            the published page whose labels are exactly prod
/public/status/prod+mail            the published page whose labels are exactly prod and mail
```

A slug is a public address, so it belongs to one organization only; saving a slug that another organization already uses is refused. Labels are not unique: when several organizations publish the same labels, the label address belongs to the default organization, then to the oldest one, so hand out the slug address. An address without a published page answers 404. When a page hides host names, the JSON leaves out host and port as well, and public incidents never carry acknowledgements, assignees or notes.

Monitor badges are SVG URLs. A badge shows a monitor while a published page of its organization covers it; for any other monitor it reads `unknown`, the same as for a monitor that does not exist:

```text
/public/badge/{monitorId}.svg
/public/badge/tags/prod+mail.svg
```

Badges size themselves from their content, keep long hostnames clipped inside the label area, and expose a `viewBox` for responsive embedding. Add a custom public label or short alias with `?label=Mail` or `?alias=Mail`:

```text
/public/badge/{monitorId}.svg?label=Mail
/public/badge/tags/prod+mail.svg?alias=Customer%20Mail
```

Status pages include the latest incident timeline and expose a simple email/webhook subscription form. A subscription belongs to the organization of the page it was made on, and it is notified when an incident opens or resolves for a monitor of that organization that matches its labels and is published at that moment. Subscriptions from earlier versions belong to the default organization.

Status pages are configured in the Operations page. A page maps a public slug to one or more labels and can set a title, description, logo URL, and hostname-hiding behavior.

Public status page subscriptions are inactive until the recipient confirms the opt-in link. Email subscriptions receive a confirmation email through the global SMTP settings. Webhook subscriptions receive a JSON opt-in payload with `confirm_url`.

Incident updates carry what the status page shows. A webhook subscription receives JSON with `event` (`opened` or `resolved`), `monitor_id`, `monitor_name`, `status`, `severity`, `message`, `days_remaining`, `checked_at` and `status_page`, and with `host` and `port` while the page shows host names. An email names the monitor with its message, status and check time and links the page. A subscription follows the page it was made on, and a subscription from an earlier version the published page with its labels; when that page no longer exists, updates leave out host and port.

## Operations

The Operations page contains production controls that are intentionally kept out of config files:

- Maintenance windows for labels or individual monitors. Supported formats include `daily 22:00-23:00`, `mon-fri 01:00-02:00`, and ISO intervals such as `2026-06-01T20:00:00/2026-06-01T22:00:00`.
- TLS policy profiles for grading, including minimum TLS version, weak cipher penalty, and SAN requirements.
- Intensive TLS probing can be enabled in Operations. It performs additional handshakes to detect supported TLS versions and feeds those findings into the grade.
- SSL Labs external assessment can be enabled in Operations with a registered SSL Labs API email. There is no API key field; SSL Labs v4 expects the registered organization email in the `email` header. The Operations UI can submit the one-time SSL Labs API registration for first name, last name, email, and organization, then save the email for future assessments. Operators can also trigger a manual assessment from Operations or an eligible HTTPS monitor detail page. crt.watch respects the scheduled minimum 24-hour per-host interval and lets manual triggers choose cached or fresh SSL Labs scans. A monitor reuses a recent assessment of its host from its own organization, which ran it with its own registered email and settings.
- Alert policy can notify on TLS grade or score deterioration. The score-drop threshold controls how sensitive these alerts are.
- Alert policy can notify on certificate changes and DNS resolution changes. Individual monitors can override both policies. DNS resolver comparisons are intentionally uncached and run fresh on each monitor check.
- Scheduled discovery for web and mail endpoints, with direct accept buttons for individual suggestions or all suggestions.
- Scheduled SQLite backups with retention and downloadable backup files.
- API tokens with read-only or read/write scopes.
- Notification delivery log for sent and failed provider deliveries.

Monitor labels are entered as chips in the monitor form. Press Enter or comma to add a label, move to another field to commit the current label on blur, click a label to remove it, or switch to text mode when labels need to be copied or pasted in bulk.

Dark and light mode are switched from the header and apply to the whole interface. Both modes are built from the same tokens, and every status colour is chosen so that text in that colour clears WCAG AA contrast against its own tinted background.

## SaaS Readiness

crt.watch now has a clean organization and team layer that prepares the app for SaaS operation:

- Authentication uses Passport Local today and has an optional Passport GitHub strategy ready for future OAuth login.
- Each authenticated request is scoped to the selected organization through the verified `X-Tenant-Id` header.
- Team context is selected with `X-Team-Id` and verified server-side against the active organization membership.
- Monitors, notification providers, alert policy, SMTP settings, TLS policy, discovery, status page settings, and backups are tenant-scoped, and so are alert history, incidents with their acknowledgements and notes, the notification delivery log and status page subscriptions. An id that belongs to another organization reads as not found.
- The public sees only monitors an organization has published on its own status pages; see [Public Status And Badges](#public-status-and-badges).
- Organization memberships support direct `owner`, `admin`, `member`, and `viewer` roles.
- Organizations contain tenant-scoped teams with `team_owner`, `team_admin`, and `team_member` roles. Private teams are visible to members, while tenant-visible teams are readable by the whole organization.
- Public registration creates an isolated organization for the new user when `PUBLIC_REGISTRATION_ENABLED=true`.
- Owners and organization admins can invite users by email with an explicit organization role. If no role is selected, invites default to `viewer`.
- The same user can belong to several organizations with different direct roles, for example admin in one organization and viewer in another.
- Viewers can read organization data. Members can operate monitors: create, edit, import and check them, acknowledge incidents and add notes, and run discovery for a domain. Owners and admins can also delete monitors, manage settings, providers, status pages, teams, invites and members, test channels, restore backups and run the certificate transparency check. A refused action names the role it needs.
- The last active organization owner and the last active team owner are protected from accidental removal or demotion.
- Invite tokens are hashed at rest. The raw invite URL is shown when an invite is created and is not reconstructed from stored hashes later.
- Tenants include plan, status, monitor limit, user limit, and team limit fields so billing or subscription logic can be added later.
- The monitor limit covers every way of creating monitors: the form, cloning, the bulk, discovery and JSON imports, and restores. A JSON import or a restore with more valid monitors than the organization has room for is refused with 402 before anything is written, and the answer names the room left. Bulk and discovery imports create monitors up to the limit and list the entries beyond it with the reason. New organizations get a limit of 50 monitors, the default organization 1000; a limit of 0 means no limit.

Set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and optionally `GITHUB_CALLBACK_URL` to enable the prepared GitHub OAuth strategy once the UI flow is connected.

Billing, automated invite emails, team-scoped monitor ownership, and per-tenant custom domains are intentionally not included yet.

## Prometheus

`/metrics` answers only to callers that identify themselves (`METRICS_ACCESS=authenticated`, the default):

- the bearer token from `METRICS_TOKEN`, meant for the operator's Prometheus, sees the monitors of every organization;
- a signed-in session or a crt.watch API token sees the monitors of that member's organization.

Generate a token and set it in `.env`:

```bash
openssl rand -hex 32
```

```env
METRICS_TOKEN=<the generated value>
```

Scrape configuration:

```yaml
scrape_configs:
  - job_name: crtwatch
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/crtwatch-token
    static_configs:
      - targets: ["crt.watch.example.com"]
```

Without credentials `/metrics` answers 401 and says how to authenticate. `METRICS_ACCESS=public` opens it without a token, with every organization's monitors; use that only on an instance that nothing but a trusted network can reach.

Exported metrics include `crtwatch_monitor_status`, `crtwatch_cert_days_remaining`, `crtwatch_last_check_timestamp`, and `crtwatch_check_duration_seconds`. Each series carries the labels `organization` (the organization's slug), `monitor_id`, `monitor_name`, `host`, `type` and `tags`.

## Watchtower Updates

The Compose file uses the published image `ghcr.io/brightcolor/crt-watch:latest` and does not start its own Watchtower container. This keeps updates under your existing external Watchtower instance.

The crt.watch service keeps `com.centurylinklabs.watchtower.enable=true`, so an external Watchtower running with `--label-enable` can update it automatically.

## Local Image Builds

The production Compose file intentionally does not contain `build:` so self-hosted installs and external Watchtower deployments always use the published GHCR image. It uses compact Compose syntax and a relative bind mount by default. To build locally from the repository, use the development override:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

## Reverse Proxy

Set:

```env
BASE_URL=https://crt.watch.example.com
TRUST_PROXY=loopback,uniquelocal
COOKIE_SECURE=true
```

`TRUST_PROXY` names the proxies whose `X-Forwarded-For` header gives the client address, and it is off by default. List the addresses or networks the proxy connects from; `loopback`, `linklocal` and `uniquelocal` stand for their ranges (`uniquelocal` covers 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and fc00::/7, which includes Docker networks). For a proxy on the Docker host that reaches a published port, or a proxy container in the same Docker network, `TRUST_PROXY=loopback,uniquelocal` fits. A single network such as `TRUST_PROXY=172.18.0.0/16` is narrower. `TRUST_PROXY=true` trusts one hop from any address; use it only when nothing but the proxy can reach the container.

Example nginx config:

```nginx
server {
  listen 443 ssl http2;
  server_name crt.watch.example.com;

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```

The rate limits count requests per client address. With `TRUST_PROXY` set, crt.watch takes that address from the `X-Forwarded-For` header of a trusted proxy. Without it, every visitor behind the proxy counts as the proxy's address, and crt.watch writes a hint to its log the first time such a header arrives. On a container that clients reach directly, leave `TRUST_PROXY` unset or `false`; the client address then comes from the connection. The log line at start says which source is in effect.

## Security Settings

These environment variables control the protections added in the security hardening, the limits of checks and the scheduler. Every value is checked when crt.watch starts; an invalid value stops the start with a message that names the variable, the accepted values and the default.

| Variable | Default | Effect |
| --- | --- | --- |
| `TRUST_PROXY` | `false` | Proxies whose `X-Forwarded-For` header gives the client address: a list of addresses and networks such as `loopback,uniquelocal` or `172.18.0.0/16`, or `true` / a number of hops (1 to 10) to trust that many hops from any address. Off, the address comes from the connection. See [Reverse Proxy](#reverse-proxy). |
| `METRICS_ACCESS` | `authenticated` | `authenticated` lets `/metrics` answer `METRICS_TOKEN`, a signed-in session or a crt.watch API token. `public` answers everyone with every organization's monitors. |
| `METRICS_TOKEN` | empty | Bearer token for the operator's Prometheus, at least 32 characters without spaces, for example from `openssl rand -hex 32`. It sees the monitors of every organization. Empty, only signed-in members and API tokens read `/metrics`. |
| `PASSWORD_MIN_LENGTH` | `12` | Shortest password accepted for every account: setup, registration, user management and password changes (8 to 128). |
| `ALLOW_PRIVATE_TARGETS` | `false` | `true` lets monitors check loopback, private and link-local addresses. Use it only where every user who can create monitors is trusted. |
| `MONITOR_ALLOWED_NETWORKS` | empty | Internal addresses or networks that monitors may check even though internal targets are blocked, separated by commas, for example `192.168.10.5, 10.20.0.0/16`. |
| `MONITOR_MAX_REDIRECTS` | `20` | Redirects that an HTTP monitor follows when it follows redirects or logs in with basic authentication (0 to 20). Every redirect target is checked like the monitor's host. |
| `MONITOR_HTTP_BODY_LIMIT_KB` | `1024` | Kilobytes of an HTTP response that a check reads to find the expected text (1 to 65536). |
| `MONITOR_PROTOCOL_READ_LIMIT_KB` | `64` | Kilobytes a check reads from a service during the STARTTLS negotiation, the banner or a login (1 to 1024). A service that sends more ends the check with a message that names this setting. |
| `MONITOR_CHECK_DEADLINE_SECONDS` | `60` | Seconds that all connections of one check may stay open together: TLS handshake, STARTTLS negotiation, banner, login and the probes of the intensive TLS assessment (1 to 600). The monitor's timeout still ends every wait without an answer. |
| `MONITOR_TLS_PROBE_TIMEOUT_SECONDS` | `3` | Seconds each probe of the intensive TLS assessment waits for an answer; a shorter monitor timeout applies (1 to 120). |
| `MONITOR_DNS_NAMESERVER_LIMIT` | `4` | Authoritative nameservers of a monitored zone whose addresses the DNS details resolve (1 to 13). |
| `MONITOR_DNS_NAMESERVER_ADDRESS_LIMIT` | `6` | Addresses of those nameservers that the DNS details query, after the monitor target check (1 to 26). |
| `SCHEDULER_INTERVAL_SECONDS` | `30` | How often the scheduler looks for due monitors, discovery runs and backups (5 to 3600). |
| `ALLOW_PRIVATE_NOTIFICATION_TARGETS` | `false` | `true` lets webhook, chat and email notifications reach loopback, private and link-local addresses, including SMTP servers. Use it only where every user who can configure channels and SMTP settings is trusted. |
| `NOTIFICATION_ALLOWED_NETWORKS` | empty | Internal addresses or networks that notifications, including SMTP servers, may reach even though internal targets are blocked, separated by commas, for example `192.168.10.5, 10.20.0.0/16`. |
| `NOTIFICATION_MAX_REDIRECTS` | `3` | Redirects a notification request follows (0 to 10). Every redirect target is checked like the original URL. |
| `NOTIFICATION_TIMEOUT_SECONDS` | `10` | Time a notification request may take including redirects, and time an SMTP server has to accept the connection (1 to 120). |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Window of the general request limit (1 to 3600). |
| `RATE_LIMIT_MAX_REQUESTS` | `1200` | Requests per client address and window (0 to 100000). `0` switches the general limit off, for example when the reverse proxy already limits. |
| `AUTH_RATE_LIMIT_WINDOW_MINUTES` | `15` | Window for failed sign-in, registration, setup and two-factor attempts (1 to 1440). |
| `AUTH_RATE_LIMIT_MAX_ATTEMPTS` | `10` | Failed attempts per client address and window (1 to 1000). Two-factor codes are also counted per account. Successful requests are not counted. |
| `CONTENT_SECURITY_POLICY` | `enforce` | `report-only` lets the browser report policy violations in its console instead of blocking them, for diagnosis. |
| `CONTENT_SECURITY_POLICY_IMAGE_SOURCES` | `self data: https:` | Allowed image sources, separated by spaces. Status page logos load from here; add `http:` or a single host such as `https://logos.example.com` as needed. |

## Backups

The Import page includes a backup and restore UI for portable JSON exports of monitor definitions, provider definitions, notification routes, CT-watch settings, and non-secret settings. Secrets are masked in this export by design and must be re-entered after restore.

SQLite data is stored in the host bind mount configured by `DATA_DIR` and mounted into the container at `/data`. The default is `./data`, so manual installs store the database under the repository checkout. For a full secret-bearing backup, back up `crtwatch.sqlite` and its WAL files while the container is stopped, or use a SQLite online backup command from a maintenance shell.

The Operations page can also create and retain full SQLite backup files inside `/data/backups`. These backups can be downloaded from the UI and are controlled by a keep-count retention setting. Each file holds the whole database with every organization, so listing, creating, downloading and deleting backup files is reserved for platform administrators.

Independently of those tenant-configured backups, crt.watch always writes an automatic safety-net backup (`crtwatch-auto-*.sqlite` in `/data/backups`). It is controlled by environment variables instead of database-stored settings, so it keeps working even if the database is lost or replaced: `AUTO_BACKUP_ENABLED` (default `true`), `AUTO_BACKUP_INTERVAL_HOURS` (default `24`), and `AUTO_BACKUP_KEEP` (default `14`). Automatic backups appear in the Operations backup list like any other backup.

## Updates

```bash
docker compose pull
docker compose up -d
```

The schema migration currently creates missing tables only. Back up the database before upgrading.

### Upgrading to the unprivileged container

The image runs crt.watch as the unprivileged user `node` (uid 1000, gid 1000). Data written by older images belongs to root, so the data directory has to be handed over once before the new image starts. This also applies when Watchtower updates the container:

```bash
cd /opt/crt.watch
sudo chown -R 1000:1000 data
docker compose pull
docker compose up -d
```

Use the directory configured as `DATA_DIR` if it differs from `./data`. Running the quickstart script again does the same: it changes the owner of `data` and pulls the new image. If the directory is not writable, crt.watch stops at start with a message that names the directory and the command.

### Upgrading to organization-scoped public pages, protected metrics and named proxies

Existing installations keep their administrator, so no setup screen appears. Check these points before or right after the update, also on installations that Watchtower updates:

1. Reverse proxy: `TRUST_PROXY` is off by default. Behind a proxy, set it in `.env` to the proxy's addresses, for example `TRUST_PROXY=loopback,uniquelocal`. An existing `TRUST_PROXY=true` keeps its meaning; replace it with the proxy's network when the container port is reachable without the proxy.
2. Prometheus: `/metrics` needs a token. Set `METRICS_TOKEN` and add it to the scrape configuration, see [Prometheus](#prometheus), or set `METRICS_ACCESS=public` on an instance that only a trusted network reaches.
3. Public status pages and badges: label addresses and badges answer only for monitors on a published status page. Publish a status page in Operations for every label address or badge that is linked somewhere.
4. Email: an SMTP host on an internal address (Docker host, mail container, LAN relay) is refused like an internal webhook. Add its address or network to `NOTIFICATION_ALLOWED_NETWORKS`, then use the Test button of an email channel.
5. Default organization: an account joins it once, at the first start of this version, and only when it belongs to no organization at all. Open Organizations, select the default organization and remove members that do not belong there.

### Upgrading to checked monitor targets

Check these points before or right after the update, also on installations that Watchtower updates:

1. Monitors: while `ALLOW_PRIVATE_TARGETS` is off, monitors reach public addresses only. The check covers every special-purpose range, every connection of a check and every redirect of an HTTP check. A monitor whose host lies in a Docker network, the LAN, a VPN with carrier-grade NAT addresses (`100.64.0.0/10`) or another internal range reports "points to a private, loopback or link-local address" and is down. List such hosts or networks in `MONITOR_ALLOWED_NETWORKS`, or set `ALLOW_PRIVATE_TARGETS=true` on an instance where every user who can create monitors is trusted. Monitors that are already down with an address or HTTP connection error send one alert with the new wording of their message.
2. `ALLOW_PRIVATE_TARGETS` accepts `true` and `false` (also `1`, `0`, `yes`, `no`, `on`, `off`). Any other value stops the start with a message that names the variable.
3. Scripts that sign in or change something without an API token send their body as JSON (`Content-Type: application/json`), and with a session also the `X-CSRF-Token` header. Scripts with an API token keep working as before.
4. HTTP monitors read up to `MONITOR_HTTP_BODY_LIMIT_KB` (1024 KB) of a response for the expected text and follow up to `MONITOR_MAX_REDIRECTS` (20) redirects. They send the user agent `crt.watch`.

### Upgrading to check limits and error references

Check these points before or right after the update, also on installations that Watchtower updates:

1. Check limits: a check reads at most `MONITOR_PROTOCOL_READ_LIMIT_KB` (64 KB) during a STARTTLS negotiation, a banner or a login, and all its connections end after `MONITOR_CHECK_DEADLINE_SECONDS` (60) together. A monitor of a service that needs more, for example a mail server with a long greeting delay, reports which setting to raise.
2. Messages: a STARTTLS negotiation, banner, login or TLS handshake that gets no answer or ends early reports what happened and what to check. A monitor that is down with such a message sends one alert with the new wording.
3. DNS details: the authoritative nameservers of a monitored zone are queried on addresses that pass the monitor target check. For a zone whose nameservers sit in an internal network, the DNS details report that the comparison with authoritative DNS is skipped; add the addresses they list to `MONITOR_ALLOWED_NETWORKS`. With DNS change alerts on, such a monitor reports one DNS change.
4. Errors: a failed request answers with JSON and a reference that the server log carries, a request body that is not JSON answers 400 and a body over the limit 413. A failed step of the scheduler is logged with a reference and the next step, and the scheduler goes on.
5. Settings: the new settings start with their defaults and are validated at start. The Compose file passes each setting by name, so a setting that should differ from its default needs its line under `environment` as well as its value in `.env`.

## Troubleshooting

- Login fails on a fresh install: every page leads to the setup screen; create the first admin user there with the setup code from `docker compose exec crt-watch node apps/api/dist/cli.js setup-code`. For an existing install, reset the password in the SQLite database or recreate the bind-mounted data directory if no data must be kept.
- The setup answers "The setup code is not valid": the code changes at every start, so take it from the log of the current start or print it again with the command above.
- Creating a user fails: make sure the current account has the Admin role, the email address is not already used, and the password has at least `PASSWORD_MIN_LENGTH` characters (12 by default).
- A check reports "Monitor target … points to a private, loopback or link-local address": add the address or network of the host to `MONITOR_ALLOWED_NETWORKS`, or set `ALLOW_PRIVATE_TARGETS=true` if every user who can create monitors is trusted.
- An HTTP check reports "did not contain the expected text within its first … KB": check the expected text, or raise `MONITOR_HTTP_BODY_LIMIT_KB` when the text sits further down in a large page.
- A check reports "The server sent more than … KB during the …": check that the monitor uses the right port and protocol, or raise `MONITOR_PROTOCOL_READ_LIMIT_KB`.
- A check reports "did not finish within the … seconds a check may take": check how long the service takes to answer, or raise `MONITOR_CHECK_DEADLINE_SECONDS`.
- The DNS details report that the authoritative nameservers "resolve only to private, loopback or link-local addresses": add the listed addresses to `MONITOR_ALLOWED_NETWORKS`, or set `ALLOW_PRIVATE_TARGETS=true` if every user who can create monitors is trusted.
- An error message names a reference, or the server log shows "… failed (reference …)": the log line with that reference names the failed request or scheduler step and the error, and for a scheduler step what to check. crt.watch keeps running and tries failed scheduler steps again at the next run.
- A change answers 403 "did not carry the security token of your session": reload the page and try again; scripts use an API token in the `Authorization` header. A sign-in from a script answers 415 "accepts this request as JSON only": send the body as JSON.
- Notifications to a service on the local network fail with "is a private, loopback or link-local address", or email fails with "SMTP server … is a private, loopback or link-local address": add the address of the service or mail relay to `NOTIFICATION_ALLOWED_NETWORKS`, or set `ALLOW_PRIVATE_NOTIFICATION_TARGETS=true` if every user who can configure channels and SMTP settings is trusted.
- Prometheus gets 401 from `/metrics`: set `METRICS_TOKEN` and send it as bearer token, as described in [Prometheus](#prometheus).
- A public status page or badge answers 404 or `unknown`: publish a status page with those labels in Operations; only published monitors are public.
- The container stops with "cannot write to its data directory": hand the data directory to uid 1000 as described in [Upgrading to the unprivileged container](#upgrading-to-the-unprivileged-container).
- Creating, importing or restoring monitors answers that the organization "has reached its limit" or that the import or backup holds more monitors than it has room for: delete monitors the organization no longer needs, or raise `monitor_limit` of the organization in the `tenants` table of the SQLite database (`0` means no limit).
- Sign-in answers "Too many failed attempts": wait for the time the message names, or adjust `AUTH_RATE_LIMIT_MAX_ATTEMPTS` and `AUTH_RATE_LIMIT_WINDOW_MINUTES`. Behind a reverse proxy, check that `TRUST_PROXY` names the proxy, for example `TRUST_PROXY=loopback,uniquelocal`, so each visitor is counted by their own address.
- Cookies fail behind HTTPS: set `COOKIE_SECURE=true` and ensure `X-Forwarded-Proto` is passed by the proxy.
- STARTTLS fails: verify the service advertises STARTTLS and that firewalls allow the configured port.
- Stored secrets cannot be read after changing `SESSION_SECRET`: restore the previous secret or re-enter affected monitor, SMTP, and notification provider passwords.

## TODO

- Add API token management
- Add full quiet-hours and maintenance-window enforcement
- Add OIDC, LDAP, and reverse-proxy-auth integrations
