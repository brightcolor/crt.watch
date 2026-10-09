# Changelog

## Unreleased

Security hardening in several rounds: first the code scanning and dependency findings, then organization boundaries, the first-run setup, email targets and the defaults for metrics and proxies, then monitor targets, the CSRF check and the remaining scanner findings, then error handling, limits for the conversations of a check and the queries of the DNS details. Entries that need a step on upgrade are marked; the README collects them under "Upgrading to organization-scoped public pages, protected metrics and named proxies", "Upgrading to checked monitor targets" and "Upgrading to check limits and error references".

- **Upgrade step:** a check ends its conversation with the service at two limits besides the monitor's timeout. The STARTTLS negotiation, the banner and a login read at most `MONITOR_PROTOCOL_READ_LIMIT_KB` each (default 64), and all connections of one check — TLS handshake, STARTTLS negotiation, banner, login and the probes of the intensive TLS assessment — end after `MONITOR_CHECK_DEADLINE_SECONDS` together (default 60). The message names the setting to raise. A probe waits `MONITOR_TLS_PROBE_TIMEOUT_SECONDS` for an answer (default 3). STARTTLS, logins and banners read through one reader (`checks/conversation.ts`).
- **Upgrade step:** a STARTTLS negotiation, banner, login or TLS handshake that gets no answer or ends early reports what happened and what to check. A monitor that is down with such a message sends one alert with the new wording.
- **Upgrade step:** the DNS details query the authoritative nameservers of a monitored zone on the addresses that pass the monitor target check, with `ALLOW_PRIVATE_TARGETS` and `MONITOR_ALLOWED_NETWORKS`. When every address is internal, the authoritative row says so, lists the addresses and names the settings; with DNS change alerts on, such a monitor reports one DNS change. `MONITOR_DNS_NAMESERVER_LIMIT` (default 4) and `MONITOR_DNS_NAMESERVER_ADDRESS_LIMIT` (default 6) bound the nameservers that are resolved and the addresses that are queried.
- Every handler below `/api` and `/public` hands the rejection of its promise to the error middleware (`routes/errors.ts`), which answers with JSON and a reference that the server log carries, and the server keeps serving. A request body that is not JSON answers 400, a body over the limit 413, and an answer that has already begun ends with a closed connection. A rejected promise outside a request is logged with a reference.
- Each step of the scheduler — the checks, the retention cleanup, discovery, the organizations' backups and the automatic backup — and each monitor and organization within a step fails on its own: the failure is logged with a reference and the next step, the remaining work goes on, and the failed work is tried again at the next run. `SCHEDULER_INTERVAL_SECONDS` (default 30) sets how often the scheduler runs. A backup copy that fails leaves no temporary file behind.
- The new settings are validated at start, and the Compose file and `.env.example` list them with their defaults.

- **Upgrade step:** monitors reach public addresses only while `ALLOW_PRIVATE_TARGETS` is off, with the same address check as notifications. A monitor's host is checked when the monitor is saved and before every check, and every connection of a check (TCP, banner, login, TLS, STARTTLS, SSH and HTTP with each redirect) uses only addresses that pass, after DNS resolution. Hosts in an internal network need their address or network in `MONITOR_ALLOWED_NETWORKS`, or `ALLOW_PRIVATE_TARGETS=true`. `ALLOW_PRIVATE_TARGETS` is validated at start like the other settings.
- **Upgrade step:** HTTP and HTTP login monitors send their request through the guarded client of the webhook notifications. They follow up to `MONITOR_MAX_REDIRECTS` redirects (default 20), the monitor's timeout covers the whole exchange including the body, and the expected text is looked for in the first `MONITOR_HTTP_BODY_LIMIT_KB` of the response (default 1024). Basic authentication goes to the configured origin only, a failed request names its reason, and the user agent is `crt.watch`.
- **Upgrade step:** every changing API request passes one CSRF check before its route. With the session cookie it carries the session's token in `X-CSRF-Token`, with an API token it needs none, and without a session (sign-in, registration, setup) it is accepted as JSON only; other content types answer 415 with the reason. A missing or wrong token answers 403 with the next step. Scripts that sign in without an API token send their body as JSON.
- The address check for notifications and monitors covers the IANA special-purpose registries completely, including the IPv6 forms that carry an IPv4 address (IPv4-mapped, IPv4-compatible, NAT64 and 6to4).
- A monitor with a refused host or port is answered with 400 and the reason, also in bulk imports, discovery imports and restores, which list or skip the monitor.
- The certificate transparency check answers 502 with the reason when crt.sh cannot be reached.
- The CI and Docker workflows use GitHub Actions pinned to the commit of their release.
- The page shell is sent relative to the directory of the web build, server log lines pass their values as arguments to a fixed format, and IMAP STARTTLS reads tagged completions with a fixed pattern.
- **Upgrade step:** public status pages, badges and status page subscriptions show the monitors an organization has published on its enabled status pages. A page answers under its slug and under its labels, for every organization; a label address or badge without a published page answers 404 or reads `unknown`. Publish a status page in Operations for every label address or badge that is linked somewhere. Slugs are unique across organizations, and when several organizations publish the same labels, the label address belongs to the default organization, then to the oldest one.
- **Upgrade step:** `/metrics` requires a token or a sign-in (`METRICS_ACCESS=authenticated`, the default). The bearer token from `METRICS_TOKEN` covers every organization; a signed-in session or a crt.watch API token covers that member's organization. Add the token to the Prometheus scrape configuration, or set `METRICS_ACCESS=public` on an instance that only a trusted network reaches. Every series carries the organization's slug as label `organization`.
- **Upgrade step:** `TRUST_PROXY` is off by default; the client address for the rate limits then comes from the connection. Behind a reverse proxy, name the proxy with a list of addresses and networks such as `TRUST_PROXY=loopback,uniquelocal` or `172.18.0.0/16`. `TRUST_PROXY=true` and hop counts keep their meaning. The start log names the source of client addresses in effect, and the first proxy header that arrives while `TRUST_PROXY` is off leaves a hint with the setting to change.
- **Upgrade step:** SMTP hosts from the organization's SMTP settings and from email channels pass the same address check as webhooks, after DNS resolution and on the address the connection uses, with the same settings `ALLOW_PRIVATE_NOTIFICATION_TARGETS` and `NOTIFICATION_ALLOWED_NETWORKS`. A mail relay on the Docker host or in the LAN needs its address in `NOTIFICATION_ALLOWED_NETWORKS`. `NOTIFICATION_TIMEOUT_SECONDS` also bounds the connection to the SMTP server, and a missing SMTP host is reported as such.
- **Upgrade step:** an account joins the default organization once, at the first start of this version, and only when it belongs to no organization at all. Memberships of the default organization that exist from earlier versions stay as they are; review its members under Organizations and remove accounts that do not belong there.
- First-run setup with a setup code. While no administrator exists, every page leads to `/setup`, which asks for a code that the server writes to its log at every start and that `docker compose exec crt-watch node apps/api/dist/cli.js setup-code` prints. The API, health, metrics, public pages and static files stay reachable meanwhile, and registration opens after the setup. The administrator is signed in, owns a new organization and appears in its audit log as `setup.completed`. Afterwards `/setup` and the setup API answer 404, and registered accounts get no platform role.
- Alert history, incidents, the notification delivery log and status page subscriptions are listed for the selected organization, and acknowledging an incident, adding a note and deleting a subscription work within it. The latest results on the status overview, the monitor list and the certificate export are read for the organization as well.
- Notification channels are saved within their own organization; an id from another organization answers 404. A restore gives a channel whose id is taken by another organization a new id and updates the references of the restored monitors and routes.
- The channel test needs the owner or admin role, like saving a channel. Importing monitors needs the member role, a restore the owner or admin role, and deleting a subscription the owner or admin role. A restore checks its status pages before it writes anything.
- Acknowledging an incident and adding a note need the member role, like the other changes to monitors. Discovery for a domain needs the member role, the role that imports its suggestions, and the certificate transparency check needs the owner or admin role, the role that manages the CT watch. The incident timeline, the CT watch and the import page show the reason of a refused action next to it, a bulk import lists the reasons for up to five lines it could not import, and a restore of text that is not JSON says so.
- The monitor limit of an organization covers every way of creating monitors. A JSON import or a restore with more valid monitors than the organization has room for answers 402 before anything is written and names the room left; bulk and discovery imports create monitors up to the limit and list the entries beyond it. Every answer at the limit names the limit and the next step.
- A monitor reuses an SSL Labs assessment of its host from its own organization, which ran it with its own registered email and settings.
- Incident updates to status page subscribers carry what the status page shows: `event`, `monitor_id`, `monitor_name`, `status`, `severity`, `message`, `days_remaining`, `checked_at` and `status_page`, and `host` and `port` while the page shows host names. Emails follow the same rule, and a subscription whose page no longer exists receives its updates without host and port.
- An email channel test uses the SMTP settings of the channel's organization.
- The JSON of a public status page leaves out host and port when the page hides host names, and public incidents carry status, message and times.
- `PASSWORD_MIN_LENGTH` (default 12) sets the shortest password for setup, registration, user management and password changes, and the forms show it.
- A refused role names the role it needs and the role the account has. A server error answers with a reference that leads to its entry in the server log, and the channel test shows its result next to the channel.
- The database sets its busy timeout before switching to WAL, so a second process that opens a new database file at the same moment waits for the lock.
- **Upgrade step:** the container runs as the unprivileged user `node` (uid 1000, gid 1000). Data written by older images belongs to root, so hand the data directory over once with `sudo chown -R 1000:1000 data` before the new image starts, also on installations that Watchtower updates. Running the quickstart script again does this. If the directory is not writable, the server stops at start with a message that names the directory and the command.
- **Upgrade step:** webhook and chat notifications reach public addresses only. The check runs on the address each connection actually uses, after DNS resolution and for every redirect, so a channel URL or a status page webhook subscription can no longer reach loopback, private or link-local addresses, including the cloud metadata endpoint. Notifications to a service on the local network need `NOTIFICATION_ALLOWED_NETWORKS` (single addresses or networks) or `ALLOW_PRIVATE_NOTIFICATION_TARGETS=true`. `NOTIFICATION_MAX_REDIRECTS` (default 3) and `NOTIFICATION_TIMEOUT_SECONDS` (default 10) bound each delivery, and a redirect to another origin drops the `Authorization` header.
- A failed channel test answers with its reason: 400 for a refused target, 502 for a failed delivery. Before, the rejected promise was left unhandled by Express 4.
- Requests are limited per client address, 1200 per 60 seconds by default (`RATE_LIMIT_MAX_REQUESTS`, `RATE_LIMIT_WINDOW_SECONDS`; 0 switches the limit off). Failed sign-in, registration, setup, password and two-factor attempts are limited to 10 per 15 minutes (`AUTH_RATE_LIMIT_MAX_ATTEMPTS`, `AUTH_RATE_LIMIT_WINDOW_MINUTES`), and two-factor codes are also counted per account, so changing addresses buys no extra guesses. A limited client gets the wait time in the message and in `Retry-After`.
- Every response carries a Content Security Policy: scripts, styles and fonts come from the server itself, images also from `CONTENT_SECURITY_POLICY_IMAGE_SOURCES` (default `self data: https:` for status page logos). `CONTENT_SECURITY_POLICY=report-only` turns blocking into console reports for diagnosis. The server-rendered front page hands its boot configuration over as a JSON data block, so the page runs without inline script.
- Database backup files can be listed, created, downloaded and deleted by platform administrators only, because each file holds the whole database with every organization. An unknown backup name answers 404 with an explanation.
- Starting a two-factor setup while two-factor authentication is active is refused. The new secret used to replace the active one at once, which switched the second factor off without the password that `/mfa/disable` asks for.
- TLS login checks send service credentials only after the certificate passes the monitor's own trust rules: a chain the system trusts for the host name, or a certificate the operator accepted for that monitor by allowing self-signed certificates or switching off chain validation. Before, the password went out before the certificate was evaluated. A skipped login is reported as a problem of the check.
- nodemailer 10.0.9 replaces 9.1.1 and closes GHSA-v53p-9fqp-m79j, GHSA-prgh-xp8r-p3m5 and GHSA-g57g-f23g-4646. `npm audit --omit=dev` reports no findings.
- Stored secrets are decrypted with an explicit 16-byte GCM tag length, and shorter values are refused.
- The bearer token is read from the `Authorization` header with a pattern that matches in linear time.
- New settings are validated at start. An invalid value stops the start with a message that names the variable, the accepted range and the default.

## 0.21.0 - 2026-09-28

Every entry below names something that was measured on the running application, not read off the source.

- Card titles were drawn in Anton at weight 800 with negative tracking. Anton ships one weight, so the browser synthesised the bold and the condensed capitals ran into each other. Titles now carry one weight and open tracking, on a head strip that separates them from the fields below.
- A heading inside a form section came out at 19 px while the card title above it sat at 16 px, so the subordinate line shouted louder than the one it belongs under. Sub-headings are quiet labels on a rule.
- The search field in the top bar drew two edges: one on the form, one on the input inside it, with the magnifier stranded between them. The form is the field now, and the icon sits in it.
- The top bar held three control heights and two type sizes in one row. One height, one size, one gap.
- Form controls used three different edges: a 1.2:1 hairline on most, the house tone on the search field, and none at all on the date and time controls, which were also 2 px shorter than everything else. One edge everywhere, at 3.4:1 against the card, so a field looks like a field.
- The DNS card ran its first four rows through the key/value grid and the resolver rows through a flex row with space-between, so the same card read left-aligned at the top and edge-aligned below. One grid for both, and every row starts its columns in the same place.
- The check history drew 24 identical rows and the delivery log 25, which pushed one column of the page far past the other. Both keep their own scroll, so a card stays the size of a card.
- A count of zero stood at 2.2:1 — present and unreadable. Quiet tone at full strength.
- The state of a monitor row was a circle, the one round shape in a surface built from 6 and 12 px corners. It carries the row's colour as a square field with the drawing in ink, like the signal square.
- The remaining lifetime was a 3 px line directly under the number and read as a stray underline. It has its own line and a track to be read against.
- The chosen half of the grouped/list switch was a white button on a white card, so nothing said which of the two was on. Ink in the light surface, yellow in the dark one.
- The TLS grade sat in a pale outline, quieter than the row it judges. It carries its tone as a field at the size the other pills use.
- A group of checkboxes sat on a tinted field with no edge and read as a grey blob. It has the hairline every other frame in the workbench uses.
- At 320 px the resolver list pushed the page 17 px past the window. Long host lists break, and below 768 px the three columns become three lines.
- The footer floated in the empty space below the content. A rule ties it to the page.

## 0.20.2 - 2026-09-28

- The sign-in stands in two equal halves again. A fixed 420 px column left the greeting as a narrow block with the card adrift beside it; the page now splits down the middle, the way the house sets a sign-in. The base rule centres both halves, so the onyx side needed to be told to fill its column.

## 0.20.1 - 2026-09-28

- Fixed the public front page reading the dark palette. The colour mode defaults to dark when a visitor has no stored preference, so a first-time visitor met ink-coloured text on light panels: the demo heading landed at a contrast of 1.04. The public surface is light by design and now keeps its palette whatever the application around it is set to, and the document ground follows it while the page is on screen.
- The product mark on the ink head sits on a yellow square and is drawn in ink. It inherited the white of the head and stood on a near-white chip, which left the head with an empty box beside the name.
- The head runs into the band below it without the hairline that showed left and right of it: the head's own lower border ends with the content width, so the ink field now covers those two pixels as well.
- The demo panel stands straight on a hard offset. A one-degree tilt left every hairline inside it soft, and the panel kept its layer, so it steps over the band as intended.
- Each feature card carries its icon as a square field in the card's own colour with the ink drawing, the way the signal square works elsewhere on the page.
- On a phone the call below the opening line stays reachable: stacked, the demo panel used to land on top of it. The head keeps its two actions there and leaves the section link to the opening block, so it fits on one row again.

## 0.20.0 - 2026-09-28

- The application wears the bright color workbench. An onyx rail on the left carries the modules with a yellow edge on the open one, a 60 px top bar holds search, alerts and the account, and the panels sit as white cards on warm paper. Headings are set in Anton capitals, running text in Atkinson Hyperlegible, hostnames and measured values in IBM Plex Mono.
- Colour carries meaning throughout: lime says running, yellow says this wants attention, pink says this is urgent. The same three drive the status pills, the meters, the alert bands and the monitor rows, in light and in dark mode.
- The public front page is its own surface. It presents with square edges, two-pixel ink borders, a cyan band carrying the opening line, tiles edged in the house colours and a closing band in ink with a yellow heading.
- The front page speaks German and addresses the reader directly; the application behind the sign-in stays English. The page subtree carries `lang="de"`, so a screen reader switches voice for it and keeps the document language for everything else.
- The three type faces ship inside the image. The page asks no font service for anything at run time, so the first render costs no third-party request and the surface is complete on a closed network.
- The front page describes what the product does and leaves the question of where the source lives to the README.
- Measured before release: every visible text on eleven views reaches AA with reserve, in light and in dark mode, and every width from 320 to 1440 px stays inside the window.

## 0.19.0 - 2026-09-03

- Split the product into a public surface and an application, by address. The front page, sign-in and registration live at `/`, `/login` and `/register`; everything that needs a session lives under `/app`. Previously all of it shared one URL and the screen was chosen by internal state, so a link never said what it opened.
- Pages now have addresses: `/app/reports`, `/app/operations`, `/app/monitors/<id>`. A link opens what it names, the back button walks the pages you actually visited, and the browser tab carries the page name.
- The server sends each visitor to the half they belong in: a signed-in visitor asking for `/` or `/login` lands on `/app`, and a signed-out visitor asking for `/app` is sent to sign in. Query parameters survive the redirect, so an invite link keeps its token.
- Invite links now point at `/register` instead of the root, so an invited person lands on the form that accepts them rather than on the marketing page for a moment.
- `robots.txt` excludes `/app`, which is now possible without excluding the front page along with it.
- Fixed the browser tab keeping the last page name after signing out. The effect lived in the application shell, which stops rendering at that moment.

## 0.18.0 - 2026-09-03

- The public front page is now rendered on the server. A crawler that does not execute JavaScript — and a visitor on a slow connection — receives the page itself rather than an empty div, and the response carries the configuration the client would otherwise have fetched, so its first render matches the markup and React hydrates instead of rebuilding.
- Rendering is deliberately narrow. Only the root path, only visitors without a session, and only on an instance that already has an administrator: everything else needs a session, no crawler reaches it, and rendering it would add latency for nothing. Any other path still gets the plain shell, so search engines are not offered the same content under every URL.
- The server bundle is optional at every step. A missing or broken `dist-server` logs once and falls back to the shell, so a partial build can never take the application down. In development the client renders as before.
- Fixed `express.static` answering `/` with the index file before the renderer was reached, which is why the first attempt served the empty shell either way.

## 0.17.0 - 2026-09-03

- Made the project findable. The repository had no description, no homepage and no topics — the three fields GitHub search ranks on. It now carries all three, along with a README opening that says what the tool does in one sentence, badges for release, CI, container image and licence, and a line naming every protocol and check it covers.
- Added the metadata a link needs to describe itself: page description, canonical URL, Open Graph and Twitter card tags, and JSON-LD describing the project as a SoftwareApplication. Sharing the URL now produces a preview card instead of a bare link.
- Added a 1200×630 preview image built from the product mark and the palette, plus `robots.txt` and `sitemap.xml`.
- The page carries a `<noscript>` summary of what crt.watch checks, so crawlers that do not run JavaScript see the product rather than an empty div.
- The browser tab names the page you are on (`Operations · crt.watch`) instead of repeating the marketing title in every tab.

## 0.16.2 - 2026-09-03

- Removed the scrollbar from the sidebar. Its inner wrapper reserved `100vh` minus the brand row, a fixed subtraction that stopped being correct the moment the workspace switcher was added below it: the content ran 57 px past the viewport and produced a scrollbar with nothing worth scrolling to. Brand and switcher now keep their height and the navigation takes what is left, so it scrolls only when it genuinely does not fit — and then only the navigation, with the brand staying put.
- The maintenance window field shows all three example formats in its placeholder. It was two lines tall while the placeholder was three, so the third example was cut off.

## 0.16.1 - 2026-09-03

- Pinned `qs` to 6.16.0 through a root override to clear GHSA-x5fp-wj9c-mxmx and GHSA-4mjr-xmp4-gh2g. Express 4.22.2 and body-parser both require `qs` as `~6.15.1`, and the advisories cover that entire line, so no Express 4 release can resolve them on its own. `npm audit --omit=dev` reports no findings again.

## 0.16.0 - 2026-09-03

- The product has a mark of its own. A shield with a certificate check now appears in the sidebar, on the sign-in and registration cards, on the public front page, and as the browser icon, replacing a generic activity glyph and a favicon that showed an unrelated green circle.
- Replaced the two unlabelled dropdowns in the header with one workspace switcher in the sidebar: the current organization with its initials, the active team, every organization you belong to with your role in each, and how much of the plan's monitor allowance is used.
- The header is down to what an operator needs while working: search, an alert bell that carries the critical count, one primary action, and an account avatar. Colour mode moved into the account menu, where a personal preference belongs.
- Menus behave like menus: they close on an outside click and on Escape.
- An organization with no monitors now gets a first-run screen that says what a check does and offers the one action that starts it, instead of a health ring reporting "100 % healthy" about nothing and three rows of zero counters.
- Added a loading state. Without it, an account with hundreds of monitors saw the first-run screen flash by while the first request was still in flight.
- Applications and Reports explain what fills them when they are empty, and distinguish "nothing here yet" from "nothing matches your filters".

## 0.15.1 - 2026-09-03

- Rebuilt the availability report as a real table. The monitor name had a fixed 110px column while a single-digit count had the widest one, so names wrapped onto three lines and were clipped on top of that. Columns now size to what they hold, and numbers are right-aligned and tabular so they line up digit under digit.
- Fixed status pills stretching across a whole column: `StatusPill` emitted `info` as a tone name, which collided with `.info`, the label/value row layout class, and pills inherited a `flex` rule meant for text cells. A pill is now sized by its content and never grows.
- Settings, Operations and Organizations were built as a sequence of separate two-column blocks. Each block balanced its own height, so a block with an odd number of panels left a hole beside it. Each page is now one flow that fills both columns continuously.
- Stored values no longer reach the interface raw: `super_admin`, `tenant_visible` and `active` are now written out as words, through one shared label helper that falls back to sentence case for anything unlisted.
- Incident states carry their own colours (open amber, acknowledged blue, resolved green) instead of falling through to grey.
- The notification delivery log is laid out as a log: state, channel and provider on one line, the error below it, rather than an error right-aligned into whatever space was left.
- Colour follows meaning in the remaining places it did not: logging out, cancelling an edit and archiving a team are no longer red, and a team's slug is no longer coloured as if it were a role.
- Page titles no longer repeat the first panel heading below them, and rollup rows in Applications are keyboard-reachable with a visible hover state.

## 0.15.0 - 2026-09-03

- Rebuilt the interface on one design token layer (`theme.css`): four corner radii instead of sixteen, five status tint values instead of thirty-three, and one control height shared by buttons, inputs and selects. The `soft-ui`, `polish` and `status` stylesheets that each corrected the previous layer are gone, and with them 157 `!important` declarations.
- Unified twelve competing chip and badge classes into one pill shape and one status square, both taking their colour from a single `--tone` carrier, so a status reads the same in a list row, a filter, a group header and a detail panel.
- Buttons now speak one language. Bare `<button>` elements are no longer styled, so nothing has to override anything: an action is the accent button, a neutral outline, or a status outline. Green stopped meaning "save" — it only reports health — and red is reserved for actions that destroy something, so Cancel, Close and Impersonate became neutral.
- Replaced the dashboard's three separate counter rows, which showed the same monitors under different labels and occasionally different numbers, with one hero: a ring for the share of healthy checks, a one-line verdict, and four counters that double as filters. Counters and filter chips now read from the same source.
- Certificate lifetime is set apart wherever it appears, with a meter that shows the remaining days against that monitor's own warning threshold, so "41 days" reads as comfortable or urgent without doing the arithmetic.
- Monitor groups take the colour of their worst member in the header, and the detail header carries the monitor's status as a left accent.
- Rows in narrow panels now wrap onto more lines instead of squeezing names, selects and buttons into unreadable widths; settings pages flow their panels into both columns instead of leaving one half empty.
- Fixed the sidebar rendering near-invisible light-grey labels on a light background in bright mode, a navigation counter that sat on top of its own label, DNS entries overlapping their values, a page title that read "Dashboard" while a monitor was open, and a sidebar surface that stopped halfway down long pages.
- Copyable values (badge URLs, embed snippets, invite links) wrap instead of trailing off into an ellipsis.
- Every status colour is now chosen so that text in that colour clears WCAG AA against its own tinted pill in both themes, and the accent carries separate values for tint, text and filled surfaces for the same reason.
- Interface wording follows one rule: sentence case throughout, navigation labels match page titles ("Alerts" no longer opens "Notification Channels"), and the settings page no longer names the admin template it is built on.

## 0.14.1 - 2026-07-25

- Added a motion and depth polish layer: consistent eased transitions and press feedback on all interactive elements, page and modal entrance animations, floating dropdown menus, springier metric-card hover, and a sliding sidebar active indicator.
- The fixed header is now translucent with a backdrop blur in both themes, dark-mode cards get a machined top edge highlight, theme switches blend smoothly, and the login page has a quiet primary-tinted spotlight.
- All animations and transitions respect the user's reduced-motion preference.

## 0.14.0 - 2026-07-17

- Replaced sql.js with better-sqlite3: the database no longer lives fully in process memory and writes go to disk incrementally in WAL mode, so memory usage stays flat regardless of database size and the OOM-kill class of failures is gone. Existing SQLite files are opened in place with no migration needed.
- Statements are prepared once and cached; named parameters are trimmed to what each statement declares, and missing optional values bind as NULL.
- Backups and the boot snapshot checkpoint the WAL first so copies always contain the latest commits.
- The container now runs with a 384MB Node heap limit so garbage collection engages well below the container memory cap.

## 0.13.11 - 2026-07-17

- Added an always-on automatic safety-net backup (`crtwatch-auto-*.sqlite` in `/data/backups`) controlled by `AUTO_BACKUP_ENABLED`, `AUTO_BACKUP_INTERVAL_HOURS`, and `AUTO_BACKUP_KEEP` environment variables instead of database-stored settings, so backups keep running even after a database loss.
- Backup files are now written via temp file + rename so a crash mid-copy cannot leave a truncated backup, and automatic backups show up in the Operations backup list alongside manual ones with separate retention.

## 0.13.10 - 2026-07-17

- Fixed a data-loss bug: the SQLite file was rewritten in place on every persist, so an OOM kill or crash mid-write could truncate it to an empty file and the next start would silently create a fresh database. Persistence now writes to a temp file with fsync and renames it atomically over the target.
- Added a last-known-good snapshot: on startup, a database that contains at least one user is copied to `<databasePath>.boot-bak`; a wiped or fresh database never overwrites the snapshot, so the previous state stays restorable.

## 0.13.9 - 2026-07-08

- Reworked the dashboard layout: compact health hero with status icon, slimmer metric cards, a column header row in list view, and properly aligned certificate columns with readable day/date/TLS spacing.
- Fixed clipped monitor messages, problem chips, group badges, tag chips, and ghost buttons that were losing against the global button style and rendering with wrong colors or center-clipped text.
- Calmed secondary actions: monitor row icons and detail-page Pause/Resume are now neutral with color on hover, and Delete is separated by a divider from the other detail actions.
- Monitor rows are keyboard-accessible (focusable, Enter/Space opens the monitor) with a visible focus ring.
- Global polish: themed thin scrollbars, unified panel headers, centered empty states, refined toast, sidebar active accent bar, content-sized panel buttons, and a 2-column metric grid plus wrapping hero badges on small screens.

## 0.13.8 - 2026-07-08

- Added TOTP-based two-factor authentication: users can enable it from Profile (QR-free manual key entry, confirmation code, one-time backup codes), and login now requires a second step when 2FA is active.
- Added an audit log viewer: `GET /api/audit-log` (owner/admin only) plus a new panel on the Operations page showing organization and team management actions.
- Fixed the API dev server picking up an inherited `PORT` environment variable and silently binding to the Vite port instead of 8080; `dev:api` now pins `PORT=8080` explicitly via `cross-env`.

## 0.13.7 - 2026-07-08

- Added an optimization backlog documenting scheduler, storage, and UI polling improvement opportunities.
- Debounced SQLite persistence so writes no longer rewrite the whole database file on every statement, and flush pending writes on shutdown.
- Added missing indexes for the scheduler's due-monitor scan and check-result history lookups.

## 0.13.6 - 2026-06-18

- Moved the certificate authority mark to the top of the certificate detail panel.
- Added local Wikimedia-sourced CA logo assets for supported issuers with a safe initials fallback.

## 0.13.5 - 2026-06-18

- Matched certificate detail row spacing with the TLS panel and added a compact certificate authority mark to use the recovered panel space.

## 0.13.4 - 2026-06-18

- Required admin-level users to add an incident comment when acknowledging incidents and store that comment in the incident timeline.

## 0.13.3 - 2026-06-18

- Made monitor detail information panels more compact with finer row spacing and smaller certificate metadata typography.

## 0.13.2 - 2026-06-18

- Updated Nodemailer to clear the runtime dependency audit failure in CI.

## 0.13.1 - 2026-06-17

- Reduced monitor detail information row height while keeping long certificate values readable and safely wrapped.

## 0.13.0 - 2026-06-04

- Rebuilt the auth entry point around Passport Local while keeping secure HTTP-only API sessions and CSRF protection.
- Added optional Passport GitHub strategy configuration for a future GitHub login flow.
- Removed the previous workspace access-group/effective-role logic from the API and UI.
- Reworked organization and team management around direct tenant roles and direct team roles.
- Renamed current SaaS/user-management wording from workspaces to organizations/tenants across the active UI and documentation.
- Stopped creating legacy access-group tables for fresh installations while leaving existing legacy tables untouched.

## 0.12.7 - 2026-06-04

- Fixed fresh-database user creation by inserting explicit user columns so CI and new installs work with the impersonation column.

## 0.12.6 - 2026-06-04

- Added tenant-scoped teams with private or tenant-visible visibility, team roles, team memberships, and a team selector in the app shell.
- Added team management to the workspace admin UI, including create, edit, archive, member assignment, role changes, and member removal.
- Added optional initial team assignment to workspace invites so accepted invitations can create both tenant and team memberships.
- Hardened multi-tenant access with server-side `X-Team-Id` validation, active membership checks, last-owner protections, disabled membership handling, and audit log entries for team changes.
- Stored new invite tokens as hashes at rest and only exposed the raw invite URL immediately after invite creation.
- Added focused multi-tenant tests for team boundaries and owner-count protections.

## 0.12.5 - 2026-06-04

- Split the monitor form into mobile-friendly steps for Basics, Checks, Alerts, and Advanced settings.
- Added a thin Bootstrap 5.3 soft-UI design layer with Inter, tabular numbers, rounded cards, tinted status pills, subtle glows, and left accent bars.
- Added Bootstrap Icons and used them in the new monitor form step navigation and summary pills.
- Reduced hard-coded dashboard/status colors in favor of Bootstrap CSS variables and `rgba(var(--bs-*-rgb), ...)` tints.
- Refined dashboard hero, KPI cards, status pills, and monitor status marks to match the new flat SaaS dashboard style.

## 0.12.4 - 2026-05-31

- Improved label/tag entry with stable chips, blur/tab commit behavior, text mode, quick suggestions, and clear/remove actions.
- Reused the label input in personal alert preferences and notification routing so label handling is consistent across forms.
- Clarified workspace groups as access groups with role explanations, selected member counts, select-all/clear controls, and clearer group rows.
- Added a sticky monitor form action bar so save, save-and-check, and cancel actions stay visible in long forms.
- Constrained the public frontpage content to 80% desktop width for a calmer landing-page layout.

## 0.12.3 - 2026-05-31

- Added a profile page with account details, logout, and self-service password changes that require the current password.
- Added a header profile menu so logout and profile actions are always discoverable.
- Added direct pause/resume controls for monitors in the dashboard list and monitor detail view.

## 0.12.2 - 2026-05-31

- Rebranded the visible product name to `crt.watch` across the web UI, public pages, notifications, documentation, tests, quickstart output, and logo asset.
- Updated package metadata and README logo references to use the `crt.watch` name.

## 0.12.1 - 2026-05-31

- Reduced UI font weights so interface text does not exceed `600`, including dashboard monitor names and targets.
- Made default and Bootstrap buttons more compact.
- Added consistent semantic button styling for success, warning, and destructive actions across monitor, user, workspace, settings, import, and operations screens.

## 0.12.0 - 2026-05-30

- Added a `super_admin` platform role and migrated existing platform admins to super admins.
- Made first-run setup create a super admin account.
- Added super-admin user management for creating users, changing platform roles, rotating passwords, deleting users, and impersonating users for support.
- Added an impersonation banner action so super admins can return to their own account.
- Added a platform setting to disable public organization registration from the web UI while keeping invite links usable.

## 0.11.9 - 2026-05-30

- Removed the redundant `Selfhosted TLS monitoring` eyebrow from the application title bar.

## 0.11.8 - 2026-05-30

- Made dashboard list view the default monitor layout.
- Filled monitor row status markers with their status color and added status-colored row and metric-card hover treatment.
- Darkened dashboard card borders so they sit below the card background instead of reading as light outlines.

## 0.11.7 - 2026-05-30

- Darkened the dashboard KPI cards and restored padded rounded status icon blocks inside each card.

## 0.11.6 - 2026-05-30

- Restored the earlier dark colorful dashboard checklist styling from the repository history.
- Removed the circular health score from that restored layout while keeping clickable status, KPI, message, and problem filters.

## 0.11.5 - 2026-05-30

- Restored the larger dark dashboard health header and KPI card styling while removing the old circular score display.
- Kept the dashboard summary chips, KPI cards, status chips, messages, and problem chips clickable as monitor filters.

## 0.11.4 - 2026-05-30

- Rebranded the visible product name, public pages, authentication screens, notifications, README, license, and logo asset to `crt.watch`.
- Updated the quickstart script to install into `/opt/crt.watch` while keeping the current GitHub repository URL stable until the repository is renamed.
- Kept existing internal compatibility identifiers such as `crtwatch` metric names, database defaults, cookie names, and workspace package scopes unchanged.

## 0.11.3 - 2026-05-30

- Added clickable dashboard status summaries, metric cards, row status marks, result messages, and problem chips as filters.
- Added issue filters so operators can isolate monitors with the same warning, error, DNS mismatch, TLS deduction, or SSL Labs finding.
- Kept the dashboard row design compact by showing the first problem inline and expanding additional clickable messages only on demand.
- Changed DNS resolver comparison to run fresh on every monitor check instead of reusing cached DNS samples.
- Removed the per-monitor DNS comparison interval field from the monitor form.

## 0.11.2 - 2026-05-30

- Fixed dashboard status filter chips so inactive filters stay neutral gray and only selected filters use status colors.
- Kept the `All` filter selected only when no individual status filters are active.

## 0.11.1 - 2026-05-30

- Added a manual SSL Labs trigger API for public HTTPS targets and eligible monitor detail pages.
- Added an Operations UI form to trigger SSL Labs assessments for arbitrary public hosts.
- Stored monitor-triggered SSL Labs assessments in check history so the dashboard and monitor detail views update immediately.

## 0.11.0 - 2026-05-30

- Added workspace permission groups with group roles and effective per-organization member roles.
- Added member role editing, group assignment, group creation, group editing, and group deletion to the Workspaces UI.
- Extended user management so platform admins can update platform roles and rotate user passwords.
- Kept users multi-organization capable with independent rights per organization, including invite-time role selection that defaults to viewer.
- Added personal alert preferences for non-critical events while critical delivery remains controlled by workspace admin routes.

## 0.10.0 - 2026-05-30

- Added public registration that creates an isolated organization workspace for new users.
- Added workspace invite links so owners and admins can invite users who do not yet have an account.
- Added environment switches for the public frontpage and public registration while keeping first-run admin setup direct.
- Updated the workspace UI to show pending invites, copy invite links, and revoke unused invites.
- Added an Operations UI action to register an SSL Labs v4 API email directly through crt.watch and save it for assessments.
- Made dashboard status filter chips visibly color-coded in active and inactive states.

## 0.9.9 - 2026-05-30

- Added a public crt.watch frontpage that explains the service, links to GitHub, and keeps setup or sign-in one click away.
- Updated README and quickstart URLs for the renamed GitHub repository at `brightcolor/crt.watch`.
- Updated the local repository remote to the renamed GitHub repository.

## 0.9.8 - 2026-05-30

- Rebranded the product UI, public status pages, notifications, documentation, logo, package metadata, and server logs to `crt.watch`.
- Normalized Docker service, container, backup, export, database, cookie, and Prometheus metric names to the `crtwatch` / `crt-watch` naming scheme.
- Updated quickstart configuration variables to the `CRTWATCH_` prefix while keeping the current GitHub repository URL as the source checkout.

## 0.9.7 - 2026-05-30

- Removed the duplicate header brand so crt.watch is only shown in the sidebar brand area.
- Added a functional desktop sidebar collapse that keeps icon-only navigation visible and shows labels on hover.
- Removed the dashboard score ring while keeping the contextual health header and colored status summary chips.
- Tuned dashboard row typography, certificate validity display, TLS/SSL grade alignment, and hover surfaces for a denser operator view.

## 0.9.6 - 2026-05-30

- Reworked the dashboard into a dark, colorful score-and-checklist layout inspired by audit result interfaces.
- Added an overall health score ring with contextual headline, description, and status summary chips.
- Replaced the monitor table with compact status rows that show a colored status mark, monitor reason, target, certificate details, and actions.
- Fixed monitor row hover styling by removing the old table-cell surface model and making each monitor row a single interactive surface.
- Switched informational accent color to cyan for a darker but more colorful interface.

## 0.9.5 - 2026-05-30

- Made dashboard monitor rows denser with shorter row height, tighter text spacing, and compact icon actions.
- Added monitor cloning from the dashboard and monitor detail view; cloned monitors are created paused to avoid duplicate checks and alerts.
- Preserved monitor secrets during server-side cloning while continuing to redact them in API responses.
- Strengthened filled status indicators for OK, Warning, Critical, Down, Paused, and Unknown states.
- Fixed status filter chip behavior so clicking a status selects that status from the All view, and colored every chip by its status.
- Adjusted dashboard row hover styling so text cells, pills, and action areas visually move with the hovered row.

## 0.9.4 - 2026-05-29

- Removed the sidebar live overview block and made dashboard monitor rows more compact.
- Added dashboard view switching between grouped and flat list modes.
- Added multi-select status filters so operators can combine states such as OK and Warning while excluding Critical or Down.
- Enlarged dashboard summary numbers for quicker scanning.
- Added explicit TLS grade deduction reasons, persisted them with check results, and included them in TLS/SSL Labs deterioration alerts.
- Added status reason text to monitor details so operators can see why the latest status was assigned.
- Added certificate expiry threshold reasons to warning and critical status classification.

## 0.9.3 - 2026-05-29

- Added live UI refresh for visible pages so dashboards, monitor details, users, workspaces, settings, operations, and reports update without manual reloads.
- Refreshed visible data immediately when the browser tab becomes active again while pausing refreshes during form editing.
- Added dashboard problem chips that surface certificate, TLS, DNS, SSL Labs, and service issues directly in the monitor overview.

## 0.9.2 - 2026-05-28

- Removed the remaining cool-toned UI accents and moved the operator interface to a Discord-like neutral gray palette.
- Overrode AdminLTE/Bootstrap primary buttons, links, callouts, focus rings, navigation highlights, and label chips so the UI stays gray outside explicit status colors.
- Tightened custom panels to behave more like AdminLTE cards with card headers, card backgrounds, and table-style monitor rows.

## 0.9.1 - 2026-05-28

- Polished the AdminLTE operator interface with a more coherent shell, card, table, form, and monitor-detail treatment.
- Added explicit `Dark`, `Bright`, and `Auto` color modes, with dark mode as the default and auto mode following the operating system preference.
- Replaced the remaining color-heavy surfaces with a neutral charcoal and bright palette.
- Improved dashboard rows, embed controls, status surfaces, focused inputs, and theme persistence.

## 0.9.0 - 2026-05-28

- Added a SaaS-ready workspace model with tenant records, plan/status/limit fields, and role-based memberships.
- Scoped monitors, notification providers, and tenant settings by selected workspace while preserving existing installs through a default workspace migration.
- Added workspace roles for owners, admins, members, and viewers plus API enforcement for monitor writes, provider changes, and settings updates.
- Added a workspace switcher and workspace/member management page to the AdminLTE UI.

## 0.8.3 - 2026-05-28

- Added DNS resolution details to monitor results, including resolved IP addresses, authoritative nameservers, and comparison against Cloudflare, Quad9, and Google public resolvers.
- Added configurable DNS resolution change alerting with a global policy, per-monitor override, and per-monitor DNS comparison interval.
- Added per-monitor certificate change alert overrides while keeping the global certificate-change alert policy.
- Extended notification payloads and certificate CSV exports with DNS resolution data.

## 0.8.2 - 2026-05-28

- Replaced the fixed-width public SVG badges with a responsive badge renderer that dynamically sizes content and safely clips long hostnames.
- Added `?label=` and `?alias=` support for monitor and label badges so embeds can use short customer-facing names.
- Exposed alias badge URLs in the monitor and application embed panels.

## 0.8.1 - 2026-05-28

- Reworked the dark theme to use a neutral gray palette and removed the green/olive cast.
- Strengthened status colors across pills, table rows, dashboard info boxes, and status counters with clear green/yellow/red/gray states.
- Added datetime range builders for global and per-monitor maintenance windows while keeping text rules for recurring schedules.

## 0.8.0 - 2026-05-28

- Made AdminLTE 4 the only frontend shell and removed the previous native/AdminLTE skin switch.
- Rebuilt the main operator layout around AdminLTE navbar, sidebar, content header, footer, Bootstrap cards, info boxes, callouts, and responsive admin forms.
- Added a global monitor quick search in the header so operators can jump directly to a monitor by name, host, type, or label.
- Added a status center dropdown and sidebar health summary using the existing live status counts.
- Kept dark and light mode as the remaining interface preference.

## 0.7.1 - 2026-05-28

- Added a Vite development proxy for `/api`, `/metrics`, and `/public` so the frontend on `localhost:5173` can talk to the API on `localhost:8080`.
- Restarted the local development server after dependency and lockfile updates so Vite re-optimized AdminLTE and rendered the app again.

## 0.7.0 - 2026-05-28

- Added AdminLTE `4.0.0` as an optional frontend skin.
- Added an Appearance panel in Settings to switch between the native crt.watch design and AdminLTE 4.
- Reworked the main layout to use AdminLTE app wrapper, navbar, sidebar, content header, and content area classes when the AdminLTE skin is selected.
- Mapped existing crt.watch dashboard cards, panels, tables, forms, and modals into the AdminLTE/Bootstrap visual system while preserving the existing React workflows.

## 0.6.0 - 2026-05-19

- Added optional Qualys SSL Labs v4 assessments for public HTTPS hosts on port `443`, configured from the Operations UI with a registered API email.
- Cached SSL Labs assessments per host for at least 24 hours and carried the last external grade into regular check results between external scans.
- Added SSL Labs grade, status, findings, URL, CSV export fields, webhook payload fields, dashboard badges, and monitor detail rows.
- Added alert escalation when an SSL Labs grade deteriorates compared with the previous monitor result.
- Added direct import for discovery suggestions, including one-click accept and accept-all actions in the UI.
- Marked MX-derived discovery suggestions with `mail` and `mx` labels.
- Fixed label chip entry so Enter, comma, and blur commits keep all labels until they are explicitly removed.
- Standardized UI and public status dates to include leading zeroes for day and month.

## 0.5.0 - 2026-05-19

- Added an intensive TLS assessment that can probe supported TLS versions and flag deprecated protocol support, weak cipher patterns, missing forward secrecy, small certificate keys, and incomplete chains.
- Persisted supported TLS versions in check history and displayed them in monitor details.
- Added configurable alerting when a monitor's TLS grade or score deteriorates compared with the previous check.
- Extended webhook payloads with TLS grade, score, and supported protocol versions.

## 0.4.9 - 2026-05-19

- Fixed user creation feedback in the Users page by adding client-side validation, submit state, and visible API error messages.
- Added a clear password-length hint for new users.
- Added duplicate-email handling for user creation with a readable API response.

## 0.4.8 - 2026-05-18

- Clarified plain service checks versus TLS/STARTTLS certificate checks in monitor details, dashboard rows, and monitor type labels.
- Hid empty certificate-chain sections for plain service checks and replaced blank certificate fields with actionable guidance.
- Limited TLS validation options in the monitor form to monitor types that actually collect certificate data.
- Added per-service transport security modes for TCP, FTP, SMTP, IMAP, and POP3: Auto, STARTTLS where supported, SSL/TLS, and Plain.
- Added certificate collection, TLS grading, certificate-change watch, and secure login checks to service monitors when a secure transport mode is active.
- Grouped the dashboard monitor list by primary label and surfaced TLS grades directly in overview rows.

## 0.4.7 - 2026-05-18

- Redesigned public status pages with a polished customer-facing layout, summary cards, monitor list, incident timeline, and responsive styling.
- Changed public status page subscriptions to double opt-in so email and webhook targets must confirm before alerts are enabled.
- Added tests for public status page rendering, escaping, hostname hiding, and opt-in copy.

## 0.4.6 - 2026-05-18

- Fixed label blur commits with synchronous state updates so typed labels remain when moving into another field or saving.
- Improved monitor, operations, settings, and login form layout with aligned label/control rows.
- Simplified form section styling to reduce nested card clutter and improve scanability.

## 0.4.5 - 2026-05-18

- Fixed label inputs so a typed label is committed when the field loses focus instead of being discarded.
- Kept Enter/comma label entry and text-mode switching behavior intact.

## 0.4.4 - 2026-05-18

- Added a dynamic browser favicon that glows green when no actionable problems exist.
- Made the favicon blink red when warning, critical, down, or unknown monitor states need attention.
- Added periodic status polling so the favicon can update while the dashboard remains open.

## 0.4.3 - 2026-05-18

- Switched Docker Compose service settings to compact list/string syntax where supported.
- Changed the `/data` bind mount to the short Compose volume form while keeping the relative `DATA_DIR` default.
- Removed the bundled Watchtower service while keeping the update label for external Watchtower instances.

## 0.4.2 - 2026-05-18

- Removed `build: .` from the production Compose file so deployments and Watchtower use the published GHCR image.
- Added `docker-compose.dev.yml` for explicit local image builds.
- Updated quickstart and update docs to pull and run the published container image.

## 0.4.1 - 2026-05-18

- Changed Docker Compose persistence to an explicit relative bind mount using `DATA_DIR=./data`.
- Removed the image-level `/data` volume declaration to avoid implicit anonymous Docker volumes.
- Added missing runtime environment variables to Compose for scheduler defaults and timezone-sensitive windows.
- Added `.dockerignore` entries so local data and `.env` files are not copied into Docker build context.

## 0.4.0 - 2026-05-17

- Added monitor and label-based maintenance windows that suppress notifications while checks continue to run.
- Added API token management with read-only and read/write scopes.
- Added incident acknowledgement, assignment, and notes.
- Added notification delivery logging for sent and failed provider deliveries.
- Added TLS policy settings for security grading.
- Added custom public status page settings with slugs, titles, descriptions, logo URLs, and hostname hiding.
- Added scheduled auto-discovery jobs and persisted discovery suggestions.
- Added availability reports with check counts, incident counts, availability percentage, and MTTR.
- Added scheduled SQLite backups with UI download and retention controls.
- Reworked monitor labels into Enter-driven chips with a copy-friendly text mode.
- Added HTTP expected-header and redirect-follow checks.

## 0.3.0 - 2026-05-17

- Added SSL Labs-style TLS security grading and displayed grades in the dashboard and monitor detail view.
- Added flapping detection with a configurable global transition threshold.
- Added incident timelines for monitor details and public status pages.
- Added public status page subscriptions with email and webhook delivery for incident open and recovery events.
- Added route-level escalation delay controls for configurable notification policies.
- Added Certificate Transparency watch settings with manual check support.
- Added auto-discovery suggestions for common web and mail monitors.
- Added backup and restore UI for portable non-secret JSON exports.

## 0.2.2 - 2026-05-17

- Added browser history support for monitor details so mouse/browser Back returns to the monitor overview.
- Made Dashboard navigation always clear the selected monitor and return to the overview.

## 0.2.1 - 2026-05-16

- Reworked the main UI around clearer navigation, dashboard scanning, application rollups, detail actions, and grouped monitor form sections.
- Moved public status embed controls into the Applications area and added clearer empty states for first-run usage.

## 0.2.0 - 2026-05-16

- Added SemVer versioning and a subtle UI version display.
- Added label-based application rollups so one service can contain multiple checks.
- Added optional login checks after SMTP, IMAP, and POP3 STARTTLS negotiation.
- Added Prometheus-compatible `/metrics` output.

## 0.1.0 - 2026-05-12

- Initial crt.watch implementation.
- Added a Linux quickstart script that clones the repository into `/opt/crt.watch`, creates `.env`, and starts Docker Compose.
- Added configurable Docker host port publishing through `HOST_PORT` and the quickstart `CRTWATCH_PORT` override.
- Replaced environment-seeded admin credentials with a first-run web setup screen for creating the initial administrator.
- Fixed STARTTLS negotiation by using protocol-aware multiline response parsing for SMTP, IMAP, and POP3.
- Added direct SSL/TLS protocol presets with default ports for SMTPS, IMAPS, POP3S, LDAPS, implicit FTPS, and XMPP TLS.
- Added certificate-change alerts, public status pages, SVG badges, notification routing, user management, bulk import, retention settings, Docker health checks, and Watchtower/GHCR update support.
- Split notification provider configuration from per-monitor and per-route recipients.
- Added Uptime Kuma-style service checks for HTTP, HTTP login, TCP, DNS, SSH, FTP, SMTP, IMAP, and POP3.
- Added explicit FTP AUTH TLS certificate checks alongside the existing mail STARTTLS and direct SSL/TLS presets.
- Added optional service login checks for HTTP, SSH, FTP, SMTP, IMAP, and POP3, with plaintext credential checks gated per monitor.
- Added per-monitor alert grace periods so transient failures do not notify until the configured duration is exceeded.
- Added monitor deletion from the detail view and explicit cleanup of monitor history and alert history.
- Added public status pages and SVG badges for combined label/tag filters such as `prod+mail`.
- Added encrypted-at-rest storage for monitor login secrets, SMTP settings, and notification provider secrets.
- Added UI fields for service-check configuration and masked saved login/provider secrets in API responses.
- Added Docker Compose deployment on port `8080`.
- Added Express API, SQLite persistence, session authentication, CSRF header checks, and seeded admin user.
- Added monitor CRUD, manual checks, scheduler, TLS and STARTTLS check engine, status classification, and historical check storage.
- Added notification channels for SMTP email, Pushover, webhooks, Discord, Slack, Telegram, Gotify, and ntfy-compatible endpoints.
- Added alert deduplication and recovery notification behavior.
- Added React dashboard, monitor detail page, monitor editor, notification settings, search, filters, and dark/light mode.
- Added JSON import/export and CSV exports.
- Added tests for status classification, validation, and webhook payload shape.
