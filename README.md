# WebGuard

WebGuard is a small Chrome Extension Manifest V3 dashboard for **limited,
local-only observations** of the active website. It does not determine whether
a site is malicious and does not protect the user from threats.

## What currently works

- When opened from the toolbar, the popup reads the active tab's URL and shows
  its hostname and HTTP/HTTPS status.
- It automatically checks a few URL properties: transport scheme, embedded
  URL credentials, punycode hostname labels, IP-address hosts, and non-default
  ports. The local risk estimate uses only embedded credentials,
  internationalized hostnames, and non-default ports; HTTP and IP-address
  observations do not add points by themselves.
- Overview and URL Analysis show an explainable preliminary local URL risk
  estimate from 0 to 100. Embedded credentials add 35 base points and
  internationalized hostnames add 30 base points; together they share a
  50-point cap to limit overlap. A non-default port adds 10 points. The
  resulting maximum of 60 points is normalized to 0–100. Scores 0–24 are Low,
  25–59 Medium, and 60–100 High. Each finding shows its source evidence,
  severity, weight, and reason. Missing or inconsistent check data produces an
  unavailable estimate instead of being treated as a clean result.
  These heuristic weights are not calibrated probabilities, and the estimate
  does not detect malware or conclusively identify phishing or malicious sites.
- The **Check page signals** button injects a small function into the current
  tab on demand. It snapshots cross-origin resource hostnames, the navigation
  redirect count, possible visible cookie/consent interface elements, and
  cookie names exposed through `document.cookie`. Cookie values are discarded
  before results return to the popup; HttpOnly cookies are not visible to page
  scripts. These are best-effort observations, not confirmed trackers or a
  consent assessment.
- The service worker passively records main-frame navigation starts,
  completions, errors, browser-reported redirect events, and
  `onCreatedNavigationTarget` events. Navigation IDs and tab IDs associate
  observed redirect steps; Chrome's source and target tab IDs identify
  browser-reported new-tab targets where available. A new-tab event is not
  treated as proof of a redirect. Overview and URL Analysis show the sanitized
  destination, new-tab/source-tab relationship, observed redirect chain, and
  unavailable details. A navigation with no redirect event is described as
  "no redirect event observed", not proof that no redirect occurred.
- A bounded history of at most 100 navigation records is held in
  `chrome.storage.session`, which survives service-worker restarts and is
  cleared when the browser session ends. Stored URLs omit credentials, query
  strings, and fragments. Monitoring starts when the updated extension loads;
  it cannot recover earlier events.
- For up to 12 observed resource hostnames, the Ads & Trackers section compares
  hosts against a small bundled subset of host-wide EasyList and EasyPrivacy
  rules. A match shows its source, exact rule, and revision. A non-match is
  labeled unknown, not safe. The extension does not block requests or inspect
  hosts omitted by the 12-host display limit. Missing, invalid, checksum-
  mismatched, or expired rule data produces an explicit unavailable state.
- Website Report displays the local observations held in the open popup.
- **Exposure Intelligence** provides an email mode and a website incident
  history mode. Both validate input locally. No provider with approved terms
  is configured, so neither an email address nor a domain is sent anywhere.
  The UI distinguishes invalid input, provider unavailable, no-match, and
  provider results; no-match is never a safety verdict.

## Local reputation foundation (preparatory only)

`popup/url-reputation.mjs` defines a provider-independent result contract with
`not-checked`, `malicious`, `no-match`, and `unavailable` statuses. It includes
provider/dataset identity when available and threat categories explicitly
supplied by that dataset; it does not invent categories or confidence scores.
The local matcher accepts a canonicalized HTTP(S) URL and an in-memory dataset.
Domain indicators match the exact hostname and match subdomains only when
`includeSubdomains` is explicitly true. URL indicators match the exact scheme,
host, port, and pathname; query strings and fragments are ignored. URL
normalization strips credentials, query strings, and fragments before local
matching, and normalized visited URLs are not included in results.

This is an interface and matching mechanism only, not active threat
intelligence. No dataset is bundled, and no lookup is wired into the dashboard.
Tests use only synthetic fixtures and do not contact or claim to represent a
threat-intelligence provider. A matching indicator reports malicious only with
its explicitly supplied categories; valid data with no match reports
`no-match`, never safe. Missing or invalid data reports unavailable. Local URL
checks and Ads & Trackers host classification remain independent; clean HTTPS
or structural checks cannot override a malicious reputation result. Future
provider adapters can use `normalizeProviderResult`; that pure function does
not call an adapter or perform network access.

## Exposure Intelligence provider status

Both modes currently return **provider unavailable** after local input
validation. No search value is transmitted, stored, or logged. The UI and
provider contract are ready for a source that has been approved for WebGuard's
intended use; a production adapter must be explicitly configured in
`popup/popup.js`. There is no live or simulated result data in the popup.

Provider review completed on 22 October 2026:

| Source | Access / conditions | Decision |
| --- | --- | --- |
| HIBP email breach API | Authenticated API key and an eligible subscription plan; direct email search transmits the address. Domain-wide breached-address search requires an authenticated request and verified domain ownership. | Not integrated. No key or approved backend is configured. |
| HIBP public all-breaches metadata API | Public catalog endpoint is reachable without an API key. The [Terms of Use](https://haveibeenpwned.com/TermsOfUse) restrict third-party/commercial benefit and prohibit building a substantially similar breach database/search service unless an expressly permitted paid service applies. | Not integrated: a website breach-history search adapter could be covered by that restriction. Private-only use did not establish permission. |
| HIBP Pwned Passwords | Public API, but checks password material and is outside this feature; WebGuard must not collect passwords. | Not used. |

The HIBP [API documentation](https://haveibeenpwned.com/API/v3),
[public catalog](https://haveibeenpwned.com/PwnedWebsites), and
[privacy policy](https://haveibeenpwned.com/Privacy) were reviewed. During
development, a direct request to the public catalog endpoint succeeded and
returned metadata; this was a provider research probe only. The extension does
not call that endpoint, and a successful public request is not permission to
build or distribute a lookup product. Obtain written approval or an
applicable paid license before implementing an HIBP-backed search.

Email results require an approved provider. If its API key is required, use a
separately deployed backend with server-side environment variables; never put
secrets in the manifest, popup, service worker, or content scripts. No backend
or provider environment variables are implemented in this project. The
adapter contract requires a provider ID/name, explicit approval, terms URL,
abortable lookup, source attribution, normalized incident metadata, and
an explicit website relationship (`website`, `organization-domain`,
`related-service`, or `email-domain`) for website results. Direct website and
organization-domain classifications must match the submitted hostname
exactly; related-service and email-domain records must remain separately
labeled. Provider data must be rendered as text and confirmed/unverified
status must reflect the source. The
implementation includes timeout, network failure, rate-limit, and malformed
response states. Tests use clearly synthetic in-memory adapter fixtures and
never contact a provider.

WebGuard does not contact a reputation service, transmit browsing data,
display or retain cookie values, block content, or export reports. Navigation
monitoring is passive and local; it does not block or claim to prevent
redirects. Chrome may omit events or URL details, restricted browser pages may
have unavailable destinations, and monitoring can miss events. URLs shown and
held in session history have credentials, query strings, and fragments removed.
A redirect, external destination, or new tab alone is not evidence of
maliciousness. Cookie names are read only after the user starts a page-signal
check and are held only in the open popup session. HttpOnly cookies and cookie
attributes are not available through this page-level inventory. Cross-origin
resources are not necessarily ads or trackers; unmatched and omitted hosts
have not been determined safe. Request blocking, live reputation lookup, and
verified security verdicts are not available in this permission-limited build.
During browsing, rule data is read from the bundled extension package and
browsing data is not sent to an external service. The explicit developer-run
rules updater contacts the public EasyList GitHub snapshot and feed.

## Project structure

```text
WebGuard/
├── manifest.json
├── README.md
├── background/
│   └── service-worker.js
├── content/
│   └── content.js
├── rules/
│   └── resource-host-rules.json
├── popup/
│   ├── popup.css
│   ├── popup.html
│   ├── popup.js
│   ├── exposure-intelligence.mjs
│   ├── exposure-intelligence.test.mjs
│   ├── exposure-renderer.mjs
│   ├── navigation-history.mjs
│   ├── navigation-history.test.mjs
│   ├── navigation-renderer.mjs
│   ├── resource-classifier.mjs
│   ├── resource-classifier.test.mjs
│   ├── resource-classification-preview.html
│   ├── resource-classification-preview.js
│   ├── resource-classification-failure-preview.html
│   ├── resource-classification-failure-preview.js
│   ├── url-reputation.mjs
│   ├── url-reputation.test.mjs
│   ├── url-checks.mjs
│   ├── url-checks-renderer.mjs
│   ├── url-checks.test.mjs
│   ├── risk-engine.mjs
│   ├── risk-engine.test.mjs
│   ├── url-checks-preview.html
│   └── url-checks-preview.js
└── tools/
    ├── update-resource-rules.mjs
    └── update-resource-rules.test.mjs
```

## Install in Chrome

1. Save the project files in a folder named `WebGuard`.
2. Open Google Chrome and navigate to `chrome://extensions`.
3. Turn on **Developer mode** using the toggle in the upper-right corner.
4. Click **Load unpacked**.
5. Select the `WebGuard` project folder itself—the folder containing
   `manifest.json`—and confirm.
6. Pin WebGuard from Chrome's Extensions menu if you want a toolbar shortcut.
7. Open a regular website in a tab, then click the WebGuard toolbar icon. The
   dashboard displays its URL properties and local URL checks.
8. In Overview, click **Check page signals** to take an on-demand snapshot of
   the current page's loaded-resource timing entries, navigation redirect
   count, visible consent-interface hints, and cookie names visible to page
   scripts. Cookie values are not displayed; HttpOnly cookies are unavailable.
9. Use the left navigation or overview quick-access cards to review local URL
   results, passive navigation records, page signals, and the in-popup report.
   Use the arrow keys, Home, or End while focused on navigation to switch
   sections with the keyboard.
10. Open **Exposure Intel**, switch between its two modes, and submit valid
   and invalid values. Both modes validate locally and report provider
   unavailable without transmitting the values in this build.
11. To confirm restricted-page handling, open a Chrome page such as
   `chrome://extensions` and open the popup there. Chrome restricts access to
   browser-internal pages; WebGuard reports that limitation without attempting
   to inspect the page.

After editing extension files, return to `chrome://extensions` and click the
extension's **Reload** button before testing again.

## Permissions and privacy

- `activeTab` permits temporary access to the active tab's URL after the user
  opens the popup. The extension does not request the broad `tabs` permission
  or site-wide host permissions.
- `webNavigation` is required to receive Chrome navigation lifecycle events,
  redirect details, navigation identifiers, and `onCreatedNavigationTarget`
  source/target tab identifiers. These browser events can expose navigation
  URLs across sites; WebGuard strips credentials, query strings, and fragments
  before keeping event history, and does not transmit those details.
- `storage` is used with `chrome.storage.session` only for the bounded event
  history, so it survives service-worker restarts but not the end of the
  browser session. The service worker restricts session storage to trusted
  extension contexts. This API requires Chrome 102 or later. No persistent
  browsing-history database is used.
- `scripting` is used only after the user presses **Check page signals**.
  Together with `activeTab`, it permits a one-time script in the current tab;
  it does not grant continuous access to all websites. Chrome may show this
  additional permission when the extension is reloaded.
- Cookie names are read from the active page's `document.cookie` only during
  that on-demand check. The popup receives names only; values are discarded in
  the page script. This cannot see HttpOnly cookies and does not require the
  `cookies` or broad host permissions.
- Open the popup from the extension's toolbar button on a regular website.
  Chrome may not expose the URL for browser-internal pages, the Chrome Web
  Store, or special tabs.
- The content script is intentionally not registered in the manifest.
- The extension does not transmit visited URLs, page signals, navigation
  records, email addresses, or exposure-search domains. Exposure values stay
  in the popup and are not written to extension storage. No provider is called
  in this build. No remote code is loaded and no verified threat verdict is
  issued. Only the bounded, sanitized navigation event history is held in
  session storage. Rule data is loaded from the extension package. The updater
  below is an explicit developer operation that contacts the public ruleset
  source.
- Popup console diagnostics do not include the active page URL or its query
  parameters. Page-signal failures are shown in the popup without logging
  exception details.

## Troubleshooting

Run all tests from the project folder with
`node --test background/navigation-listeners.test.mjs popup/url-checks.test.mjs popup/risk-engine.test.mjs popup/navigation-history.test.mjs popup/url-reputation.test.mjs popup/resource-classifier.test.mjs popup/exposure-intelligence.test.mjs tools/update-resource-rules.test.mjs`.
The tests use local fixtures and
parsing only; they do not contact the rule feeds, navigate to sample URLs, or
make external network requests. Classifier failure-state tests inject in-memory
responses for missing, expired, malformed, and checksum-invalid rules data;
they never modify the bundled rules file.

### Exposure Intelligence manual test checklist

- [ ] Email: submit a valid-looking address. It is validated locally, reports
  provider unavailable, and makes no network request.
- [ ] Email: submit malformed values (missing `@`, bad domain, or whitespace).
  The UI reports invalid input without a request.
- [ ] Website: submit a valid domain. Confirm provider-unavailable is shown
  and no network request is made in this provider-unconfigured build.
- [ ] No findings: run the synthetic provider adapter tests and confirm a
  no-match state is not described as safe. No live no-match can be claimed
  without an approved provider.
- [ ] Confirmed/unverified sample records: the tests use synthetic adapter
  fixtures only. The UI does not include demo data and must not display those
  fixtures as live findings.
- [ ] Website: submit an invalid host, IP address, localhost, or non-HTTP(S)
  URL. Confirm validation prevents a request.
- [ ] Provider unavailable: this is the expected state for both modes until an
  approved source is configured.
- [ ] Rate limit: the provider adapter handles HTTP 429 and bounded
  `Retry-After` values; automated tests exercise the normalized adapter
  response without deliberately rate-limiting a live service.
- [ ] Timeout, network failure, and malformed provider response: automated
  tests inject these cases and confirm they render as unavailable, not
  no-match.
- [ ] Sample/demo mode: no simulated UI provider is bundled. Automated tests
  use synthetic fixtures only and never present those fixtures as live
  findings.

## Passive navigation monitoring

After reloading the extension with the `webNavigation` and `storage`
permissions, open `myanimes.in` and click a link or video control that opens a
new tab. Open WebGuard in both the source tab and destination tab. The monitor
should show the destination tab ID and source tab ID when Chrome reports them.
Use a test page or site that performs an HTTP redirect to observe a confirmed
redirect chain; a navigation without a reported redirect is not proof that
none occurred. Try a browser-internal destination to confirm that WebGuard
reports its URL as restricted or unavailable rather than guessing. The
monitor only sees events after the extension has been reloaded and cannot
recover activity from before installation or while it was disabled. Chrome
may withhold details or events; the monitor is not a security verdict and
does not block navigation.

For a visual, test-only preview of all five URL-check rows, open a separate
browser tab to
`chrome-extension://<extension-id>/popup/url-checks-preview.html`, replacing
`<extension-id>` with WebGuard's ID shown on `chrome://extensions`. The page
imports the same checker and row renderer used by the popup, evaluates sample
URLs in memory, and labels each case PASS or FAIL. It is not linked from the
dashboard, does not change the active website tab, makes no requests, and does
not present results as a security verdict.

For a synthetic host-classification preview, open
`chrome-extension://<extension-id>/popup/resource-classification-preview.html`
in a separate tab. It loads only the bundled JSON from the extension package
and passes synthetic strings to the same classifier and renderer used by the
popup. It does not inspect the active website or navigate to or contact any
sample host.

To inspect ruleset failure handling in Chrome, open
`chrome-extension://<extension-id>/popup/resource-classification-failure-preview.html`
in a separate tab. This isolated test-only page injects in-memory missing,
invalid-JSON, malformed, expired, and checksum-mismatched responses into the
same loader and renderer, then verifies the packaged bundle still classifies
an unmatched host as unknown. It never modifies the bundled JSON, the active
popup, or the active website, and requires no additional permission. This
browser preview must be opened and observed in Chrome; Node tests alone do not
constitute browser verification.

## Bundled host-rule data and updates

The bundled subset contains only exact host-wide rules in the
`||hostname^` form, from EasyList's `easylist/easylist_adservers.txt` and
EasyPrivacy's `easyprivacy/easyprivacy_trackingservers_general.txt`. The
updater also checks the corresponding EasyList/EasyPrivacy allowlist files and
declines to emit a curated host if a matching exception is present.
Path-specific, wildcard, option-bearing/contextual, malformed, and IP rules
are not accepted. The current small reviewed host set is deliberately not the
complete EasyList or EasyPrivacy ruleset and is not an ad blocker. At the
checked-in revision, the subset has 17 rules. `googleads.g.doubleclick.net`
matches the supported EasyList rule `||g.doubleclick.net^` at a DNS label
boundary. EasyList also has path- and context-scoped allowlist entries for that
host; WebGuard does not apply those request-level exceptions because it only
observes hostnames. A host classification is therefore source-list association,
not a claim that a particular request would be blocked. The
`tpc.googlesyndication.com` rule appears in a different EasyList file,
`easylist_specific_block.txt`, which this updater does not consume, so it
remains unknown. WebGuard does not infer labels from hostname wording.

The checked-in JSON records both list names and source URLs, the pinned Git
revision, source modification/expiry times, the exact matched source rules,
and a SHA-256 checksum over the data. It expires according to EasyList's
published feed metadata (currently a four-day update interval); stale or
integrity-invalid data is unavailable rather than treated as a clean result.
Rule refresh is **not automatic**. To explicitly refresh, from the project
root run:

```text
node tools/update-resource-rules.mjs
```

That command contacts the public EasyList feed to validate its title, version,
last-modified time, expiry, and commit, then fetches the ad-server and general
tracking-server files plus their allowlists from that pinned Git revision.
It only emits the fixed reviewed host set when every exact host-wide rule is
still present and no overlapping exception is found. On success it atomically
replaces `rules/resource-host-rules.json`; on validation or download failure,
the existing bundle remains unchanged. Review the resulting revision and
attribution before distributing an updated build.

EasyList's repository states that, unless otherwise noted, its contents are
dual-licensed under GPL version 3 or later, or CC BY-SA 3.0 Unported or later;
when required, attribute **“The EasyList authors”** and link to
[EasyList](https://easylist.to/) and its
[license terms](https://easylist.to/pages/licence.html). The bundled rules are
derived from the pinned repository snapshot shown in the JSON. Check those
terms before redistributing the extension or its extracted data.

- **"Manifest file is missing or unreadable":** In **Load unpacked**, select
  the project root folder containing `manifest.json`, not its `popup` or
  `background` subfolder.
- **"Service worker registration failed":** Check that
  `background/service-worker.js` exists at the shown path and that
  `manifest.json` is valid JSON. Use the **Errors** button on the extension's
  card for more details. If the worker reports a missing or unregistered
  `webNavigation` event, navigation history is explicitly unavailable rather
  than partially monitored; verify the extension was loaded from the project
  root and reload it.
- **Popup says the URL is unavailable:** Chrome restricts access to some
  browser-internal pages and special tabs. Test by opening WebGuard on a normal
  `http://` or `https://` website. The popup reports missing tab URLs instead
  of attempting to inspect those restricted pages.
- **Page signal check is unavailable:** Check that the `scripting` permission
  appears in `manifest.json`, reload the extension, and launch it from the
  toolbar on a normal website. Chrome blocks script access to browser-owned
  pages and the Chrome Web Store.
- **Page signal check appears stuck:** Reload WebGuard at `chrome://extensions`,
  close any existing popup, reopen it from the toolbar on the website, and
  check the popup DevTools Console for a `[WebGuard]` error message.
- **Exposure lookup is unavailable:** This is expected until an approved
  provider adapter is configured. No provider permission or API key is active
  in the current build.
- **Popup still shows an older version:** Click **Reload** on the extension
  card at `chrome://extensions`, then close and reopen the popup.
- **The extension does not appear in the toolbar:** Open Chrome's Extensions
  menu and pin WebGuard.
- **An API or JavaScript error appears:** Open the extension's **Errors**
  details on `chrome://extensions`. For popup errors, right-click the popup,
  select **Inspect**, and check the **Console**.
