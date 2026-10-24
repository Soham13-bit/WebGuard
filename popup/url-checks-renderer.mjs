export function appendUrlCheckResult(container, check) {
  const document = container.ownerDocument;
  const item = document.createElement("article");
  item.className = "result-item" + (check.flagged ? " has-observation" : "");

  const indicator = document.createElement("span");
  indicator.className = "result-indicator";
  indicator.setAttribute("aria-hidden", "true");
  indicator.textContent = check.flagged ? "!" : "✓";

  const content = document.createElement("div");
  content.className = "result-content";
  const title = document.createElement("strong");
  title.textContent = check.name;
  const detail = document.createElement("p");
  detail.textContent = check.detail;
  content.append(title, detail);

  const status = document.createElement("span");
  status.className = "result-status";
  status.textContent = check.status;
  item.append(indicator, content, status);
  container.append(item);
}

export function renderUrlCheckResults(container, checks) {
  container.replaceChildren();
  checks.forEach((check) => appendUrlCheckResult(container, check));
}

export function renderUrlRiskResults(container, risk) {
  container.replaceChildren();
  const document = container.ownerDocument;
  const summary = document.createElement("p");
  summary.className = "url-risk-summary";

  if (!risk || !risk.available) {
    summary.textContent =
      risk && risk.missingChecks && risk.missingChecks.length
        ? "Preliminary local URL risk estimate unavailable. Missing checks: " +
          risk.missingChecks.join(", ") +
          "."
        : "Preliminary local URL risk estimate unavailable; this is missing information, not a detected problem.";
    container.append(summary);
    return;
  }

  summary.textContent =
    "Preliminary local URL risk estimate: " +
    risk.score +
    "/100 · " +
    risk.severity +
    ". " +
    risk.points +
    " of " +
    risk.maxPoints +
    " weighted points after overlap caps. This is not a verified threat verdict.";
  container.append(summary);

  const note = document.createElement("p");
  note.className = "url-risk-note";
  note.textContent =
    "HTTP transport and IP-address hosts are shown as URL observations but do not add risk points by themselves.";
  container.append(note);

  if (risk.findings.length === 0) {
    const empty = document.createElement("p");
    empty.className = "url-risk-empty";
    empty.textContent =
      "No scored URL indicators were detected in the available checks; this does not establish that the site is safe.";
    container.append(empty);
    return;
  }

  const list = document.createElement("div");
  list.className = "result-list url-risk-findings";
  risk.findings.forEach((finding) => {
    const item = document.createElement("article");
    item.className = "result-item has-observation";

    const content = document.createElement("div");
    content.className = "result-content";
    const title = document.createElement("strong");
    title.textContent = finding.name;
    const evidence = document.createElement("p");
    evidence.textContent = "Evidence: " + finding.evidence;
    const reason = document.createElement("small");
    reason.textContent =
      finding.severity +
      " · " +
      finding.weight +
      " base points" +
      (finding.group ? " · overlapping-indicator cap applies" : "") +
      " · " +
      finding.reason;
    content.append(title, evidence, reason);
    item.append(content);
    list.append(item);
  });
  container.append(list);
}
