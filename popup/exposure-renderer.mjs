const STATUS_MESSAGES = Object.freeze({
  idle: "Choose an investigation mode and submit a value to begin.",
  "invalid-input": "Input is invalid. Check the value and try again.",
  unavailable:
    "Provider results are unavailable. This is not a no-match or a safety verdict.",
  "network-error":
    "The provider could not be reached. Check your connection and try again.",
  timeout: "The provider request timed out. Try again later.",
  "rate-limited":
    "The provider is rate limiting requests. Wait before trying again.",
  "no-match":
    "No matching records were found in the available catalog. This does not mean the website is safe or that every incident is known."
});

function addText(document, container, tagName, className, text) {
  const element = document.createElement(tagName);
  if (className) {
    element.className = className;
  }
  element.textContent = text;
  container.append(element);
  return element;
}

function plainDescription(document, html) {
  const Parser = document.defaultView && document.defaultView.DOMParser;
  if (typeof Parser !== "function") {
    return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
  }

  const parsed = new Parser().parseFromString(html, "text/html");
  return (parsed.body.textContent || "").replace(/\s+/g, " ").trim();
}

function formatDate(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    return null;
  }

  return new Date(value).toLocaleDateString();
}

function formatTimestamp(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    return null;
  }

  return new Date(value).toLocaleString();
}

function remediationFor(record) {
  const categories = record.dataClasses.map((item) => item.toLowerCase());
  const actions = [
    "Check the affected service’s official incident notice and account-security guidance."
  ];

  if (categories.some((item) => item.includes("password"))) {
    actions.push(
      "Change the password on the affected service and anywhere it was reused; use a unique password."
    );
  } else {
    actions.push(
      "Use unique passwords for important accounts and change any credentials you believe may be exposed."
    );
  }

  actions.push("Enable multifactor authentication where available.");
  if (
    categories.some((item) =>
      /email|phone|address|birth|payment|credit|financial/.test(item)
    )
  ) {
    actions.push(
      "Be alert for targeted phishing or unexpected account-recovery messages."
    );
  }
  return actions;
}

function websiteRelationshipLabel(relationship) {
  return {
    website: "AFFECTS THIS WEBSITE",
    "organization-domain": "ORGANIZATION-DOMAIN MATCH",
    "related-service": "RELATED SERVICE — NOT THIS WEBSITE",
    "email-domain": "EMAIL-DOMAIN ASSOCIATION — NOT A WEBSITE INCIDENT"
  }[relationship];
}

function renderProviderMetadata(container, result) {
  const document = container.ownerDocument;
  const providerName =
    result.provider && result.provider.name
      ? result.provider.name
      : "Intelligence provider";
  const successfulAt = formatTimestamp(result.lastSuccessfulAt);
  addText(
    document,
    container,
    "p",
    "exposure-lookup-meta",
    successfulAt
      ? "Provider: " +
          providerName +
          " · Last successful lookup: " +
          successfulAt
      : "Provider: " + providerName
  );

  if (result.provider && result.provider.termsUrl) {
    const link = document.createElement("a");
    link.href = result.provider.termsUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "Provider terms";
    container.append(link);
  }
}

function renderRecord(container, record, mode) {
  const document = container.ownerDocument;
  const card = document.createElement("article");
  card.className = "exposure-result-card";
  card.dataset.confidence = record.confidence;

  addText(document, card, "h4", "exposure-result-title", record.title);
  const badge = addText(
    document,
    card,
    "span",
    "exposure-confidence",
    record.confidence === "confirmed"
      ? "CONFIRMED BY PROVIDER"
      : "UNVERIFIED REPORT"
  );
  badge.setAttribute("aria-label", badge.textContent);

  const breachDate = formatDate(record.breachDate);
  if (breachDate) {
    addText(document, card, "p", "exposure-result-meta", "Reported incident date: " + breachDate);
  }
  const addedDate = formatDate(record.addedDate);
  if (addedDate) {
    addText(document, card, "p", "exposure-result-meta", "Added to catalog: " + addedDate);
  }

  if (record.description) {
    addText(
      document,
      card,
      "p",
      "exposure-result-description",
      plainDescription(document, record.description).slice(0, 1200)
    );
  }

  if (record.dataClasses.length > 0) {
    addText(document, card, "strong", "exposure-subheading", "Exposed data categories");
    const categories = document.createElement("ul");
    categories.className = "exposure-category-list";
    record.dataClasses.forEach((category) => {
      addText(document, categories, "li", "", category);
    });
    card.append(categories);
  }

  if (mode === "website") {
    const relationship = addText(
      document,
      card,
      "span",
      "exposure-relationship",
      websiteRelationshipLabel(record.relationship)
    );
    relationship.className +=
      " exposure-relationship--" + record.relationship;
    if (record.exactDomain) {
      addText(
        document,
        card,
        "p",
        "exposure-result-meta",
        "Provider-reported domain: " + record.exactDomain
      );
    }
    addText(
      document,
      card,
      "p",
      "exposure-domain-note",
      record.relationship === "website"
        ? "This relationship is the provider’s classification and is not independently verified by WebGuard."
        : "This provider-reported relationship does not establish that the requested website itself was compromised."
    );
  }

  addText(document, card, "strong", "exposure-subheading", "Suggested next steps");
  const actions = document.createElement("ul");
  actions.className = "exposure-remediation-list";
  remediationFor(record).forEach((action) => {
    addText(document, actions, "li", "", action);
  });
  card.append(actions);

  const source = document.createElement("p");
  source.className = "exposure-source";
  const sourceLabel = document.createTextNode("Source: " + record.sourceName);
  source.append(sourceLabel);
  if (record.attribution) {
    source.append(document.createTextNode(" · " + record.attribution));
  }
  card.append(source);

  if (record.sourceUrl) {
    const sourceLink = document.createElement("a");
    sourceLink.href = record.sourceUrl;
    sourceLink.target = "_blank";
    sourceLink.rel = "noopener noreferrer";
    sourceLink.textContent = "Provider source and terms";
    card.append(sourceLink);
  }

  if (record.disclosureUrl) {
    const link = document.createElement("a");
    link.href = record.disclosureUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "Open source disclosure";
    card.append(link);
  }

  container.append(card);
}

export function renderExposureResult(container, result) {
  container.replaceChildren();
  const document = container.ownerDocument;
  const status = result && typeof result.status === "string"
    ? result.status
    : "unavailable";

  if (status !== "results") {
    if (status === "no-match" && result.provider) {
      renderProviderMetadata(container, result);
    }
    const message =
      status === "unavailable" && result && result.reason
        ? result.reason
        : status === "no-match" && result.mode === "email"
          ? "No matching records were found in the provider's available data. This does not establish that the address has never appeared in an incident."
          : STATUS_MESSAGES[status] || STATUS_MESSAGES.unavailable;
    addText(document, container, "p", "exposure-state-message", message);
    if (status === "rate-limited" && Number.isInteger(result.retryAfterSeconds)) {
      addText(
        document,
        container,
        "small",
        "exposure-state-detail",
        "Provider requested a wait of " + result.retryAfterSeconds + " seconds."
      );
    }
    if (status === "no-match" && result.mode === "website") {
      addText(
        document,
        container,
        "small",
        "exposure-state-detail",
        "Coverage is limited to the provider’s available catalog; parent domains, subdomains, related services, and unreported incidents are not inferred."
      );
    }
    return;
  }

  renderProviderMetadata(container, result);
  if (result.mode === "website") {
    addText(
      document,
      container,
      "p",
      "exposure-domain-note",
      "Provider-reported relationships are labeled per incident as website, organization domain, related service, or email-domain association. No matching record is not a safety verdict."
    );
  }

  result.records.forEach((record) =>
    renderRecord(container, record, result.mode)
  );
}
