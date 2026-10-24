const DEFAULT_TIMEOUT_MS = 12000;
const MAX_PROVIDER_RECORDS = 100;
const WEBSITE_RELATIONSHIPS = Object.freeze([
  "website",
  "organization-domain",
  "related-service",
  "email-domain"
]);
const EMAIL_UNAVAILABLE_REASON =
  "No approved email-breach provider is configured. Your email address was not sent anywhere.";
const WEBSITE_UNAVAILABLE_REASON =
  "No provider with approved terms is configured. Your domain was not sent anywhere.";

function hasValidDomainLabels(hostname) {
  if (
    typeof hostname !== "string" ||
    hostname.length > 253 ||
    !hostname.includes(".") ||
    hostname.startsWith(".") ||
    hostname.endsWith(".") ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) ||
    hostname.startsWith("[")
  ) {
    return false;
  }

  const labels = hostname.split(".");
  return (
    labels.length >= 2 &&
    labels.every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ) &&
    (labels[labels.length - 1].length >= 2 ||
      labels[labels.length - 1].startsWith("xn--"))
  );
}

export function normalizeWebsiteDomain(input) {
  if (typeof input !== "string" || input.trim().length === 0) {
    return { domain: null, reason: "empty" };
  }

  const value = input.trim();
  if (value.length > 2048) {
    return { domain: null, reason: "invalid" };
  }

  let parsed;
  try {
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(value)) {
      parsed = new URL(value);
      if (
        (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
        parsed.username ||
        parsed.password
      ) {
        return { domain: null, reason: "invalid" };
      }
    } else {
      if (/[\s/?#@:\\]/.test(value)) {
        return { domain: null, reason: "invalid" };
      }
      parsed = new URL("https://" + value);
    }
  } catch {
    return { domain: null, reason: "invalid" };
  }

  const domain = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!hasValidDomainLabels(domain)) {
    return { domain: null, reason: "invalid" };
  }

  return { domain, reason: null };
}

export function isValidEmailAddress(input) {
  if (typeof input !== "string") {
    return false;
  }

  const email = input.trim();
  if (!email || email.length > 254 || /[\u0000-\u0020\u007f]/.test(email)) {
    return false;
  }

  const separator = email.lastIndexOf("@");
  if (
    separator < 1 ||
    separator !== email.indexOf("@") ||
    separator > 64
  ) {
    return false;
  }

  const local = email.slice(0, separator);
  const domain = email.slice(separator + 1);
  if (
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    /[/:?#@\\]/.test(domain) ||
    !/^[a-z\d.!#$%&'*+/=?^_`{|}~-]+$/i.test(local)
  ) {
    return false;
  }

  return normalizeWebsiteDomain(domain).domain !== null;
}

function validText(value, maximumLength, { allowEmpty = false } = {}) {
  return (
    typeof value === "string" &&
    value.length <= maximumLength &&
    (allowEmpty || value.trim().length > 0) &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)
  );
}

function validHttpsUrl(value) {
  if (!validText(value, 2048)) {
    return false;
  }

  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.hostname.length > 0 &&
      !parsed.username &&
      !parsed.password
    );
  } catch {
    return false;
  }
}

function unavailable(status, reason, provider = null) {
  return {
    status,
    provider,
    records: [],
    reason,
    lastSuccessfulAt: null
  };
}

function isApprovedProvider(provider) {
  return Boolean(
    provider &&
      typeof provider.id === "string" &&
      provider.id.trim() &&
      typeof provider.name === "string" &&
      provider.name.trim() &&
      provider.approvedForUse === true &&
      validHttpsUrl(provider.termsUrl) &&
      typeof provider.lookup === "function"
  );
}

function normalizeDate(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  if (
    typeof value !== "string" ||
    value.length > 40 ||
    !Number.isFinite(Date.parse(value))
  ) {
    return undefined;
  }
  return value;
}

function normalizeDisclosureUrl(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  return validHttpsUrl(value) ? new URL(value).href : undefined;
}

function normalizeRecord(record, mode, provider, input) {
  if (
    !record ||
    typeof record !== "object" ||
    !validText(record.title, 300) ||
    !Array.isArray(record.dataClasses) ||
    record.dataClasses.length > 100 ||
    !record.dataClasses.every((category) => validText(category, 120)) ||
    typeof record.isVerified !== "boolean" ||
    typeof record.isFabricated !== "boolean"
  ) {
    return null;
  }

  const breachDate = normalizeDate(record.breachDate);
  const addedDate = normalizeDate(record.addedDate);
  const disclosureUrl = normalizeDisclosureUrl(record.disclosureUrl);
  if (
    breachDate === undefined ||
    addedDate === undefined ||
    disclosureUrl === undefined
  ) {
    return null;
  }

  let exactDomain = null;
  let relationship = null;
  if (mode === "website") {
    if (!WEBSITE_RELATIONSHIPS.includes(record.relationship)) {
      return null;
    }
    const normalizedDomain = normalizeWebsiteDomain(record.domain);
    if (!normalizedDomain.domain) {
      return null;
    }
    exactDomain = normalizedDomain.domain;
    relationship = record.relationship;
    if (
      (relationship === "website" ||
        relationship === "organization-domain") &&
      exactDomain !== input
    ) {
      return null;
    }
  }

  const sourceName = validText(record.sourceName, 200)
    ? record.sourceName
    : provider.name;
  const sourceUrl = validHttpsUrl(record.sourceUrl)
    ? new URL(record.sourceUrl).href
    : provider.termsUrl;

  return {
    title: record.title,
    breachDate,
    addedDate,
    description: validText(record.description, 10000, { allowEmpty: true })
      ? record.description
      : "",
    dataClasses: [...record.dataClasses],
    confidence: record.isVerified && !record.isFabricated
      ? "confirmed"
      : "unverified",
    attribution: validText(record.attribution, 500, { allowEmpty: true })
      ? record.attribution
      : sourceName,
    sourceName,
    sourceUrl,
    disclosureUrl,
    exactDomain,
    relationship
  };
}

function retryAfterSeconds(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return null;
  }
  return Math.min(Math.floor(value), 86400);
}

async function invokeProvider(provider, input, mode, options) {
  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? Math.max(1, options.timeoutMs)
    : DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  let timedOut = false;
  let timeoutId;
  const timeoutPromise = new Promise((resolve) => {
    timeoutId = setTimeout(() => {
      timedOut = true;
      controller.abort();
      resolve({ type: "timeout" });
    }, timeoutMs);
  });
  const lookupPromise = Promise.resolve()
    .then(() => provider.lookup(input, { signal: controller.signal }))
    .then(
      (value) => ({ type: "response", value }),
      () => ({ type: "error" })
    );

  const outcome = await Promise.race([lookupPromise, timeoutPromise]);
  clearTimeout(timeoutId);
  if (outcome.type === "timeout") {
    return unavailable(
      "timeout",
      "The provider request timed out. Try again later.",
      { id: provider.id, name: provider.name }
    );
  }
  if (outcome.type === "error") {
    return unavailable(
      "network-error",
      "The provider could not be reached. Check your connection and try again.",
      { id: provider.id, name: provider.name }
    );
  }

  const response = outcome.value;
  const providerIdentity = { id: provider.id, name: provider.name };
  if (!response || typeof response !== "object") {
    return unavailable(
      "unavailable",
      "The provider returned an invalid response.",
      providerIdentity
    );
  }
  if (response.status === "rate-limited") {
    return {
      ...unavailable(
        "rate-limited",
        "The provider is rate limiting requests. Wait before trying again.",
        providerIdentity
      ),
      retryAfterSeconds: retryAfterSeconds(response.retryAfterSeconds)
    };
  }
  if (response.status === "unavailable") {
    return unavailable(
      "unavailable",
      "Provider results are unavailable. Try again later.",
      providerIdentity
    );
  }
  if (response.status === "no-match") {
    if (
      response.records !== undefined &&
      (!Array.isArray(response.records) || response.records.length > 0)
    ) {
      return unavailable(
        "unavailable",
        "The provider returned conflicting no-match data.",
        providerIdentity
      );
    }
    const now = options.now instanceof Date ? options.now : new Date();
    if (!Number.isFinite(now.getTime())) {
      return unavailable(
        "unavailable",
        "The lookup time is unavailable.",
        { id: provider.id, name: provider.name }
      );
    }
    return {
      status: "no-match",
      mode,
      provider: { ...providerIdentity, termsUrl: provider.termsUrl },
      records: [],
      reason: null,
      lastSuccessfulAt: now.toISOString()
    };
  }
  if (
    response.status !== "results" ||
    !Array.isArray(response.records) ||
    response.records.length === 0 ||
    response.records.length > MAX_PROVIDER_RECORDS
  ) {
    return unavailable(
      "unavailable",
      "The provider returned invalid or unsupported incident data.",
      providerIdentity
    );
  }

  const records = response.records.map((record) =>
    normalizeRecord(record, mode, provider, input)
  );
  if (records.some((record) => record === null)) {
    return unavailable(
      "unavailable",
      "The provider returned invalid or unrelated incident data.",
      providerIdentity
    );
  }

  const now = options.now instanceof Date ? options.now : new Date();
  if (!Number.isFinite(now.getTime())) {
    return unavailable(
      "unavailable",
      "The lookup time is unavailable.",
      providerIdentity
    );
  }

  return {
    status: "results",
    mode,
    provider: { ...providerIdentity, termsUrl: provider.termsUrl },
    records,
    reason: null,
    lastSuccessfulAt: now.toISOString()
  };
}

/**
 * Approved provider contract: { id, name, approvedForUse: true, termsUrl,
 * lookup(input, { signal }) }. Website records must classify their
 * relationship as website, organization-domain, related-service, or
 * email-domain; direct website/organization matches must exactly match the
 * submitted hostname. The adapter must be approved for this product, send
 * only submitted input, and return normalized incident metadata. Keep
 * authenticated credentials on a separately deployed backend, never here.
 */
export function createExposureProviders(options = {}) {
  const emailProvider = isApprovedProvider(options.emailProvider)
    ? options.emailProvider
    : null;
  const websiteProvider = isApprovedProvider(options.websiteProvider)
    ? options.websiteProvider
    : null;

  return {
    email: Object.freeze({
      id: emailProvider ? emailProvider.id : "email-provider-unconfigured",
      name: emailProvider ? emailProvider.name : "No approved email provider",
      async lookup(input) {
        if (!isValidEmailAddress(input)) {
          return unavailable(
            "invalid-input",
            "Enter a valid email address."
          );
        }
        if (!emailProvider) {
          return unavailable("unavailable", EMAIL_UNAVAILABLE_REASON);
        }
        return invokeProvider(emailProvider, input.trim(), "email", options);
      }
    }),
    website: Object.freeze({
      id: websiteProvider
        ? websiteProvider.id
        : "website-provider-unconfigured",
      name: websiteProvider
        ? websiteProvider.name
        : "No approved website incident provider",
      async lookup(input) {
        const normalized = normalizeWebsiteDomain(input);
        if (!normalized.domain) {
          return unavailable(
            "invalid-input",
            "Enter a valid public website domain or HTTP(S) URL."
          );
        }
        if (!websiteProvider) {
          return unavailable("unavailable", WEBSITE_UNAVAILABLE_REASON);
        }
        return invokeProvider(
          websiteProvider,
          normalized.domain,
          "website",
          options
        );
      }
    })
  };
}
