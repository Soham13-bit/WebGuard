export const REPUTATION_STATUSES = Object.freeze([
  "not-checked",
  "malicious",
  "no-match",
  "unavailable"
]);

const DATASET_FORMAT_VERSION = 1;
const MAX_INDICATORS = 10000;
const CATEGORY_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const explanations = Object.freeze({
  malicious: "A supplied reputation indicator explicitly matched this URL.",
  "no-match":
    "No supplied reputation indicator matched. This does not guarantee that the URL is safe.",
  unavailable: "Reputation information is unavailable.",
  "not-checked": "Reputation has not been checked."
});

function isValidText(value, maximumLength = 100) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maximumLength &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function isValidCategory(category) {
  return (
    typeof category === "string" &&
    category.length <= 60 &&
    CATEGORY_PATTERN.test(category)
  );
}

function normalizeIdentity(source, supportedThreatCategories) {
  if (
    !source ||
    !isValidText(source.id) ||
    !isValidText(source.name) ||
    !Array.isArray(supportedThreatCategories) ||
    !supportedThreatCategories.every(isValidCategory) ||
    new Set(supportedThreatCategories).size !==
      supportedThreatCategories.length
  ) {
    return null;
  }

  return {
    id: source.id,
    name: source.name,
    supportedThreatCategories: [...supportedThreatCategories]
  };
}

function makeResult(status, provider = null, threatCategories = []) {
  return {
    status,
    provider,
    threatCategories,
    explanation: explanations[status]
  };
}

export function createNotCheckedReputationResult(provider = null) {
  const identity = provider
    ? normalizeIdentity(provider, provider.supportedThreatCategories)
    : null;
  return makeResult("not-checked", identity);
}

/**
 * Removes credentials, query, and fragment data and canonicalizes HTTP(S)
 * URLs. The returned URL is intended for an explicitly local lookup only.
 */
export function normalizeReputationUrl(input) {
  if (typeof input !== "string" || !input.trim()) {
    return null;
  }

  try {
    const url = new URL(input);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }

    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function isValidDomain(domain) {
  if (
    typeof domain !== "string" ||
    domain.length > 253 ||
    domain !== domain.toLowerCase() ||
    domain.startsWith(".") ||
    domain.endsWith(".") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain)
  ) {
    return false;
  }

  return domain.split(".").every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );
}

function validateDataset(dataset) {
  if (
    !dataset ||
    typeof dataset !== "object" ||
    dataset.formatVersion !== DATASET_FORMAT_VERSION ||
    !Array.isArray(dataset.supportedThreatCategories) ||
    !Array.isArray(dataset.indicators) ||
    dataset.indicators.length > MAX_INDICATORS
  ) {
    return null;
  }

  const provider = normalizeIdentity(
    dataset.provider,
    dataset.supportedThreatCategories
  );
  if (!provider) {
    return null;
  }

  const valid = dataset.indicators.every((indicator) => {
    if (
      !indicator ||
      typeof indicator !== "object" ||
      !Array.isArray(indicator.threatCategories) ||
      indicator.threatCategories.length === 0 ||
      !indicator.threatCategories.every(
        (category) =>
          isValidCategory(category) &&
          provider.supportedThreatCategories.includes(category)
      ) ||
      new Set(indicator.threatCategories).size !==
        indicator.threatCategories.length
    ) {
      return false;
    }

    if (indicator.type === "domain") {
      return (
        isValidDomain(indicator.domain) &&
        typeof indicator.includeSubdomains === "boolean" &&
        !Object.hasOwn(indicator, "url")
      );
    }

    if (indicator.type === "url") {
      const normalized = normalizeReputationUrl(indicator.url);
      if (
        !normalized ||
        normalized !== indicator.url ||
        !indicator.url.startsWith("http")
      ) {
        return false;
      }

      try {
        const parsed = new URL(indicator.url);
        return (
          !parsed.username &&
          !parsed.password &&
          !parsed.search &&
          !parsed.hash &&
          !Object.hasOwn(indicator, "domain") &&
          !Object.hasOwn(indicator, "includeSubdomains")
        );
      } catch {
        return false;
      }
    }

    return false;
  });

  return valid ? { provider } : null;
}

function matchIndicator(url, indicator) {
  if (indicator.type === "url") {
    return url.href === indicator.url;
  }

  const hostMatches =
    url.hostname === indicator.domain ||
    (indicator.includeSubdomains &&
      url.hostname.endsWith("." + indicator.domain));
  return hostMatches;
}

/**
 * Match a canonical URL against a caller-supplied in-memory dataset.
 * Domain indicators match the exact hostname, optionally including DNS-label
 * subdomains, across paths and ports. URL indicators match exact canonical
 * scheme, hostname, port, and pathname; query and fragment are ignored.
 */
export function lookupLocalReputation(normalizedUrl, dataset) {
  const validation = validateDataset(dataset);
  if (!validation || typeof normalizedUrl !== "string") {
    return makeResult("unavailable", validation?.provider || null);
  }

  const canonicalUrl = normalizeReputationUrl(normalizedUrl);
  if (!canonicalUrl || canonicalUrl !== normalizedUrl) {
    return makeResult("unavailable", validation.provider);
  }

  const url = new URL(canonicalUrl);
  const matchingIndicator = dataset.indicators.find((indicator) =>
    matchIndicator(url, indicator)
  );
  if (!matchingIndicator) {
    return makeResult("no-match", validation.provider);
  }

  return makeResult(
    "malicious",
    validation.provider,
    [...matchingIndicator.threatCategories]
  );
}

/**
 * Provider adapters expose id, name, supportedThreatCategories, and
 * lookup(url), resolving to { status, threatCategories }. This normalizer is
 * pure; it does not call the adapter or perform network access.
 */
export function normalizeProviderResult(provider, response) {
  const identity = provider
    ? normalizeIdentity(provider, provider.supportedThreatCategories)
    : null;
  if (
    !identity ||
    typeof provider.lookup !== "function" ||
    !response ||
    typeof response !== "object"
  ) {
    return makeResult("unavailable", identity);
  }

  if (
    response.status !== "malicious" &&
    response.status !== "no-match" &&
    response.status !== "unavailable"
  ) {
    return makeResult("unavailable", identity);
  }

  if (
    !Array.isArray(response.threatCategories) ||
    !response.threatCategories.every(
      (category) =>
        isValidCategory(category) &&
        identity.supportedThreatCategories.includes(category)
    ) ||
    new Set(response.threatCategories).size !== response.threatCategories.length
  ) {
    return makeResult("unavailable", identity);
  }

  if (
    (response.status === "malicious" &&
      response.threatCategories.length === 0) ||
    (response.status !== "malicious" &&
      response.threatCategories.length > 0)
  ) {
    return makeResult("unavailable", identity);
  }

  return makeResult(response.status, identity, [
    ...response.threatCategories
  ]);
}
