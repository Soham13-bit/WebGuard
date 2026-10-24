const RULE_FORMAT_VERSION = 1;
const MAX_RULES = 500;
const SOURCE_PATHS = {
  EasyList: "easylist/easylist_adservers.txt",
  EasyPrivacy: "easyprivacy/easyprivacy_trackingservers_general.txt"
};

function checksumPayload(data) {
  return JSON.stringify({
    formatVersion: data.formatVersion,
    generatedAt: data.generatedAt,
    expiresAt: data.expiresAt,
    sourceRevision: data.sourceRevision,
    sources: data.sources,
    rules: data.rules
  });
}

async function sha256(value) {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("SHA-256 is unavailable in this environment.");
  }

  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function isValidDomain(domain) {
  if (
    typeof domain !== "string" ||
    domain.length > 253 ||
    !domain.includes(".") ||
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
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
  );
}

function validateSources(data) {
  if (
    !Array.isArray(data.sources) ||
    data.sources.length !== 2 ||
    !data.sources.every(
      (source) =>
        source &&
        ["EasyList", "EasyPrivacy"].includes(source.name) &&
        source.revision === data.sourceRevision &&
        source.url ===
          "https://raw.githubusercontent.com/easylist/easylist/" +
            data.sourceRevision +
            "/" +
            SOURCE_PATHS[source.name] &&
        typeof source.lastModified === "string" &&
        typeof source.expiresAt === "string" &&
        Number.isFinite(Date.parse(source.lastModified)) &&
        Number.isFinite(Date.parse(source.expiresAt)) &&
        Date.parse(source.lastModified) <= Date.parse(source.expiresAt)
    ) ||
    new Set(data.sources.map((source) => source.name)).size !== 2
  ) {
    return false;
  }

  return true;
}

export async function validateHostRules(data, now = new Date()) {
  if (!data) {
    return { available: false, reason: "missing" };
  }

  if (
    data.formatVersion !== RULE_FORMAT_VERSION ||
    !Number.isFinite(Date.parse(data.generatedAt)) ||
    !Number.isFinite(Date.parse(data.expiresAt)) ||
    !/^[a-f0-9]{40}$/i.test(data.sourceRevision || "") ||
    !validateSources(data) ||
    !Array.isArray(data.rules) ||
    data.rules.length === 0 ||
    data.rules.length > MAX_RULES ||
    !data.rules.every(
      (rule) =>
        rule &&
        isValidDomain(rule.domain) &&
        rule.domain === rule.domain.toLowerCase() &&
        ["EasyList", "EasyPrivacy"].includes(rule.source) &&
        rule.rule === "||" + rule.domain + "^" &&
        rule.revision === data.sourceRevision
    ) ||
    !/^[a-f0-9]{64}$/i.test(data.checksum || "")
  ) {
    return { available: false, reason: "invalid" };
  }

  let expectedChecksum;
  try {
    expectedChecksum = await sha256(checksumPayload(data));
  } catch {
    return { available: false, reason: "integrity-check-unavailable" };
  }

  if (expectedChecksum !== data.checksum.toLowerCase()) {
    return { available: false, reason: "checksum-mismatch" };
  }

  const currentTime = now instanceof Date ? now.getTime() : Number(now);
  const generatedTime = Date.parse(data.generatedAt);
  const expiresTime = Date.parse(data.expiresAt);
  if (
    !Number.isFinite(currentTime) ||
    generatedTime > currentTime + 5 * 60 * 1000 ||
    generatedTime > expiresTime
  ) {
    return { available: false, reason: "invalid" };
  }
  if (
    currentTime > expiresTime ||
    data.sources.some(
      (source) => currentTime > Date.parse(source.expiresAt)
    )
  ) {
    return { available: false, reason: "stale" };
  }

  return { available: true, data };
}

export async function loadHostRules(url, options = {}) {
  if (typeof url !== "string" || !url) {
    return { available: false, reason: "missing" };
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return { available: false, reason: "unavailable" };
  }

  try {
    const response = await fetchImpl(url);
    if (!response || !response.ok) {
      return { available: false, reason: "missing" };
    }

    const data = await response.json();
    return validateHostRules(data, options.now);
  } catch {
    return { available: false, reason: "invalid" };
  }
}

export function normalizeResourceHost(input) {
  if (typeof input !== "string") {
    return { host: null, reason: "invalid-host" };
  }

  const candidate = input.trim().replace(/\.$/, "").toLowerCase();
  if (!candidate || candidate.length > 253) {
    return { host: null, reason: "invalid-host" };
  }

  if (
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(candidate) ||
    /^\[[0-9a-f:.]+\]$/i.test(candidate)
  ) {
    return { host: null, reason: "ip-address" };
  }

  if (!isValidDomain(candidate)) {
    return { host: null, reason: "invalid-host" };
  }

  return { host: candidate, reason: null };
}

export function classifyResourceHosts(hosts, validation) {
  if (!Array.isArray(hosts)) {
    return {
      available: false,
      reason: "invalid-host-list",
      checkedCount: 0,
      classifications: []
    };
  }

  if (!validation || !validation.available) {
    return {
      available: false,
      reason: validation && validation.reason ? validation.reason : "missing",
      checkedCount: 0,
      classifications: hosts.map((host) => ({
        host: typeof host === "string" ? host : "Invalid hostname",
        classification: "unavailable",
        matches: []
      }))
    };
  }

  const classifications = hosts.map((input) => {
    const normalized = normalizeResourceHost(input);
    if (!normalized.host) {
      return {
        host: typeof input === "string" ? input : "Invalid hostname",
        classification: "unknown",
        reason: normalized.reason,
        matches: []
      };
    }

    const matches = validation.data.rules.filter(
      (rule) =>
        normalized.host === rule.domain ||
        normalized.host.endsWith("." + rule.domain)
    );
    const sources = new Set(matches.map((match) => match.source));
    const classification =
      sources.size > 1
        ? "both"
        : sources.has("EasyList")
          ? "advertising"
          : sources.has("EasyPrivacy")
            ? "tracking"
            : "unknown";

    return {
      host: input,
      normalizedHost: normalized.host,
      classification,
      reason: matches.length ? null : "no-supported-rule",
      matches: matches.map(({ source, rule, revision }) => ({
        source,
        rule,
        revision
      }))
    };
  });

  return {
    available: true,
    reason: null,
    checkedCount: classifications.length,
    classifications
  };
}

const labels = {
  advertising: "Advertising-related match",
  tracking: "Tracking-related match",
  both: "Matches in both lists",
  unknown: "Unknown — no supported host rule matched",
  unavailable: "Classification unavailable"
};

export function renderResourceClassifications(
  list,
  summary,
  classificationResult,
  omittedCount,
  totalHostCount
) {
  list.replaceChildren();
  const omitted = Math.max(0, omittedCount);

  if (!classificationResult.available) {
    summary.textContent =
      "Classification unavailable (" +
      classificationResult.reason +
      "). 0 hosts classified; " +
      omitted +
      " observed host(s) omitted by the 12-host display limit.";
  } else {
    summary.textContent =
      classificationResult.checkedCount +
      " host(s) classified from " +
      totalHostCount +
      " distinct observed host(s); " +
      omitted +
      " omitted by the 12-host display limit. Unknown does not mean safe.";
  }

  if (classificationResult.classifications.length === 0) {
    const item = list.ownerDocument.createElement("li");
    item.textContent = classificationResult.available
      ? "No observed hostnames to classify."
      : "No classification results are available.";
    list.append(item);
    return;
  }

  classificationResult.classifications.forEach((result) => {
    const item = list.ownerDocument.createElement("li");
    item.className =
      "host-classification host-classification--" + result.classification;

    const heading = list.ownerDocument.createElement("strong");
    heading.textContent = result.host;
    item.append(heading);

    const status = list.ownerDocument.createElement("p");
    status.textContent = labels[result.classification];
    item.append(status);

    if (result.reason === "ip-address") {
      const note = list.ownerDocument.createElement("small");
      note.textContent = "IP literals are not covered by host-domain rules.";
      item.append(note);
    } else if (result.reason === "invalid-host") {
      const note = list.ownerDocument.createElement("small");
      note.textContent = "This value is not a valid hostname.";
      item.append(note);
    } else if (result.classification === "unknown") {
      const note = list.ownerDocument.createElement("small");
      note.textContent =
        "No supported bundled host-wide rule matched; this is not a safety verdict.";
      item.append(note);
    }

    result.matches.forEach((match) => {
      const evidence = list.ownerDocument.createElement("small");
      evidence.textContent =
        match.source +
        " · " +
        match.rule +
        " · revision " +
        match.revision;
      item.append(evidence);
    });
    list.append(item);
  });
}
