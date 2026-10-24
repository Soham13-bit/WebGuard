import { createHash } from "node:crypto";
import { rename, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export const CURATED_HOSTS = Object.freeze({
  EasyList: [
    "000491b06a.com",
    "0017c6c37c.com",
    "0019x.com",
    "00427011ae.com",
    "00609c257b.com",
    "ad.doubleclick.net",
    "fls.doubleclick.net",
    "g.doubleclick.net"
  ],
  EasyPrivacy: [
    "00px.net",
    "18wosx.ru",
    "1bliq.io",
    "1epc8o1tg9zz.com",
    "26sgmin39.de",
    "bidswitch.net",
    "bluekai.com",
    "demdex.net",
    "everesttech.net"
  ]
});

const MAX_RULES_FILE_BYTES = 5 * 1024 * 1024;
const EASYLIST_FEED_URL = "https://easylist.to/easylist/easylist.txt";
const SOURCE_PATHS = Object.freeze({
  EasyList: {
    rules: "easylist/easylist_adservers.txt",
    exceptions: ["easylist/easylist_allowlist.txt"]
  },
  EasyPrivacy: {
    rules: "easyprivacy/easyprivacy_trackingservers_general.txt",
    exceptions: [
      "easyprivacy/easyprivacy_allowlist.txt",
      "easyprivacy/easyprivacy_allowlist_international.txt"
    ]
  }
});

function isValidDomain(domain) {
  return (
    typeof domain === "string" &&
    domain.length <= 253 &&
    domain.includes(".") &&
    !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain) &&
    domain.split(".").every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
    )
  );
}

function overlapsAtLabelBoundary(left, right) {
  return (
    left === right ||
    left.endsWith("." + right) ||
    right.endsWith("." + left)
  );
}

function parseHostWideRule(line) {
  const trimmed = line.trim();
  const match = /^\|\|([a-z0-9.-]+)\^$/i.exec(trimmed);
  if (!match || !isValidDomain(match[1])) {
    return null;
  }

  return { domain: match[1].toLowerCase(), rule: trimmed };
}

function parseExceptionDomain(line) {
  const match = /^@@\|\|([a-z0-9.-]+)\^/i.exec(line.trim());
  if (!match || !isValidDomain(match[1])) {
    return null;
  }

  return match[1].toLowerCase();
}

export function extractCuratedRules({
  sources,
  sourceRevision,
  generatedAt,
  expiresAt,
  lastModified
}) {
  if (!/^[a-f0-9]{40}$/i.test(sourceRevision || "")) {
    throw new Error("The source revision must be a 40-character Git commit.");
  }
  if (
    !Number.isFinite(Date.parse(generatedAt)) ||
    !Number.isFinite(Date.parse(expiresAt)) ||
    !Number.isFinite(Date.parse(lastModified))
  ) {
    throw new Error("Ruleset provenance contains invalid timestamps.");
  }
  if (
    Date.parse(generatedAt) < Date.parse(lastModified) ||
    Date.parse(generatedAt) > Date.parse(expiresAt)
  ) {
    throw new Error("The source timestamps are inconsistent or expired.");
  }
  if (!sources || typeof sources !== "object") {
    throw new Error("The source feeds are missing.");
  }

  const rules = [];
  const sourceMetadata = [];
  for (const name of Object.keys(CURATED_HOSTS)) {
    const input = sources[name];
    const expectedUrl =
      "https://raw.githubusercontent.com/easylist/easylist/" +
      sourceRevision +
      "/" +
      SOURCE_PATHS[name].rules;
    if (
      !input ||
      typeof input.rulesText !== "string" ||
      !Array.isArray(input.exceptionTexts) ||
      input.url !== expectedUrl
    ) {
      throw new Error("Missing or invalid source text for " + name + ".");
    }

    const rulesByDomain = new Map();
    for (const line of input.rulesText.split(/\r?\n/)) {
      const parsed = parseHostWideRule(line);
      if (parsed) {
        rulesByDomain.set(parsed.domain, parsed.rule);
      }
    }

    const exceptions = input.exceptionTexts.flatMap((text) =>
      text
        .split(/\r?\n/)
        .map(parseExceptionDomain)
        .filter(Boolean)
    );

    for (const domain of CURATED_HOSTS[name]) {
      const rule = rulesByDomain.get(domain);
      if (!rule) {
        throw new Error(
          name + " no longer contains the reviewed host-wide rule for " + domain + "."
        );
      }
      if (exceptions.some((exception) => overlapsAtLabelBoundary(domain, exception))) {
        throw new Error(
          name + " contains a matching exception for " + domain + "."
        );
      }

      rules.push({ domain, source: name, rule, revision: sourceRevision });
    }

    sourceMetadata.push({
      name,
      url: input.url,
      revision: sourceRevision,
      lastModified,
      expiresAt
    });
  }

  rules.sort((left, right) =>
    left.domain.localeCompare(right.domain) ||
    left.source.localeCompare(right.source)
  );
  const data = {
    formatVersion: 1,
    generatedAt,
    expiresAt,
    sourceRevision,
    sources: sourceMetadata,
    rules
  };
  data.checksum = createHash("sha256")
    .update(JSON.stringify(data), "utf8")
    .digest("hex");
  return data;
}

function metadataValue(feed, label) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp("^!\\s*" + escaped + ":\\s*(.+?)\\s*$", "im").exec(feed);
  return match ? match[1] : null;
}

export function parseEasyListMetadata(feed, now = new Date()) {
  if (typeof feed !== "string" || feed.length > MAX_RULES_FILE_BYTES) {
    throw new Error("The EasyList metadata feed is missing or too large.");
  }

  const title = metadataValue(feed, "Title");
  const version = metadataValue(feed, "Version");
  const modified = metadataValue(feed, "Last modified");
  const expires = metadataValue(feed, "Expires");
  const commit = metadataValue(feed, "Commit");
  const lastModified = modified ? Date.parse(modified) : NaN;
  const expiresMatch = expires && /^(\d+)\s+days?\b/i.exec(expires);
  const expiresDays = expiresMatch ? Number(expiresMatch[1]) : NaN;

  if (
    title !== "EasyList" ||
    !/^\d{8,14}$/.test(version || "") ||
    !Number.isFinite(lastModified) ||
    !Number.isFinite(expiresDays) ||
    expiresDays < 1 ||
    expiresDays > 30 ||
    !/^[a-f0-9]{40}$/i.test(commit || "")
  ) {
    throw new Error("The EasyList feed metadata is incomplete or invalid.");
  }

  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const expiresAt = lastModified + expiresDays * 24 * 60 * 60 * 1000;
  if (
    !Number.isFinite(nowMs) ||
    lastModified > nowMs + 5 * 60 * 1000 ||
    nowMs > expiresAt
  ) {
    throw new Error("The EasyList feed is stale or has an invalid timestamp.");
  }

  return {
    version,
    lastModified: new Date(lastModified).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    revision: commit.toLowerCase()
  };
}

async function fetchText(url, fetchImpl) {
  const response = await fetchImpl(url);
  if (!response || !response.ok) {
    throw new Error("Could not retrieve a required ruleset source.");
  }

  const text = await response.text();
  if (text.length > MAX_RULES_FILE_BYTES) {
    throw new Error("A ruleset source exceeded the allowed size.");
  }
  return text;
}

async function main() {
  const fetchImpl = globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("Node.js with built-in fetch is required.");
  }

  const feed = await fetchText(EASYLIST_FEED_URL, fetchImpl);
  const metadata = parseEasyListMetadata(feed);
  const base = "https://raw.githubusercontent.com/easylist/easylist/" +
    metadata.revision +
    "/";
  const sources = {};
  for (const [name, paths] of Object.entries(SOURCE_PATHS)) {
    const [rulesText, ...exceptionTexts] = await Promise.all([
      fetchText(base + paths.rules, fetchImpl),
      ...paths.exceptions.map((path) => fetchText(base + path, fetchImpl))
    ]);
    sources[name] = {
      rulesText,
      exceptionTexts,
      url: base + paths.rules
    };
  }

  const output = extractCuratedRules({
    sources,
    sourceRevision: metadata.revision,
    generatedAt: new Date().toISOString(),
    expiresAt: metadata.expiresAt,
    lastModified: metadata.lastModified
  });
  const outputPath = new URL("../rules/resource-host-rules.json", import.meta.url);
  const temporaryPath = new URL("../rules/resource-host-rules.json.tmp", import.meta.url);
  await writeFile(temporaryPath, JSON.stringify(output, null, 2) + "\n", "utf8");
  await rename(temporaryPath, outputPath);
  process.stdout.write("Updated rules/resource-host-rules.json from validated feeds.\n");
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    console.error("Ruleset update failed: " + error.message);
    process.exitCode = 1;
  });
}
