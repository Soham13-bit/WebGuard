import {
  classifyResourceHosts,
  loadHostRules,
  renderResourceClassifications
} from "./resource-classifier.mjs";

const bundleUrl = chrome.runtime.getURL("rules/resource-host-rules.json");
const status = document.getElementById("preview-status");
const casesElement = document.getElementById("preview-cases");
const hosts = ["unmatched.example"];
const now = new Date();
const day = 24 * 60 * 60 * 1000;

function copyRules(data) {
  return JSON.parse(JSON.stringify(data));
}

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

async function refreshChecksum(data) {
  const bytes = new TextEncoder().encode(checksumPayload(data));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  data.checksum = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
  return data;
}

function responseFor(json) {
  return {
    ok: true,
    json: async () => json
  };
}

async function runCase({ name, expectedReason, fetchImpl, validationNow = now }) {
  const validation = await loadHostRules(bundleUrl, {
    fetchImpl,
    now: validationNow
  });
  const result = classifyResourceHosts(hosts, validation);
  const section = document.createElement("section");
  section.className = "panel preview-case";
  const heading = document.createElement("h2");
  heading.textContent = name;
  const summary = document.createElement("p");
  const list = document.createElement("ul");
  list.className = "host-classification-list";
  renderResourceClassifications(list, summary, result, 0, hosts.length);
  const renderedStatus = list.querySelector("li p");
  const passed =
    validation.available === false &&
    validation.reason === expectedReason &&
    result.available === false &&
    result.classifications.every(
      (item) => item.classification === "unavailable"
    ) &&
    /Classification unavailable/.test(summary.textContent) &&
    renderedStatus?.textContent === "Classification unavailable" &&
    !/safe/i.test(renderedStatus.textContent);
  const outcome = document.createElement("p");
  outcome.className = "preview-result";
  outcome.dataset.state = passed ? "pass" : "fail";
  outcome.textContent =
    (passed ? "PASS" : "FAIL") +
    " · expected " +
    expectedReason +
    ", received " +
    (validation.reason || "available");
  section.append(heading, outcome, summary, list);
  casesElement.append(section);
  return passed;
}

async function main() {
  const results = [];
  let totalChecks = 0;
  const bundleResponse = await fetch(bundleUrl);
  if (!bundleResponse.ok) {
    throw new Error("Could not read the packaged rules bundle.");
  }
  const bundledRules = await bundleResponse.json();
  const stale = copyRules(bundledRules);
  const staleGeneratedAt = new Date(now.getTime() - 2 * day).toISOString();
  const staleExpiresAt = new Date(now.getTime() - day).toISOString();
  stale.generatedAt = staleGeneratedAt;
  stale.expiresAt = staleExpiresAt;
  stale.sources.forEach((source) => {
    source.lastModified = staleGeneratedAt;
    source.expiresAt = staleExpiresAt;
  });
  await refreshChecksum(stale);

  const checksumMismatch = copyRules(bundledRules);
  checksumMismatch.checksum =
    (checksumMismatch.checksum[0] === "0" ? "1" : "0") +
    checksumMismatch.checksum.slice(1);
  const malformed = copyRules(bundledRules);
  malformed.rules[0].domain = "bad..host";

  const failureCases = [
    {
      name: "Missing bundle response",
      expectedReason: "missing",
      fetchImpl: async () => ({ ok: false })
    },
    {
      name: "Invalid JSON",
      expectedReason: "invalid",
      fetchImpl: async () => ({
        ok: true,
        json: async () => {
          throw new SyntaxError("Invalid JSON fixture");
        }
      })
    },
    {
      name: "Malformed rule data",
      expectedReason: "invalid",
      fetchImpl: async () => responseFor(malformed)
    },
    {
      name: "Expired ruleset",
      expectedReason: "stale",
      fetchImpl: async () => responseFor(stale)
    },
    {
      name: "Checksum mismatch",
      expectedReason: "checksum-mismatch",
      fetchImpl: async () => responseFor(checksumMismatch)
    }
  ];

  totalChecks = failureCases.length + 1;
  for (const failureCase of failureCases) {
    results.push(await runCase(failureCase));
  }
  const validBundle = await loadHostRules(bundleUrl);
  const validResult = classifyResourceHosts(hosts, validBundle);
  const validSection = document.createElement("section");
  validSection.className = "panel preview-case";
  const validHeading = document.createElement("h2");
  validHeading.textContent = "Valid packaged bundle afterwards";
  const validSummary = document.createElement("p");
  const validList = document.createElement("ul");
  validList.className = "host-classification-list";
  renderResourceClassifications(
    validList,
    validSummary,
    validResult,
    0,
    hosts.length
  );
  const validStatus = validList.querySelector("li p");
  const validNote = validList.querySelector("li small");
  const validPassed =
    validBundle.available &&
    validResult.available &&
    validResult.classifications[0].classification === "unknown" &&
    validStatus?.textContent === "Unknown — no supported host rule matched" &&
    /not a safety verdict/i.test(validNote?.textContent || "");
  const validOutcome = document.createElement("p");
  validOutcome.className = "preview-result";
  validOutcome.dataset.state = validPassed ? "pass" : "fail";
  validOutcome.textContent = validPassed
    ? "PASS · bundle validated; unmatched host remains unknown, not safe"
    : "FAIL · packaged bundle did not validate";
  validSection.append(validHeading, validOutcome, validSummary, validList);
  casesElement.append(validSection);
  results.push(validPassed);

  const passed = results.filter(Boolean).length;
  status.dataset.state =
    results.length === totalChecks && passed === totalChecks ? "pass" : "fail";
  status.textContent =
    passed + " of " + totalChecks + " browser-side checks passed.";
}

main().catch((error) => {
  status.dataset.state = "fail";
  status.textContent = "Preview failed: " + error.message;
});
