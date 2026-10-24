import assert from "node:assert/strict";
import test from "node:test";
import { getUrlCheckResults } from "./url-checks.mjs";
import {
  createNotCheckedReputationResult,
  lookupLocalReputation,
  normalizeProviderResult,
  normalizeReputationUrl
} from "./url-reputation.mjs";

const provider = Object.freeze({
  id: "synthetic-fixture",
  name: "Synthetic test dataset",
  supportedThreatCategories: ["malware", "phishing"],
  lookup() {
    throw new Error("This provider adapter must never be invoked by tests.");
  }
});

function dataset(indicators) {
  return {
    formatVersion: 1,
    provider: {
      id: "synthetic-fixture",
      name: "Synthetic test dataset"
    },
    supportedThreatCategories: ["malware", "phishing"],
    indicators
  };
}

function domainIndicator(domain, includeSubdomains, threatCategories = ["phishing"]) {
  return {
    type: "domain",
    domain,
    includeSubdomains,
    threatCategories
  };
}

function urlIndicator(url, threatCategories = ["malware"]) {
  return { type: "url", url, threatCategories };
}

test("represents reputation as not checked before any lookup", () => {
  assert.deepEqual(createNotCheckedReputationResult(), {
    status: "not-checked",
    provider: null,
    threatCategories: [],
    explanation: "Reputation has not been checked."
  });

  const result = createNotCheckedReputationResult(provider);
  assert.equal(result.status, "not-checked");
  assert.deepEqual(result.provider, {
    id: "synthetic-fixture",
    name: "Synthetic test dataset",
    supportedThreatCategories: ["malware", "phishing"]
  });
});

test("returns malicious only for an explicit valid indicator match", () => {
  const result = lookupLocalReputation(
    normalizeReputationUrl("https://sub.bad.example/"),
    dataset([domainIndicator("bad.example", true, ["phishing"])])
  );

  assert.equal(result.status, "malicious");
  assert.deepEqual(result.threatCategories, ["phishing"]);
  assert.equal(result.provider.id, "synthetic-fixture");
  assert.match(result.explanation, /explicitly matched/i);
  assert.equal(JSON.stringify(result).includes("sub.bad.example"), false);
});

test("returns no-match for a valid dataset without a matching indicator", () => {
  const result = lookupLocalReputation(
    normalizeReputationUrl("https://example.test/"),
    dataset([domainIndicator("bad.example", false)])
  );

  assert.equal(result.status, "no-match");
  assert.deepEqual(result.threatCategories, []);
  assert.match(result.explanation, /does not guarantee/i);
  assert.doesNotMatch(result.explanation, /(?:^|\.)\s*The URL is safe/i);
});

test("an empty but valid indicator dataset reports no-match", () => {
  assert.equal(
    lookupLocalReputation(
      normalizeReputationUrl("https://example.test/"),
      dataset([])
    ).status,
    "no-match"
  );
});

test("returns unavailable for missing or malformed datasets and URLs", () => {
  const valid = dataset([domainIndicator("bad.example", false)]);
  const malformedDatasets = [
    null,
    {},
    { ...valid, formatVersion: 2 },
    { ...valid, provider: null },
    { ...valid, supportedThreatCategories: ["malware", "malware"] },
    { ...valid, indicators: "not-an-array" },
    { ...valid, indicators: [domainIndicator("bad..example", false)] },
    {
      ...valid,
      indicators: [domainIndicator("bad.example", "yes")]
    },
    {
      ...valid,
      indicators: [domainIndicator("bad.example", false, ["unknown-threat"])]
    },
    {
      ...valid,
      indicators: [domainIndicator("bad.example", false, [])]
    },
    {
      ...valid,
      indicators: [urlIndicator("https://bad.example/path?token=fixture")]
    },
    {
      ...valid,
      indicators: [urlIndicator("https://user:pass@bad.example/path")]
    },
    {
      ...valid,
      indicators: [urlIndicator("https://bad.example/path#fragment")]
    }
  ];

  malformedDatasets.forEach((candidate) => {
    assert.equal(
      lookupLocalReputation(
        normalizeReputationUrl("https://bad.example/"),
        candidate
      ).status,
      "unavailable"
    );
  });

  for (const input of [
    null,
    "not a URL",
    "ftp://bad.example/",
    "https://bad.example/?query=1"
  ]) {
    assert.equal(
      lookupLocalReputation(input, valid).status,
      "unavailable"
    );
  }
});

test("normalizes URL spelling and removes credentials, query, and fragment", () => {
  assert.equal(
    normalizeReputationUrl(
      " HTTPS://User:Password@EXAMPLE.COM:443/a/../b?secret=value#fragment "
    ),
    "https://example.com/b"
  );
  assert.equal(normalizeReputationUrl("ftp://example.com/"), null);
  assert.equal(normalizeReputationUrl("not a URL"), null);
  assert.equal(normalizeReputationUrl(""), null);
});

test("domain indicators use exact host boundaries and explicit subdomain scope", () => {
  const exactOnly = dataset([domainIndicator("bad.example", false)]);
  const includeSubdomains = dataset([domainIndicator("bad.example", true)]);
  const lookup = (host, rules) =>
    lookupLocalReputation(
      normalizeReputationUrl("https://" + host + "/"),
      rules
    ).status;

  assert.equal(lookup("bad.example", exactOnly), "malicious");
  assert.equal(lookup("sub.bad.example", exactOnly), "no-match");
  assert.equal(lookup("sub.bad.example", includeSubdomains), "malicious");
  assert.equal(
    lookupLocalReputation(
      normalizeReputationUrl("http://bad.example:8080/a/path"),
      exactOnly
    ).status,
    "malicious"
  );
  assert.equal(lookup("notbad.example", includeSubdomains), "no-match");
  assert.equal(lookup("bad.example.attacker.test", includeSubdomains), "no-match");
});

test("URL indicators match exact canonical path and port, not path lookalikes", () => {
  const rules = dataset([
    urlIndicator("https://bad.example:8443/account/reset")
  ]);
  const lookup = (url) =>
    lookupLocalReputation(normalizeReputationUrl(url), rules).status;

  assert.equal(
    lookup("https://bad.example:8443/account/reset?tracking=ignored#section"),
    "malicious"
  );
  assert.equal(lookup("https://bad.example/account/reset"), "no-match");
  assert.equal(lookup("https://bad.example:8443/account/reset/extra"), "no-match");
  assert.equal(lookup("https://bad.example:8443/account/reset-evil"), "no-match");
});

test("URL normalization makes default ports and ignored URL components deterministic", () => {
  const rules = dataset([urlIndicator("https://bad.example/path")]);
  const result = lookupLocalReputation(
    normalizeReputationUrl(
      "https://user:password@BAD.EXAMPLE:443/path?private=1#private"
    ),
    rules
  );

  assert.equal(result.status, "malicious");
  assert.deepEqual(result.threatCategories, ["malware"]);
  assert.equal(JSON.stringify(result).includes("private"), false);
  assert.equal(JSON.stringify(result).includes("password"), false);
});

test("malformed provider results normalize to unavailable", () => {
  const responses = [
    null,
    "no-match",
    {},
    { status: "not-checked", threatCategories: [] },
    { status: "malicious", threatCategories: [] },
    { status: "no-match", threatCategories: ["malware"] },
    { status: "unavailable", threatCategories: ["phishing"] },
    { status: "malicious", threatCategories: ["unknown-threat"] },
    { status: "malicious", threatCategories: ["phishing", "phishing"] }
  ];

  responses.forEach((response) => {
    assert.equal(normalizeProviderResult(provider, response).status, "unavailable");
  });
});

test("a clean local URL result cannot replace an independent malicious reputation result", () => {
  const localChecks = getUrlCheckResults("https://example.com/");
  assert.equal(localChecks.error, null);
  assert.equal(localChecks.checks.some((check) => check.flagged), false);

  const reputation = lookupLocalReputation(
    normalizeReputationUrl("https://example.com/"),
    dataset([domainIndicator("example.com", false, ["malware"])])
  );
  assert.equal(reputation.status, "malicious");
});
