import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  classifyResourceHosts,
  loadHostRules,
  normalizeResourceHost,
  renderResourceClassifications,
  validateHostRules
} from "./resource-classifier.mjs";

const bundledRules = JSON.parse(
  readFileSync(new URL("../rules/resource-host-rules.json", import.meta.url), "utf8")
);
const now = new Date("2026-10-12T12:00:00.000Z");

function refreshChecksum(data) {
  const payload = {
    formatVersion: data.formatVersion,
    generatedAt: data.generatedAt,
    expiresAt: data.expiresAt,
    sourceRevision: data.sourceRevision,
    sources: data.sources,
    rules: data.rules
  };
  data.checksum = createHash("sha256")
    .update(JSON.stringify(payload), "utf8")
    .digest("hex");
  return data;
}

function copyBundledRules() {
  return JSON.parse(JSON.stringify(bundledRules));
}

async function readyRules(data = bundledRules) {
  const result = await validateHostRules(data, now);
  assert.equal(result.available, true, result.reason);
  return result;
}

test("classifies reviewed advertising and tracking matches with evidence", async () => {
  const result = classifyResourceHosts(
    ["000491b06a.com", "00px.net"],
    await readyRules()
  );

  assert.deepEqual(
    result.classifications.map((item) => item.classification),
    ["advertising", "tracking"]
  );
  assert.equal(result.classifications[0].matches[0].source, "EasyList");
  assert.equal(result.classifications[0].matches[0].rule, "||000491b06a.com^");
  assert.equal(
    result.classifications[0].matches[0].revision,
    bundledRules.sourceRevision
  );
  assert.equal(result.classifications[1].matches[0].source, "EasyPrivacy");
});

test("classifies an observed host as both only when both lists have a rule", async () => {
  const data = copyBundledRules();
  data.rules.push({
    domain: "000491b06a.com",
    source: "EasyPrivacy",
    rule: "||000491b06a.com^",
    revision: data.sourceRevision
  });
  refreshChecksum(data);

  const result = classifyResourceHosts(
    ["000491b06a.com"],
    await readyRules(data)
  );

  assert.equal(result.classifications[0].classification, "both");
  assert.deepEqual(
    result.classifications[0].matches.map((match) => match.source).sort(),
    ["EasyList", "EasyPrivacy"]
  );
});

test("classifies newly bundled host-wide source rules", async () => {
  const result = classifyResourceHosts(
    [
      "ad.doubleclick.net",
      "fls.doubleclick.net",
      "sub.bidswitch.net",
      "bluekai.com",
      "demdex.net",
      "everesttech.net"
    ],
    await readyRules()
  );

  assert.deepEqual(
    result.classifications.map((item) => item.classification),
    [
      "advertising",
      "advertising",
      "tracking",
      "tracking",
      "tracking",
      "tracking"
    ]
  );
  assert.deepEqual(
    result.classifications.map((item) => item.matches[0].source),
    [
      "EasyList",
      "EasyList",
      "EasyPrivacy",
      "EasyPrivacy",
      "EasyPrivacy",
      "EasyPrivacy"
    ]
  );
});

test("classifies the Google ads hostname through the supported parent rule", async () => {
  const result = classifyResourceHosts(
    ["googleads.g.doubleclick.net"],
    await readyRules()
  );
  const classification = result.classifications[0];

  assert.equal(classification.classification, "advertising");
  assert.equal(classification.matches[0].source, "EasyList");
  assert.equal(classification.matches[0].rule, "||g.doubleclick.net^");
  assert.equal(classification.matches[0].revision, bundledRules.sourceRevision);
});

test("matches subdomains on label boundaries but not lookalike hostnames", async () => {
  const result = classifyResourceHosts(
    [
      "sub.000491b06a.com",
      "x000491b06a.com",
      "000491b06a.com.attacker.test",
      "not00px.net"
    ],
    await readyRules()
  );

  assert.deepEqual(
    result.classifications.map((item) => item.classification),
    ["advertising", "unknown", "unknown", "unknown"]
  );
});

test("normalizes case, whitespace, and a trailing DNS dot", () => {
  assert.deepEqual(normalizeResourceHost("  Sub.00PX.NET. "), {
    host: "sub.00px.net",
    reason: null
  });
});

test("does not apply host-domain rules to IP addresses or invalid values", async () => {
  const result = classifyResourceHosts(
    ["192.0.2.10", "[2001:db8::1]", "bad..example.com", "https://00px.net"],
    await readyRules()
  );

  assert.deepEqual(
    result.classifications.map((item) => [
      item.classification,
      item.reason
    ]),
    [
      ["unknown", "ip-address"],
      ["unknown", "ip-address"],
      ["unknown", "invalid-host"],
      ["unknown", "invalid-host"]
    ]
  );
});

test("rejects malformed, contextual, wildcard, IP, and exception entries", async () => {
  const data = copyBundledRules();
  data.rules[0].rule = "||000491b06a.com^$script";
  refreshChecksum(data);
  assert.equal((await validateHostRules(data, now)).reason, "invalid");

  data.rules[0].rule = "||000491b06a.com^";
  data.rules[0].domain = "*.000491b06a.com";
  refreshChecksum(data);
  assert.equal((await validateHostRules(data, now)).reason, "invalid");

  data.rules[0].domain = "192.0.2.10";
  data.rules[0].rule = "||192.0.2.10^";
  refreshChecksum(data);
  assert.equal((await validateHostRules(data, now)).reason, "invalid");
});

test("reports explicit states for missing, stale, invalid, and checksum-mismatched data", async () => {
  assert.equal((await validateHostRules(null, now)).reason, "missing");

  const stale = copyBundledRules();
  stale.generatedAt = "2026-10-11T00:00:00.000Z";
  stale.expiresAt = "2026-10-12T05:00:00.000Z";
  stale.sources.forEach((source) => {
    source.lastModified = "2026-10-10T00:00:00.000Z";
    source.expiresAt = stale.expiresAt;
  });
  refreshChecksum(stale);
  assert.equal((await validateHostRules(stale, now)).reason, "stale");

  const invalid = copyBundledRules();
  invalid.rules = [];
  assert.equal((await validateHostRules(invalid, now)).reason, "invalid");

  const mismatch = copyBundledRules();
  mismatch.rules[0].source = "EasyPrivacy";
  assert.equal(
    (await validateHostRules(mismatch, now)).reason,
    "checksum-mismatch"
  );

  const future = copyBundledRules();
  future.generatedAt = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
  refreshChecksum(future);
  assert.equal((await validateHostRules(future, now)).reason, "invalid");
});

test("unavailable rule loading is explicit and does not require external access", async () => {
  const missing = await loadHostRules("extension://local/rules.json", {
    fetchImpl: async () => ({ ok: false })
  });
  assert.deepEqual(missing, { available: false, reason: "missing" });

  const malformed = await loadHostRules("extension://local/rules.json", {
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({ formatVersion: "not rules" })
    })
  });
  assert.equal(malformed.reason, "invalid");
});

test("loader failure states stay unavailable in the UI and do not affect the valid bundle", async () => {
  const url = "extension://local/rules.json";
  const stale = copyBundledRules();
  stale.generatedAt = "2026-10-07T00:00:00.000Z";
  stale.expiresAt = "2026-10-11T00:00:00.000Z";
  stale.sources.forEach((source) => {
    source.lastModified = "2026-10-07T00:00:00.000Z";
    source.expiresAt = stale.expiresAt;
  });
  refreshChecksum(stale);

  const checksumMismatch = copyBundledRules();
  checksumMismatch.rules[0].source = "EasyPrivacy";

  const failureCases = [
    {
      name: "missing data",
      reason: "missing",
      fetchImpl: async () => ({ ok: false })
    },
    {
      name: "invalid JSON",
      reason: "invalid",
      fetchImpl: async () => ({
        ok: true,
        json: async () => {
          throw new SyntaxError("Unexpected token");
        }
      })
    },
    {
      name: "malformed rule data",
      reason: "invalid",
      fetchImpl: async () => ({
        ok: true,
        json: async () => ({ ...copyBundledRules(), rules: [{ domain: "bad..host" }] })
      })
    },
    {
      name: "expired rules",
      reason: "stale",
      fetchImpl: async () => ({
        ok: true,
        json: async () => stale
      })
    },
    {
      name: "checksum mismatch",
      reason: "checksum-mismatch",
      fetchImpl: async () => ({
        ok: true,
        json: async () => checksumMismatch
      })
    }
  ];

  class TestElement {
    constructor(ownerDocument) {
      this.ownerDocument = ownerDocument;
      this.children = [];
      this.textContent = "";
      this.className = "";
    }

    append(...children) {
      this.children.push(...children);
    }

    replaceChildren(...children) {
      this.children = children;
    }
  }

  const document = {
    createElement() {
      return new TestElement(document);
    }
  };

  for (const failureCase of failureCases) {
    const unavailable = await loadHostRules(url, {
      fetchImpl: failureCase.fetchImpl,
      now
    });
    assert.equal(unavailable.available, false, failureCase.name);
    assert.equal(unavailable.reason, failureCase.reason, failureCase.name);

    const result = classifyResourceHosts(["unmatched.example"], unavailable);
    assert.equal(result.available, false, failureCase.name);
    assert.equal(
      result.classifications[0].classification,
      "unavailable",
      failureCase.name
    );

    const list = new TestElement(document);
    const summary = new TestElement(document);
    renderResourceClassifications(list, summary, result, 0, 1);
    assert.match(summary.textContent, /Classification unavailable/);
    assert.equal(list.children[0].children[1].textContent, "Classification unavailable");
    assert.doesNotMatch(list.children[0].children[1].textContent, /safe/i);
  }

  const valid = await loadHostRules(url, {
    fetchImpl: async () => ({
      ok: true,
      json: async () => bundledRules
    }),
    now
  });
  assert.equal(valid.available, true, valid.reason);
  assert.equal(valid.data, bundledRules);

  const result = classifyResourceHosts(["unmatched.example"], valid);
  assert.equal(result.available, true);
  assert.equal(result.classifications[0].classification, "unknown");
  const list = new TestElement(document);
  const summary = new TestElement(document);
  renderResourceClassifications(list, summary, result, 0, 1);
  assert.equal(list.children[0].children[1].textContent, "Unknown — no supported host rule matched");
  assert.match(list.children[0].children[2].textContent, /not a safety verdict/i);
});

test("renders host labels, rule evidence, unknown, unavailable, and omitted counts safely", async () => {
  class TestElement {
    constructor(ownerDocument) {
      this.ownerDocument = ownerDocument;
      this.children = [];
      this.textContent = "";
      this.className = "";
    }

    append(...children) {
      this.children.push(...children);
    }

    replaceChildren(...children) {
      this.children = children;
    }
  }

  const document = {
    createElement() {
      return new TestElement(document);
    }
  };
  const list = new TestElement(document);
  const summary = new TestElement(document);
  const classified = classifyResourceHosts(
    ["000491b06a.com", "example.com"],
    await readyRules()
  );
  renderResourceClassifications(list, summary, classified, 3, 5);

  assert.match(summary.textContent, /2 host\(s\) classified/);
  assert.match(summary.textContent, /3 omitted/);
  assert.match(list.children[0].children[2].textContent, /EasyList/);
  assert.match(list.children[0].children[2].textContent, /\|\|000491b06a\.com\^/);
  assert.match(list.children[1].children[2].textContent, /not a safety verdict/);

  renderResourceClassifications(
    list,
    summary,
    { available: false, reason: "stale", classifications: [] },
    5,
    5
  );
  assert.match(summary.textContent, /Classification unavailable \(stale\)/);
  assert.match(summary.textContent, /0 hosts classified; 5 observed host/);
});
