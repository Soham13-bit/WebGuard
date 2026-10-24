import assert from "node:assert/strict";
import test from "node:test";
import {
  createExposureProviders,
  isValidEmailAddress,
  normalizeWebsiteDomain
} from "./exposure-intelligence.mjs";
import { renderExposureResult } from "./exposure-renderer.mjs";

const now = new Date("2026-10-22T10:00:00.000Z");

function incident(overrides = {}) {
  return {
    title: "Example Incident",
    domain: "example.com",
    relationship: "website",
    breachDate: "2024-02-01",
    addedDate: "2024-03-01T00:00:00Z",
    description: "A reported incident with metadata.",
    dataClasses: ["Email addresses", "Passwords"],
    isVerified: true,
    isFabricated: false,
    attribution: "Provider attribution",
    sourceName: "Approved sample provider",
    sourceUrl: "https://provider.example/terms",
    disclosureUrl: "https://example.com/security/notice",
    ...overrides
  };
}

function approvedProvider(lookup) {
  return {
    id: "approved-test-provider",
    name: "Approved sample provider",
    approvedForUse: true,
    termsUrl: "https://provider.example/terms",
    lookup
  };
}

test("normalizes website URLs safely to a hostname", () => {
  assert.deepEqual(
    normalizeWebsiteDomain("  HTTPS://WWW.Example.com:8443/path?q=1#fragment "),
    { domain: "www.example.com", reason: null }
  );
  assert.deepEqual(normalizeWebsiteDomain("example.com."), {
    domain: "example.com",
    reason: null
  });
});

test("rejects invalid, non-web, credentialed, local, and IP inputs", () => {
  for (const input of [
    "",
    "not a domain",
    "ftp://example.com",
    "https://user:pass@example.com",
    "localhost",
    "host.local",
    "192.0.2.1",
    "example.com/path",
    "example.com:8080"
  ]) {
    assert.equal(normalizeWebsiteDomain(input).domain, null, input);
  }
});

test("validates email format locally, including common aliases", () => {
  assert.equal(isValidEmailAddress("person+tag@example.com"), true);
  assert.equal(isValidEmailAddress("  person@example.com  "), true);
  for (const input of [
    "",
    "not-an-email",
    "person@@example.com",
    ".person@example.com",
    "person..name@example.com",
    "person@example",
    "person@localhost",
    "person@https://example.com"
  ]) {
    assert.equal(isValidEmailAddress(input), false, input);
  }
});

test("no unapproved provider is called and lookup values are not returned", async () => {
  let requests = 0;
  const providers = createExposureProviders({
    websiteProvider: {
      ...approvedProvider(async () => {
        requests += 1;
        return { status: "no-match" };
      }),
      approvedForUse: false
    }
  });

  const invalidEmail = await providers.email.lookup("invalid");
  assert.equal(invalidEmail.status, "invalid-input");
  const emailResult = await providers.email.lookup("private.person@example.com");
  assert.equal(emailResult.status, "unavailable");
  assert.match(emailResult.reason, /not sent anywhere/i);
  const websiteResult = await providers.website.lookup("example.com");
  assert.equal(websiteResult.status, "unavailable");
  assert.match(websiteResult.reason, /not sent anywhere/i);
  assert.equal(requests, 0);
  assert.equal(JSON.stringify(emailResult).includes("private.person"), false);
  assert.equal(JSON.stringify(websiteResult).includes("example.com"), false);
});

test("approved website adapter receives only submitted normalized domain", async () => {
  const calls = [];
  const providers = createExposureProviders({
    websiteProvider: approvedProvider(async (input) => {
      calls.push(input);
      return { status: "results", records: [incident()] };
    }),
    now
  });

  assert.equal(calls.length, 0);
  const result = await providers.website.lookup("HTTPS://EXAMPLE.COM/about");
  assert.deepEqual(calls, ["example.com"]);
  assert.equal(result.status, "results");
  assert.equal(result.mode, "website");
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].confidence, "confirmed");
  assert.equal(result.records[0].exactDomain, "example.com");
  assert.equal(result.records[0].sourceName, "Approved sample provider");
  assert.equal(result.lastSuccessfulAt, now.toISOString());
  assert.equal(JSON.stringify(result).includes("PwnCount"), false);
});

test("unverified and fabricated provider entries are not presented as confirmed", async () => {
  const providers = createExposureProviders({
    websiteProvider: approvedProvider(async () => ({
      status: "results",
      records: [
        incident({ isVerified: false }),
        incident({ title: "Fabricated report", isFabricated: true })
      ]
    }))
  });

  const result = await providers.website.lookup("example.com");
  assert.equal(result.records[0].confidence, "unverified");
  assert.equal(result.records[1].confidence, "unverified");
});

test("related service and email-domain incidents remain explicitly distinct", async () => {
  const providers = createExposureProviders({
    websiteProvider: approvedProvider(async () => ({
      status: "results",
      records: [
        incident({
          title: "Related service incident",
          domain: "related.example",
          relationship: "related-service"
        }),
        incident({
          title: "Email-domain association",
          relationship: "email-domain"
        })
      ]
    }))
  });

  const result = await providers.website.lookup("example.com");
  assert.equal(result.status, "results");
  assert.equal(result.records[0].relationship, "related-service");
  assert.equal(result.records[0].exactDomain, "related.example");
  assert.equal(result.records[1].relationship, "email-domain");
});

test("a purported website incident for another domain is unavailable", async () => {
  const providers = createExposureProviders({
    websiteProvider: approvedProvider(async () => ({
      status: "results",
      records: [incident({ domain: "related.example" })]
    }))
  });

  const result = await providers.website.lookup("example.com");
  assert.equal(result.status, "unavailable");
  assert.match(result.reason, /unrelated/i);
});

test("invalid website input never reaches a provider", async () => {
  let requests = 0;
  const providers = createExposureProviders({
    websiteProvider: approvedProvider(async () => {
      requests += 1;
      return { status: "no-match" };
    })
  });

  const result = await providers.website.lookup("http://127.0.0.1");
  assert.equal(result.status, "invalid-input");
  assert.equal(requests, 0);
});

test("reports no-match without a safety claim", async () => {
  const providers = createExposureProviders({
    websiteProvider: approvedProvider(async () => ({ status: "no-match" }))
  });

  const result = await providers.website.lookup("example.com");
  assert.equal(result.status, "no-match");
  assert.equal(result.records.length, 0);
  assert.doesNotMatch(result.reason || "", /safe/i);
});

test("reports provider rate limits and bounds a retry-after hint", async () => {
  const providers = createExposureProviders({
    websiteProvider: approvedProvider(async () => ({
      status: "rate-limited",
      retryAfterSeconds: 90000
    }))
  });

  const result = await providers.website.lookup("example.com");
  assert.equal(result.status, "rate-limited");
  assert.equal(result.retryAfterSeconds, 86400);
});

test("reports timeout and provider failure without exposing submitted values", async () => {
  const timeoutProviders = createExposureProviders({
    timeoutMs: 5,
    websiteProvider: approvedProvider(
      (_input, { signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => {
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          });
        })
    )
  });
  const timeout = await timeoutProviders.website.lookup("private.example.com");
  assert.equal(timeout.status, "timeout");
  assert.equal(
    JSON.stringify(timeout).includes("private.example.com"),
    false
  );

  const failedProviders = createExposureProviders({
    websiteProvider: approvedProvider(async () => {
      throw new Error("network error");
    })
  });
  assert.equal(
    (await failedProviders.website.lookup("example.com")).status,
    "network-error"
  );
});

test("rejects malformed provider responses instead of reporting no-match", async () => {
  const malformedProvider = createExposureProviders({
    websiteProvider: approvedProvider(async () => ({
      status: "results",
      records: [incident({ isVerified: "true" })]
    }))
  });
  assert.equal(
    (await malformedProvider.website.lookup("example.com")).status,
    "unavailable"
  );
});

test("renders provider data as text and attributes successful and no-match results", () => {
  class TestElement {
    constructor(tagName, ownerDocument) {
      this.tagName = tagName;
      this.ownerDocument = ownerDocument;
      this.children = [];
      this.className = "";
      this.dataset = {};
      this.attributes = {};
      this.value = "";
    }

    set textContent(value) {
      this.value = String(value);
      this.children = [];
    }

    get textContent() {
      return (
        this.value +
        this.children.map((child) => child.textContent || "").join("")
      );
    }

    append(...items) {
      this.children.push(...items);
    }

    replaceChildren(...items) {
      this.children = items;
      this.value = "";
    }

    setAttribute(name, value) {
      this.attributes[name] = value;
    }
  }

  const createdTags = [];
  const document = {
    defaultView: null,
    createElement(tagName) {
      createdTags.push(tagName);
      return new TestElement(tagName, document);
    },
    createTextNode(value) {
      return { textContent: String(value) };
    }
  };
  const container = new TestElement("div", document);

  renderExposureResult(container, {
    status: "results",
    mode: "website",
    provider: {
      name: "Approved sample provider",
      termsUrl: "https://provider.example/terms"
    },
    lastSuccessfulAt: now.toISOString(),
    records: [
      {
        title: "<img src=x onerror=alert(1)>",
        breachDate: "2024-02-01",
        addedDate: null,
        description: "<script>alert(1)</script>",
        dataClasses: ["Email addresses"],
        confidence: "confirmed",
        attribution: "Provider report",
        sourceName: "Approved sample provider",
        sourceUrl: "https://provider.example/terms",
        disclosureUrl: "https://example.com/notice"
      }
    ]
  });

  assert.match(container.textContent, /CONFIRMED BY PROVIDER/);
  assert.match(container.textContent, /Last successful lookup/);
  assert.match(container.textContent, /Provider report/);
  assert.match(container.textContent, /Suggested next steps/);
  assert.equal(createdTags.includes("img"), false);
  assert.equal(createdTags.includes("script"), false);

  renderExposureResult(container, {
    status: "no-match",
    mode: "website",
    provider: {
      name: "Approved sample provider",
      termsUrl: "https://provider.example/terms"
    },
    lastSuccessfulAt: now.toISOString(),
    records: []
  });
  assert.match(container.textContent, /Last successful lookup/);
  assert.match(container.textContent, /does not mean the website is safe/i);
});
