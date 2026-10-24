import assert from "node:assert/strict";
import test from "node:test";
import { calculateUrlRisk } from "./risk-engine.mjs";
import { getUrlCheckResults } from "./url-checks.mjs";
import { renderUrlRiskResults } from "./url-checks-renderer.mjs";

function checksFor(url) {
  return getUrlCheckResults(url);
}

test("scores a conventional HTTPS URL as low with no findings", () => {
  const result = calculateUrlRisk(checksFor("https://example.com/"));

  assert.equal(result.available, true);
  assert.equal(result.score, 0);
  assert.equal(result.severity, "Low");
  assert.deepEqual(result.findings, []);
});

test("keeps HTTP and an IP hostname as contextual observations, not findings", () => {
  const http = calculateUrlRisk(checksFor("http://example.com/"));
  const ip = calculateUrlRisk(checksFor("https://192.0.2.10/"));

  assert.equal(http.score, 0);
  assert.equal(ip.score, 0);
  assert.deepEqual(http.findings, []);
  assert.deepEqual(ip.findings, []);
});

test("scores a non-default port in the low band", () => {
  const result = calculateUrlRisk(checksFor("https://example.com:8443/"));

  assert.equal(result.score, 17);
  assert.equal(result.severity, "Low");
  assert.deepEqual(result.findings.map(({ name }) => name), ["Port"]);
  assert.equal(result.findings[0].evidence.includes("8443"), true);
  assert.equal(result.findings[0].severity, "Low");
});

test("scores individual medium indicators in the medium band", () => {
  const credentials = calculateUrlRisk(
    checksFor("https://user:pass@example.com/")
  );
  const punycode = calculateUrlRisk(
    checksFor("https://xn--bcher-kva.example/")
  );

  assert.equal(credentials.score, 58);
  assert.equal(credentials.severity, "Medium");
  assert.equal(punycode.score, 50);
  assert.equal(punycode.severity, "Medium");
  assert.equal(credentials.findings[0].reason.length > 0, true);
  assert.equal(punycode.findings[0].evidence.length > 0, true);
});

test("caps overlapping address-presentation indicators before normalization", () => {
  const result = calculateUrlRisk(
    checksFor("https://user:pass@xn--bcher-kva.example/")
  );

  assert.equal(result.points, 50);
  assert.equal(result.score, 83);
  assert.equal(result.severity, "High");
  assert.deepEqual(
    result.findings.map(({ name }) => name),
    ["Embedded credentials", "Internationalized hostname"]
  );
});

test("scores multiple indicators in the high band without exceeding 100", () => {
  const result = calculateUrlRisk(
    checksFor("https://user:pass@xn--bcher-kva.example:8443/")
  );

  assert.equal(result.points, 60);
  assert.equal(result.score, 100);
  assert.equal(result.severity, "High");
  assert.equal(result.findings.length, 3);
});

test("returns unavailable for malformed URLs", () => {
  const result = calculateUrlRisk(checksFor("not a valid URL"));

  assert.equal(result.available, false);
  assert.equal(result.score, null);
  assert.deepEqual(result.findings, []);
});

test("distinguishes missing checks from clean observations", () => {
  const complete = checksFor("https://example.com/");
  const result = calculateUrlRisk({
    checks: complete.checks.filter((check) => check.name !== "Port"),
    error: null
  });

  assert.equal(result.available, false);
  assert.equal(result.score, null);
  assert.deepEqual(result.missingChecks, ["Port"]);
});

test("does not double-count duplicate indicators", () => {
  const complete = checksFor("https://user:pass@example.com/");
  const credentials = complete.checks.find(
    (check) => check.name === "Embedded credentials"
  );
  const result = calculateUrlRisk({
    ...complete,
    checks: [...complete.checks, { ...credentials }]
  });

  assert.equal(result.score, 58);
  assert.equal(
    result.findings.filter(
      (finding) => finding.name === "Embedded credentials"
    ).length,
    1
  );
});

test("returns unavailable for conflicting duplicate indicators", () => {
  const complete = checksFor("https://example.com/");
  const transport = complete.checks.find(
    (check) => check.name === "Transport"
  );
  const result = calculateUrlRisk({
    ...complete,
    checks: [
      ...complete.checks,
      { ...transport, flagged: true, status: "Observation" }
    ]
  });

  assert.equal(result.available, false);
  assert.equal(result.score, null);
  assert.match(result.reason, /Conflicting duplicate/);
});

test("rejects malformed check output instead of treating it as clean", () => {
  const result = calculateUrlRisk({
    checks: [{ name: "Transport", flagged: false, detail: "" }],
    error: null
  });

  assert.equal(result.available, false);
  assert.equal(result.score, null);
  assert.match(result.reason, /invalid/i);
});

test("keeps score boundaries normalized from 0 through 100", () => {
  for (const url of [
    "https://example.com/",
    "https://example.com:8443/",
    "https://user:pass@example.com/",
    "https://user:pass@xn--bcher-kva.example:8443/"
  ]) {
    const result = calculateUrlRisk(checksFor(url));
    assert.equal(result.score >= 0 && result.score <= 100, true, url);
  }
});

test("renders score, evidence, severity, and reason for contributing findings", () => {
  class TestElement {
    constructor(tagName, ownerDocument) {
      this.tagName = tagName;
      this.ownerDocument = ownerDocument;
      this.children = [];
      this.textContent = "";
      this.className = "";
    }

    append(...elements) {
      this.children.push(...elements);
    }

    replaceChildren(...elements) {
      this.children = elements;
    }
  }

  const document = {
    createElement(tagName) {
      return new TestElement(tagName, document);
    }
  };
  const container = new TestElement("div", document);
  const risk = calculateUrlRisk(
    checksFor("https://user:pass@example.com/")
  );

  renderUrlRiskResults(container, risk);

  assert.match(container.children[0].textContent, /58\/100 · Medium/);
  const finding = container.children[2].children[0];
  const content = finding.children[0];
  assert.equal(content.children[0].textContent, "Embedded credentials");
  assert.match(content.children[1].textContent, /Evidence:/);
  assert.match(content.children[2].textContent, /Medium · 35 base points/);
  assert.match(content.children[2].textContent, /Credentials embedded/);
});
