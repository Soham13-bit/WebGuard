import assert from "node:assert/strict";
import test from "node:test";
import { getUrlCheckResults } from "./url-checks.mjs";
import { renderUrlCheckResults } from "./url-checks-renderer.mjs";

const checkNames = [
  "Transport",
  "Embedded credentials",
  "Internationalized hostname",
  "Host format",
  "Port"
];

function assertOnlyObservation(url, expectedCheck) {
  const result = getUrlCheckResults(url);

  assert.equal(result.error, null);
  assert.equal(result.checks.length, 5);
  assert.deepEqual(
    result.checks.map((check) => check.name),
    checkNames
  );
  assert.deepEqual(
    result.checks.filter((check) => check.flagged).map((check) => check.name),
    expectedCheck ? [expectedCheck] : []
  );
  result.checks.forEach((check) => {
    assert.equal(
      check.status,
      check.name === expectedCheck ? "Observation" : "No issue found",
      check.name
    );
  });
}

test("observes embedded URL credentials", () => {
  assertOnlyObservation(
    "https://user:pass@example.com/",
    "Embedded credentials"
  );
});

test("observes a punycode hostname", () => {
  assertOnlyObservation(
    "https://xn--bcher-kva.example/",
    "Internationalized hostname"
  );
});

test("observes an IPv4 literal host", () => {
  assertOnlyObservation("https://192.0.2.10/", "Host format");
});

test("observes a non-default port", () => {
  assertOnlyObservation("https://example.com:8443/", "Port");
});

test("observes unencrypted HTTP transport", () => {
  assertOnlyObservation("http://example.com/", "Transport");
});

test("reports no issues for a conventional HTTPS URL", () => {
  assertOnlyObservation("https://example.com/", null);
});

test("does not flag the default HTTPS port", () => {
  assertOnlyObservation("https://example.com:443/", null);
});

test("does not flag the default HTTP port", () => {
  assertOnlyObservation("http://example.com:80/", "Transport");
});

test("returns the existing invalid-URL message for malformed input", () => {
  const result = getUrlCheckResults("not a valid URL");

  assert.deepEqual(result, {
    checks: [],
    error: "The active tab URL is not valid."
  });
});

test("renders all five local checks with matching status and observation styling", () => {
  class TestElement {
    constructor(tagName, ownerDocument) {
      this.tagName = tagName;
      this.ownerDocument = ownerDocument;
      this.children = [];
      this.attributes = {};
      this.textContent = "";
      this.className = "";
    }

    append(...elements) {
      this.children.push(...elements);
    }

    replaceChildren(...elements) {
      this.children = elements;
    }

    setAttribute(name, value) {
      this.attributes[name] = value;
    }
  }

  const document = {
    createElement(tagName) {
      return new TestElement(tagName, document);
    }
  };
  const container = new TestElement("div", document);
  const { checks } = getUrlCheckResults("https://user:pass@example.com/");

  renderUrlCheckResults(container, checks);

  assert.equal(container.children.length, 5);
  assert.deepEqual(
    container.children.map((item) => item.children[1].children[0].textContent),
    checkNames
  );
  assert.deepEqual(
    container.children.map((item) => item.children[2].textContent),
    [
      "No issue found",
      "Observation",
      "No issue found",
      "No issue found",
      "No issue found"
    ]
  );
  assert.equal(container.children[1].className, "result-item has-observation");
  assert.equal(container.children[0].className, "result-item");
});
