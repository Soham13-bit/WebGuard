import { getUrlCheckResults } from "./url-checks.mjs";
import { renderUrlCheckResults } from "./url-checks-renderer.mjs";

const cases = [
  {
    title: "Embedded credentials",
    url: "https://user:pass@example.com/",
    expected: "Embedded credentials"
  },
  {
    title: "Punycode hostname",
    url: "https://xn--bcher-kva.example/",
    expected: "Internationalized hostname"
  },
  {
    title: "IP-literal host",
    url: "https://192.0.2.10/",
    expected: "Host format"
  },
  {
    title: "Non-default HTTPS port",
    url: "https://example.com:8443/",
    expected: "Port"
  },
  {
    title: "Plain HTTP",
    url: "http://example.com/",
    expected: "Transport"
  }
];

const preview = document.getElementById("preview-cases");
cases.forEach(({ title, url, expected }) => {
  const section = document.createElement("section");
  section.className = "panel preview-case";

  const heading = document.createElement("h2");
  heading.textContent = title;
  const sample = document.createElement("code");
  sample.textContent = url;
  const expectedResult = document.createElement("p");
  expectedResult.className = "preview-notice";
  const results = document.createElement("div");
  results.className = "result-list";

  const result = getUrlCheckResults(url);
  const passed =
    !result.error &&
    result.checks.length === 5 &&
    result.checks.filter((check) => check.flagged).length === 1 &&
    result.checks.some(
      (check) => check.name === expected && check.status === "Observation"
    ) &&
    result.checks.every(
      (check) =>
        check.name === expected
          ? check.status === "Observation"
          : check.status === "No issue found"
    );

  if (!result.error) {
    renderUrlCheckResults(results, result.checks);
  }
  expectedResult.textContent = result.error
    ? "FAIL — " + result.error
    : (passed ? "PASS" : "FAIL") + " — expected observation: " + expected;
  expectedResult.dataset.result = passed ? "pass" : "fail";

  section.append(heading, sample, expectedResult, results);
  preview.append(section);
});
