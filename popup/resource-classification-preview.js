import {
  classifyResourceHosts,
  loadHostRules,
  renderResourceClassifications
} from "./resource-classifier.mjs";

const samples = [
  "000491b06a.com",
  "sub.00px.net",
  "example.com",
  "x000491b06a.com",
  "192.0.2.10"
];
const summary = document.getElementById("preview-summary");
const list = document.getElementById("preview-classifications");
const rules = globalThis.chrome?.runtime?.getURL
  ? await loadHostRules(chrome.runtime.getURL("rules/resource-host-rules.json"))
  : { available: false, reason: "extension-api-unavailable" };
const result = classifyResourceHosts(samples, rules);

renderResourceClassifications(list, summary, result, 0, samples.length);
