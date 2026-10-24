"use strict";

import { getUrlCheckResults } from "./url-checks.mjs";
import {
  appendUrlCheckResult,
  renderUrlCheckResults,
  renderUrlRiskResults
} from "./url-checks-renderer.mjs";
import { calculateUrlRisk } from "./risk-engine.mjs";
import { renderNavigationHistory } from "./navigation-renderer.mjs";
import {
  classifyResourceHosts,
  loadHostRules,
  renderResourceClassifications
} from "./resource-classifier.mjs";
import { createExposureProviders } from "./exposure-intelligence.mjs";
import { renderExposureResult } from "./exposure-renderer.mjs";

const hostnameElement = document.getElementById("site-title");
const urlElement = document.getElementById("site-url");
const httpsBadge = document.getElementById("https-badge");
const httpsStatusElement = document.getElementById("https-status");
const navigationItems = Array.from(document.querySelectorAll(".nav-item"));
const views = Array.from(document.querySelectorAll(".view"));
const dashboardPanel = document.getElementById("dashboard-panel");
const urlCheckCount = document.getElementById("url-check-count");
const urlCheckState = document.getElementById("url-check-state");
const engineStatus = document.getElementById("engine-status");
const runPageChecksButton = document.getElementById("run-page-checks");
const pageCheckStatus = document.getElementById("page-check-status");
const urlResults = document.getElementById("url-results");
const overviewRiskResults = document.getElementById("overview-risk-results");
const urlRiskResults = document.getElementById("url-risk-results");
const navigationOverviewEvents = document.getElementById(
  "navigation-overview-events"
);
const navigationAnalysisEvents = document.getElementById(
  "navigation-analysis-events"
);
const reportResults = document.getElementById("report-results");
const hostClassificationList = document.getElementById(
  "host-classification-list"
);
const hostClassificationSummary = document.getElementById(
  "host-classification-summary"
);
const exposureResults = document.getElementById("exposure-results");
const emailExposureForm = document.getElementById("email-exposure-form");
const websiteExposureForm = document.getElementById("website-exposure-form");
const websiteExposureSubmit = document.getElementById(
  "website-exposure-submit"
);
const exposureModeTabs = Array.from(
  document.querySelectorAll("[data-exposure-mode]")
);
const exposureModePanels = Array.from(
  document.querySelectorAll(".exposure-mode-panel")
);
const exposureProviders = createExposureProviders();
const hostRulesPromise =
  globalThis.chrome &&
  chrome.runtime &&
  typeof chrome.runtime.getURL === "function"
    ? loadHostRules(chrome.runtime.getURL("rules/resource-host-rules.json"))
    : Promise.resolve({ available: false, reason: "unavailable" });

if (!runPageChecksButton || !pageCheckStatus) {
  console.error("[WebGuard] Page-signal controls are missing from popup.html.", {
    buttonFound: Boolean(runPageChecksButton),
    statusFound: Boolean(pageCheckStatus)
  });
} else {
  console.info("[WebGuard] Page-signal controls found; click handler will be registered.");
}

let activeTabId = null;
let currentUrlChecks = [];
let currentUrlRisk = calculateUrlRisk(null);
let currentPageSignals = null;

function updateUrlCheckCount(count, label) {
  const countValue = document.createTextNode(String(count) + " ");
  const unitLabel = document.createElement("span");
  unitLabel.textContent = label;
  urlCheckCount.replaceChildren(countValue, unitLabel);
}

function showUnavailable(message, diagnostic) {
  console.warn("[WebGuard] Active tab URL unavailable: " + diagnostic);
  hostnameElement.textContent = "Unavailable";
  hostnameElement.title = "Active tab details unavailable";
  urlElement.textContent = message;
  urlElement.title = message;
  httpsStatusElement.textContent = "Unavailable";
  httpsBadge.dataset.state = "unavailable";
  updateUrlCheckCount("—", "checks");
  urlCheckState.textContent = "UNAVAILABLE";
  engineStatus.textContent = "Tab unavailable";
  currentUrlChecks = [];
  currentUrlRisk = calculateUrlRisk(null);
  renderUrlRisk();
}

function runUrlChecks(url) {
  const result = getUrlCheckResults(url);
  currentUrlChecks = result.checks;
  currentUrlRisk = calculateUrlRisk(result);
  renderUrlRisk();
  if (result.error) {
    showUnavailable(result.error, "URL parsing failed.");
    return;
  }

  if (currentUrlChecks.length === 0) {
    return;
  }

  updateUrlCheckCount(currentUrlChecks.length, "checks");
  urlCheckState.textContent = "LOCAL ONLY";
  engineStatus.textContent = "URL checks ready";
  renderUrlChecks();
  renderReport();
}

function renderUrlRisk() {
  renderUrlRiskResults(overviewRiskResults, currentUrlRisk);
  renderUrlRiskResults(urlRiskResults, currentUrlRisk);
}

function renderUrlChecks() {
  renderUrlCheckResults(urlResults, currentUrlChecks);
}

function renderReport() {
  reportResults.replaceChildren();

  if (currentUrlChecks.length === 0 && !currentPageSignals) {
    const empty = document.createElement("p");
    empty.textContent = "URL checks are unavailable for this tab.";
    reportResults.append(empty);
    return;
  }

  if (currentUrlChecks.length > 0) {
    const heading = document.createElement("p");
    heading.className = "report-summary";
    const observations = currentUrlChecks.filter((check) => check.flagged);
    heading.textContent = observations.length
      ? observations.length + " URL observation(s) from " + currentUrlChecks.length + " local checks."
      : "No unusual URL characteristics found in " + currentUrlChecks.length + " local checks.";
    reportResults.append(heading);

    currentUrlChecks.forEach((check) =>
      appendUrlCheckResult(reportResults, check)
    );
  }

  if (currentPageSignals) {
    const pageSummary = document.createElement("p");
    pageSummary.className = "report-summary";
    pageSummary.textContent =
      "Page snapshot: " +
      currentPageSignals.crossOriginResourceCount +
      " cross-origin resource entries, " +
      currentPageSignals.redirectCount +
      " navigation redirects reported, and " +
      (currentPageSignals.consentCandidate
        ? "possible visible consent UI indicators found."
        : "no matching visible consent UI indicators detected.") +
      " " +
      (currentPageSignals.cookieInventoryAvailable
        ? currentPageSignals.visibleCookieNames.length +
          " page-visible cookie name(s) observed; values omitted."
        : "Page-visible cookie names were unavailable.");
    reportResults.append(pageSummary);
  }
}

function displayTab(tab) {
  if (!tab || typeof tab.url !== "string" || tab.url.length === 0) {
    showUnavailable(
      "Chrome did not expose this page URL. Browser-owned pages, including the new-tab page, may be restricted. Open WebGuard from a regular website tab.",
      "Chrome returned no URL for the active tab."
    );
    return;
  }

  let page;
  try {
    page = new URL(tab.url);
  } catch {
    showUnavailable(
      "The active tab URL is not valid.",
      "The tab URL could not be parsed."
    );
    return;
  }

  if (page.protocol !== "https:" && page.protocol !== "http:") {
    const isNewTab =
      (page.protocol === "chrome:" || page.protocol === "edge:") &&
      /^(newtab|new-tab-page)$/i.test(page.hostname);
    const pageLabel = isNewTab
      ? "New tab page"
      : page.protocol === "file:"
        ? "Local file"
        : "Browser page";
    const explanation = isNewTab
      ? "The new-tab page is managed by the browser and cannot be inspected."
      : page.protocol === "file:"
        ? "This local file is not an HTTP or HTTPS website."
        : "Browser-internal pages are restricted and cannot be inspected.";

    hostnameElement.textContent = pageLabel;
    hostnameElement.title = pageLabel;
    urlElement.textContent = explanation;
    urlElement.title = explanation;
    httpsStatusElement.textContent = "N/A";
    httpsBadge.dataset.state = "unavailable";
    updateUrlCheckCount("—", "checks");
    urlCheckState.textContent = "NOT A WEBSITE";
    engineStatus.textContent = "Website required";
    currentUrlChecks = [];
    currentUrlRisk = calculateUrlRisk({ checks: [], error: null });
    renderUrlRisk();
    renderUrlChecks();
    renderReport();
    console.info("[WebGuard] Active tab is not a regular HTTP(S) website.");
    return;
  }

  urlElement.textContent = tab.url;
  urlElement.title = tab.url;
  hostnameElement.textContent = page.hostname;
  hostnameElement.title = page.hostname;
  const isHttps = page.protocol === "https:";
  httpsStatusElement.textContent = isHttps ? "HTTPS" : "HTTP";
  httpsBadge.dataset.state = isHttps ? "secure" : "insecure";
  runUrlChecks(tab.url);
  console.info("[WebGuard] Local URL checks completed (" + currentUrlChecks.length + " checks).");
}

function loadActiveTab() {
  if (!globalThis.chrome || !chrome.tabs || typeof chrome.tabs.query !== "function") {
    showUnavailable(
      "The browser tab API is unavailable. Load WebGuard as an extension and open it from the toolbar.",
      "Extension APIs are missing; this may be a directly opened popup file."
    );
    return;
  }

  try {
    // activeTab grants temporary URL access after the user opens this popup.
    // No broad tabs or host permission is needed for the active tab.
    const manifest = chrome.runtime.getManifest();
    const permissions = manifest && manifest.permissions;
    if (!Array.isArray(permissions) || !permissions.includes("activeTab")) {
      showUnavailable(
        "WebGuard is missing its active-tab permission. Reload the extension from chrome://extensions.",
        "The extension manifest does not declare activeTab."
      );
      return;
    }

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const apiError = chrome.runtime.lastError;
      if (apiError) {
        showUnavailable(
          "Chrome could not provide the active tab. Open WebGuard from its toolbar button on a regular website.",
          "chrome.tabs.query reported an error."
        );
        return;
      }

      if (!Array.isArray(tabs)) {
        showUnavailable(
          "Chrome did not return the active tab. Close and reopen the WebGuard popup.",
          "chrome.tabs.query returned an unexpected result."
        );
        return;
      }

      activeTabId = tabs[0] && tabs[0].id;
      displayTab(tabs[0]);
      refreshNavigationHistory(activeTabId);
    });
  } catch {
    showUnavailable(
      "WebGuard could not access the active tab. Reload the extension and reopen it from the toolbar.",
      "An exception occurred while querying the active tab."
    );
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (
    message &&
    message.type === "WEBGUARD_NAVIGATION_HISTORY_UPDATED" &&
    Number.isInteger(activeTabId)
  ) {
    refreshNavigationHistory(activeTabId);
  }
});

async function renderPageSignals(signals) {
  if (
    !signals ||
    !Number.isFinite(signals.crossOriginResourceCount) ||
    !Number.isFinite(signals.crossOriginHostCount) ||
    !Array.isArray(signals.crossOriginHosts) ||
    signals.crossOriginHosts.length > 12 ||
    signals.crossOriginHosts.length > signals.crossOriginHostCount ||
    !signals.crossOriginHosts.every((host) => typeof host === "string") ||
    !Number.isFinite(signals.redirectCount) ||
    !Number.isFinite(signals.visibleConsentNodes) ||
    !Number.isFinite(signals.matchingConsentControls) ||
    typeof signals.consentCandidate !== "boolean" ||
    typeof signals.cookieInventoryAvailable !== "boolean" ||
    !Array.isArray(signals.visibleCookieNames) ||
    !signals.visibleCookieNames.every((name) => typeof name === "string")
  ) {
    throw new Error("The active page returned an invalid signal snapshot.");
  }

  document.getElementById("cross-resource-count").textContent =
    String(signals.crossOriginResourceCount);
  document.getElementById("cross-host-count").textContent =
    String(signals.crossOriginHostCount);

  const omittedHostCount = Math.max(
    0,
    signals.crossOriginHostCount - signals.crossOriginHosts.length
  );
  const ruleValidation = await hostRulesPromise;
  const hostClassifications = classifyResourceHosts(
    signals.crossOriginHosts,
    ruleValidation
  );
  renderResourceClassifications(
    hostClassificationList,
    hostClassificationSummary,
    hostClassifications,
    omittedHostCount,
    signals.crossOriginHostCount
  );

  document.getElementById("redirect-result").textContent =
    "The current page timing entry reports " +
    signals.redirectCount +
    " redirect(s) in this page snapshot. This is separate from observed Chrome navigation events.";
  document.getElementById("consent-result").textContent =
    signals.consentCandidate
      ? "Possible visible consent-related interface detected (" +
        signals.visibleConsentNodes +
        " matching elements, " +
        signals.matchingConsentControls +
        " matching controls). This is not a consent assessment."
      : "No matching visible consent interface was detected. A banner may still exist in a form this check does not recognize.";

  const cookieInventoryResult = document.getElementById("cookie-inventory-result");
  const visibleCookieList = document.getElementById("visible-cookie-list");
  visibleCookieList.replaceChildren();
  if (!signals.cookieInventoryAvailable) {
    cookieInventoryResult.textContent =
      "Cookie names could not be read from this page.";
    const item = document.createElement("li");
    item.textContent = "No cookie-name data is available.";
    visibleCookieList.append(item);
  } else if (signals.visibleCookieNames.length === 0) {
    cookieInventoryResult.textContent =
      "No page-visible cookie names were found.";
    const item = document.createElement("li");
    item.textContent = "No page-visible cookies found.";
    visibleCookieList.append(item);
  } else {
    cookieInventoryResult.textContent =
      signals.visibleCookieNames.length +
      " page-visible cookie name(s) found. Values are not displayed.";
    signals.visibleCookieNames.forEach((name) => {
      const item = document.createElement("li");
      item.textContent = name;
      visibleCookieList.append(item);
    });
  }

  document.getElementById("resource-status").textContent =
    signals.crossOriginResourceCount + " cross-origin entries";
  document.getElementById("consent-status").textContent =
    signals.cookieInventoryAvailable
      ? signals.visibleCookieNames.length +
        " names · " +
        (signals.consentCandidate ? "UI signal" : "no UI signal")
      : "Cookie names unavailable";
  document.getElementById("report-status").textContent = "Local snapshot ready";

  pageCheckStatus.textContent =
    "Page snapshot checked successfully. " +
    signals.crossOriginResourceCount +
    " cross-origin resource entries; " +
    (signals.cookieInventoryAvailable
      ? "cookie names only (values omitted). "
      : "cookie names unavailable. ") +
    "No request blocking.";
  currentPageSignals = signals;
  renderReport();
}

function refreshNavigationHistory(tabId) {
  if (!Number.isInteger(tabId) || !chrome.runtime?.sendMessage) {
    const result = {
      available: false,
      reason: "The active tab ID or extension messaging API is unavailable."
    };
    renderNavigationHistory(navigationOverviewEvents, [], result);
    renderNavigationHistory(navigationAnalysisEvents, [], result);
    document.getElementById("redirect-status").textContent = "Unavailable";
    return;
  }

  chrome.runtime.sendMessage(
    {
      type: "WEBGUARD_GET_NAVIGATION_HISTORY",
      tabId
    },
    (response) => {
      const apiError = chrome.runtime.lastError;
      if (apiError || !response || !response.available) {
        const unavailable = {
          available: false,
          reason:
            response?.reason ||
            "Navigation monitoring is unavailable. Reload WebGuard after checking its permissions."
        };
        renderNavigationHistory(navigationOverviewEvents, [], unavailable);
        renderNavigationHistory(navigationAnalysisEvents, [], unavailable);
        document.getElementById("redirect-status").textContent = "Unavailable";
        return;
      }

      renderNavigationHistory(navigationOverviewEvents, response.events, {
        available: true,
        limit: 3
      });
      renderNavigationHistory(navigationAnalysisEvents, response.events, {
        available: true
      });
      const redirects = response.events.reduce(
        (count, record) => count + record.redirectEvents.length,
        0
      );
      const newTabs = response.events.filter(
        (record) => record.openedInNewTab
      ).length;
      document.getElementById("redirect-status").textContent =
        redirects +
        " observed redirects · " +
        newTabs +
        " new-tab target(s)";
    }
  );
}

function queryActiveTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const apiError = chrome.runtime.lastError;
      if (apiError) {
        console.error("[WebGuard] Active-tab query failed.");
        reject(new Error(apiError.message));
        return;
      }

      resolve(Array.isArray(tabs) ? tabs[0] : null);
    });
  });
}

function collectPageSignals() {
  const pageOrigin = window.location.origin;
  const hostSet = new Set();
  let crossOriginResourceCount = 0;

  performance.getEntriesByType("resource").forEach((entry) => {
    try {
      const resource = new URL(entry.name);
      if (resource.origin !== pageOrigin) {
        crossOriginResourceCount += 1;
        hostSet.add(resource.hostname);
      }
    } catch {
      // Ignore resource entries that do not contain a usable URL.
    }
  });

  function isVisible(element) {
    const style = window.getComputedStyle(element);
    const bounds = element.getBoundingClientRect();
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      Number(style.opacity) !== 0 &&
      bounds.width > 0 &&
      bounds.height > 0
    );
  }

  const consentNodes = document.querySelectorAll(
    '[id*="cookie" i], [class*="cookie" i], [id*="consent" i], [class*="consent" i], [aria-label*="cookie" i], [aria-label*="consent" i]'
  );
  let visibleConsentNodes = 0;
  consentNodes.forEach((element) => {
    if (isVisible(element)) {
      visibleConsentNodes += 1;
    }
  });

  const consentTextPattern =
    /\b(cookie|cookies|consent|privacy settings|accept all|reject all)\b/i;
  const controls = document.querySelectorAll(
    'button, [role="button"], input[type="button"], input[type="submit"], [aria-label]'
  );
  let matchingConsentControls = 0;
  controls.forEach((element) => {
    if (!isVisible(element)) {
      return;
    }

    const label =
      (element.getAttribute("aria-label") || "") +
      " " +
      (element.innerText || element.value || "");
    if (consentTextPattern.test(label)) {
      matchingConsentControls += 1;
    }
  });

  const navigation = performance.getEntriesByType("navigation")[0];
  let cookieInventoryAvailable = false;
  let visibleCookieNames = [];
  try {
    visibleCookieNames = Array.from(
      new Set(
        document.cookie
          .split(";")
          .map((cookie) => cookie.trim().split("=")[0].trim())
          .filter(Boolean)
      )
    ).sort();
    cookieInventoryAvailable = true;
  } catch {
    // Keep the rest of the page snapshot usable if cookie access is unavailable.
  }

  return {
    crossOriginResourceCount,
    crossOriginHostCount: hostSet.size,
    crossOriginHosts: Array.from(hostSet).slice(0, 12),
    redirectCount: navigation ? navigation.redirectCount : 0,
    visibleConsentNodes,
    matchingConsentControls,
    consentCandidate: visibleConsentNodes > 0 || matchingConsentControls > 0,
    cookieInventoryAvailable,
    visibleCookieNames
  };
}

function pageSignalErrorMessage(error) {
  const detail = error && error.message ? error.message : String(error);
  if (/cannot access|cannot be scripted|extensions gallery|chrome web store|restricted|The extensions gallery cannot be scripted|Cannot access contents/i.test(detail)) {
    return "Chrome restricts extensions from checking this page. Try a regular website tab.";
  }

  return "Page signal check failed: " + detail;
}

async function runPageSignals() {
  console.info("[WebGuard] Check page signals button clicked.");
  if (!runPageChecksButton || !pageCheckStatus) {
    console.error("[WebGuard] Cannot run page-signal check because popup controls are missing.");
    return;
  }
  if (runPageChecksButton.disabled) {
    console.info("[WebGuard] Ignoring duplicate page-signal request.");
    return;
  }

  runPageChecksButton.disabled = true;
  runPageChecksButton.textContent = "Checking page…";
  pageCheckStatus.textContent = "Checking page signals...";
  console.info("[WebGuard] Page-signal check started; loading state applied.");

  let stage = "checking extension API availability";
  try {
    if (!chrome.scripting || typeof chrome.scripting.executeScript !== "function") {
      throw new Error("The scripting permission is missing. Reload WebGuard from chrome://extensions.");
    }

    stage = "querying the active tab";
    console.info("[WebGuard] Querying the active tab in the current window.");
    const tab = await queryActiveTab();
    if (!tab || !Number.isInteger(tab.id)) {
      throw new Error("Chrome did not return an active tab.");
    }
    if (typeof tab.url !== "string" || !/^https?:/i.test(tab.url)) {
      throw new Error("This is a restricted or non-website tab. Try a regular HTTP or HTTPS website.");
    }

    console.info("[WebGuard] Active tab selected.", {
      tabId: tab.id
    });
    activeTabId = tab.id;
    stage = "injecting the page-signal collector";
    console.info("[WebGuard] Active HTTP(S) tab is available; requesting page snapshot.");
    await new Promise((resolve) => requestAnimationFrame(resolve));
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectPageSignals
    });
    console.info("[WebGuard] Page script execution completed.", {
      tabId: tab.id,
      resultCount: Array.isArray(results) ? results.length : 0
    });

    stage = "validating the page-signal response";
    if (!Array.isArray(results) || !results[0] || !results[0].result) {
      throw new Error("Chrome did not return a page signal snapshot.");
    }

    const signals = results[0].result;
    stage = "rendering page-signal results";
    await renderPageSignals(signals);
    console.info("[WebGuard] Page signal check succeeded.", {
      crossOriginResourceCount: signals.crossOriginResourceCount,
      crossOriginHostCount: signals.crossOriginHostCount,
      redirectCount: signals.redirectCount,
      consentCandidate: signals.consentCandidate,
      cookieInventoryAvailable: signals.cookieInventoryAvailable,
      visibleCookieNameCount: signals.visibleCookieNames.length
    });
  } catch (error) {
    const message = pageSignalErrorMessage(error);
    pageCheckStatus.textContent = message;
    console.error("[WebGuard] Page-signal check failed while " + stage + ".");
  } finally {
    runPageChecksButton.disabled = false;
    runPageChecksButton.innerHTML = "<span aria-hidden=\"true\">⌕</span> Check page signals";
    console.info("[WebGuard] Page-signal check finished; button re-enabled.", {
      tabId: activeTabId
    });
  }
}

if (runPageChecksButton) {
  runPageChecksButton.addEventListener("click", runPageSignals);
  console.info("[WebGuard] Click handler registered for #run-page-checks.");
}

function activateView(viewName, moveFocus) {
  const selectedButton = navigationItems.find(
    (item) => item.dataset.view === viewName
  );
  const selectedView = views.find((view) => view.id === "view-" + viewName);

  if (!selectedButton || !selectedView) {
    return;
  }

  navigationItems.forEach((item) => {
    const isSelected = item === selectedButton;
    item.classList.toggle("is-active", isSelected);
    item.setAttribute("aria-selected", String(isSelected));
    item.tabIndex = isSelected ? 0 : -1;
  });

  views.forEach((view) => {
    const isSelected = view === selectedView;
    view.hidden = !isSelected;
    view.classList.toggle("is-visible", isSelected);
  });

  dashboardPanel.setAttribute("aria-labelledby", selectedButton.id);

  if (moveFocus) {
    selectedButton.focus();
  }
}

navigationItems.forEach((item, index) => {
  item.addEventListener("click", () => activateView(item.dataset.view, false));
  item.addEventListener("keydown", (event) => {
    let nextIndex;
    switch (event.key) {
      case "ArrowDown":
      case "ArrowRight":
        nextIndex = (index + 1) % navigationItems.length;
        break;
      case "ArrowUp":
      case "ArrowLeft":
        nextIndex = (index - 1 + navigationItems.length) % navigationItems.length;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = navigationItems.length - 1;
        break;
      default:
        return;
    }

    event.preventDefault();
    activateView(navigationItems[nextIndex].dataset.view, true);
  });
});

document.querySelectorAll(".quick-card").forEach((card) => {
  card.addEventListener("click", () => activateView(card.dataset.view, false));
});

document.querySelector("[data-home]").addEventListener("click", (event) => {
  event.preventDefault();
  activateView("overview", false);
});

function activateExposureMode(mode, moveFocus = false) {
  const selectedTab = exposureModeTabs.find(
    (tab) => tab.dataset.exposureMode === mode
  );
  if (!selectedTab) {
    return;
  }

  exposureModeTabs.forEach((tab) => {
    const isSelected = tab === selectedTab;
    tab.classList.toggle("is-active", isSelected);
    tab.setAttribute("aria-selected", String(isSelected));
    tab.tabIndex = isSelected ? 0 : -1;
  });
  exposureModePanels.forEach((panel) => {
    const isSelected =
      panel.id === selectedTab.getAttribute("aria-controls");
    panel.hidden = !isSelected;
  });

  if (moveFocus) {
    selectedTab.focus();
  }
}

exposureModeTabs.forEach((tab, index) => {
  tab.addEventListener("click", () =>
    activateExposureMode(tab.dataset.exposureMode)
  );
  tab.addEventListener("keydown", (event) => {
    let nextIndex;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        nextIndex = (index + 1) % exposureModeTabs.length;
        break;
      case "ArrowLeft":
      case "ArrowUp":
        nextIndex = (index - 1 + exposureModeTabs.length) % exposureModeTabs.length;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = exposureModeTabs.length - 1;
        break;
      default:
        return;
    }

    event.preventDefault();
    activateExposureMode(
      exposureModeTabs[nextIndex].dataset.exposureMode,
      true
    );
  });
});

if (emailExposureForm && exposureResults) {
  emailExposureForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("email-exposure-input");
    const result = await exposureProviders.email.lookup(input.value);
    renderExposureResult(exposureResults, result);
    exposureResults.dataset.state = result.status;
  });
}

if (websiteExposureForm && exposureResults && websiteExposureSubmit) {
  websiteExposureForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (websiteExposureSubmit.disabled) {
      return;
    }

    const input = document.getElementById("website-exposure-input");
    websiteExposureSubmit.disabled = true;
    websiteExposureSubmit.textContent = "Checking provider…";
    exposureResults.dataset.state = "loading";
    exposureResults.setAttribute("aria-busy", "true");
    exposureResults.replaceChildren();
    const loading = document.createElement("p");
    loading.className = "exposure-state-message";
    loading.textContent = "Loading available breach incident metadata…";
    exposureResults.append(loading);

    try {
      const result = await exposureProviders.website.lookup(input.value);
      renderExposureResult(exposureResults, result);
      exposureResults.dataset.state = result.status;
    } catch {
      renderExposureResult(exposureResults, {
        status: "unavailable",
        reason: "The breach catalog lookup failed unexpectedly. Try again later."
      });
      exposureResults.dataset.state = "unavailable";
    } finally {
      websiteExposureSubmit.disabled = false;
      websiteExposureSubmit.textContent = "Check breach history";
      exposureResults.setAttribute("aria-busy", "false");
    }
  });
}

loadActiveTab();
