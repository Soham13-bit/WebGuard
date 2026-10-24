"use strict";

// Reserved for a future registered content-script workflow. The popup's
// on-demand page-signal check currently uses scripting.executeScript directly.
// This file is not registered in the manifest and does not run automatically.
(() => {
  const listenerKey = "__webGuardPageSignalListenerInstalled";

  if (globalThis[listenerKey]) {
    return;
  }
  globalThis[listenerKey] = true;

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
        // Resource timing entries without a usable URL are not counted.
      }
    });

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
    return {
      crossOriginResourceCount,
      crossOriginHostCount: hostSet.size,
      crossOriginHosts: Array.from(hostSet).slice(0, 12),
      redirectCount: navigation ? navigation.redirectCount : 0,
      visibleConsentNodes,
      matchingConsentControls,
      consentCandidate: visibleConsentNodes > 0 || matchingConsentControls > 0
    };
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (
      sender.id !== chrome.runtime.id ||
      !message ||
      message.type !== "WEBGUARD_COLLECT_PAGE_SIGNALS"
    ) {
      return false;
    }

    try {
      sendResponse({ ok: true, signals: collectPageSignals() });
    } catch (error) {
      console.warn("[WebGuard] Failed to collect page signal snapshot.", error);
      sendResponse({
        ok: false,
        error: "The page snapshot could not be collected."
      });
    }

    return false;
  });

  console.info("[WebGuard] On-demand page signal listener is ready.");
})();
