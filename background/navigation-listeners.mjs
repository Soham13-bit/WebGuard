export const REQUIRED_NAVIGATION_EVENTS = Object.freeze([
  "onBeforeNavigate",
  "onBeforeRedirect",
  "onCommitted",
  "onCompleted",
  "onErrorOccurred",
  "onCreatedNavigationTarget"
]);

export function registerNavigationListeners(webNavigation, handlers) {
  if (!webNavigation || typeof webNavigation !== "object") {
    return { available: false, unavailableEvents: ["webNavigation"] };
  }

  const unavailableEvents = [];
  const apiErrors = [];
  const events = new Map();
  for (const name of REQUIRED_NAVIGATION_EVENTS) {
    try {
      const event = webNavigation[name];
      if (
        !event ||
        typeof event.addListener !== "function" ||
        !handlers ||
        typeof handlers[name] !== "function"
      ) {
        unavailableEvents.push(name);
      } else {
        events.set(name, event);
      }
    } catch (error) {
      unavailableEvents.push(name);
      apiErrors.push({ event: name, error: describeError(error) });
    }
  }
  if (unavailableEvents.length > 0) {
    return {
      available: false,
      unavailableEvents,
      apiErrors,
      registrationErrors: [],
      cleanupFailedEvents: []
    };
  }

  const registeredEvents = [];
  for (const name of REQUIRED_NAVIGATION_EVENTS) {
    const event = events.get(name);
    registeredEvents.push({ name, event, handler: handlers[name] });
    try {
      event.addListener(handlers[name]);
    } catch (error) {
      const cleanupFailedEvents = [];
      for (const registered of registeredEvents.reverse()) {
        try {
          const removeListener = registered.event.removeListener;
          if (typeof removeListener !== "function") {
            throw new Error("removeListener is unavailable");
          }
          removeListener.call(registered.event, registered.handler);
        } catch (cleanupError) {
          cleanupFailedEvents.push({
            event: registered.name,
            error: describeError(cleanupError)
          });
        }
      }
      return {
        available: false,
        unavailableEvents: [name],
        apiErrors: [],
        registrationErrors: [
          { event: name, error: describeError(error) }
        ],
        cleanupFailedEvents
      };
    }
  }

  return {
    available: true,
    unavailableEvents: [],
    apiErrors: [],
    registrationErrors: [],
    cleanupFailedEvents: []
  };
}

function describeError(error) {
  if (error && typeof error === "object") {
    const name = typeof error.name === "string" ? error.name : "Error";
    const message =
      typeof error.message === "string" && error.message
        ? error.message
        : "No error message was provided";
    return name + ": " + message;
  }
  return typeof error === "string" ? error : "Unknown error";
}

export function formatNavigationRegistrationFailure(result) {
  const details = [];
  if (Array.isArray(result.unavailableEvents) && result.unavailableEvents.length) {
    details.push("unavailable: " + result.unavailableEvents.join(", "));
  }
  if (Array.isArray(result.apiErrors)) {
    for (const entry of result.apiErrors) {
      details.push("could not inspect " + entry.event + ": " + entry.error);
    }
  }
  if (Array.isArray(result.registrationErrors)) {
    for (const entry of result.registrationErrors) {
      details.push(
        "registration failed for " + entry.event + ": " + entry.error
      );
    }
  }
  if (Array.isArray(result.cleanupFailedEvents)) {
    for (const entry of result.cleanupFailedEvents) {
      details.push(
        "could not remove " + entry.event + " during rollback: " + entry.error
      );
    }
  }
  return details.length
    ? details.join("; ")
    : "No API or event failure details were available.";
}
