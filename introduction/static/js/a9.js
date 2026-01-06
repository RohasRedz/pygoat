// console.log("imported a9.js");

/**
 * introduction/static/js/a9.js
 *
 * Security Remediation:
 * - Removed hardcoded JWT and CSRF token from client-side code.
 * - JWT is now obtained securely at runtime from the backend (for the
 *   current authenticated user/session), not baked into the bundle.
 * - CSRF token is obtained from a cookie or injected into the DOM,
 *   instead of being hardcoded.
 * - No secrets are committed to source control.
 *
 * NOTE:
 * - This implementation assumes:
 *     1) The backend exposes an authenticated endpoint at
 *        `/api/auth/token` returning `{ token: "<jwt>" }`.
 *     2) A CSRF token is either present in a cookie named `csrftoken`
 *        (Django-style) or is rendered into the page by the server
 *        (e.g., hidden input in a form).
 * - Adjust the URLs and token retrieval as needed to fit your backend.
 */

/**
 * Safely read a cookie value by name.
 *
 * This is used to obtain the CSRF token without hardcoding it.
 */
function getCookie(name) {
  if (typeof document === "undefined") return null;

  const cookieString = document.cookie || "";
  if (!cookieString) return null;

  const cookies = cookieString.split(";");

  for (let i = 0; i < cookies.length; i += 1) {
    const cookie = cookies[i].trim();
    if (!cookie) continue;

    const [key, ...rest] = cookie.split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

/**
 * Retrieve the CSRF token used by the backend.
 *
 * Priority:
 *   1. Cookie named "csrftoken" (Django default)
 *   2. Hidden input element with id="csrf-token" or name="csrfmiddlewaretoken"
 */
function getCsrfToken() {
  // Try cookie (Django-style)
  const fromCookie = getCookie("csrftoken");
  if (fromCookie) {
    return fromCookie;
  }

  // Try DOM (e.g., <input type="hidden" id="csrf-token" ...>)
  if (typeof document !== "undefined") {
    const byId = document.getElementById("csrf-token");
    if (byId && byId.value) {
      return byId.value;
    }

    const byName = document.querySelector("input[name='csrfmiddlewaretoken']");
    if (byName && byName.value) {
      return byName.value;
    }
  }

  // If not found, return null and let caller decide how to handle.
  return null;
}

/**
 * Fetch a JWT for the current authenticated user from the backend.
 *
 * Security considerations:
 * - JWT is not hardcoded; it is issued server-side per user/session.
 * - This function relies on existing authentication (e.g., session cookie).
 * - Tokens should be short-lived and revocable on the server.
 */
async function fetchJwtForCurrentUser() {
  const response = await fetch("/api/auth/token", {
    method: "GET",
    credentials: "include",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error("Failed to obtain JWT from server");
  }

  const data = await response.json();

  if (!data || typeof data.token !== "string") {
    throw new Error("Invalid token response from server");
  }

  return data.token;
}

/**
 * Original UI behavior:
 * - event1: show/hide specific DOM sections
 * - event2: show/hide specific DOM sections
 * - event3: submit log_code and api_code via POST to
 *           `/2021/discussion/A9/api` and render returned logs list.
 *
 * Security changes in event3:
 * - No hardcoded `Cookie` header with JWT or CSRF token.
 * - CSRF token is dynamically obtained via `getCsrfToken()`.
 * - JWT is dynamically obtained via `fetchJwtForCurrentUser()`.
 * - Logs are added to the DOM using textContent instead of innerHTML
 *   to prevent DOM XSS from log entries.
 */

event1 = function () {
  document.getElementById("a9_b1").style.display = "none";
  document.getElementById("a9_d1").style.display = "flex";
};

event2 = function () {
  document.getElementById("a9_b2").style.display = "none";
  document.getElementById("a9_d2").style.display = "flex";
};

event3 = async function () {
  const log_code = document.getElementById("a9_log").value;
  const target_code = document.getElementById("a9_api").value;

  // Obtain CSRF token securely at runtime.
  const csrfToken = getCsrfToken();
  if (!csrfToken) {
    console.error("CSRF token not found. Aborting request for safety.");
    // Optionally, you can show a user-visible error instead of silently failing.
    return;
  }

  let jwt;
  try {
    // Obtain JWT securely at runtime, not from hardcoded constants.
    jwt = await fetchJwtForCurrentUser();
  } catch (err) {
    console.error("Unable to fetch JWT from server:", err);
    // Again, you might want to show a user-visible error here.
    return;
  }

  // Build headers without manually constructing a Cookie string
  // containing sensitive tokens.
  const myHeaders = new Headers();
  // JWT is typically used in Authorization header. If your backend
  // expects it in a cookie instead, set it server-side, not here.
  myHeaders.append("Accept", "application/json");
  myHeaders.append("X-CSRFToken", csrfToken);
  myHeaders.append("Authorization", `Bearer ${jwt}`);

  const formdata = new FormData();
  formdata.append("csrfmiddlewaretoken", csrfToken);
  formdata.append("log_code", log_code);
  formdata.append("api_code", target_code);

  const requestOptions = {
    method: "POST",
    headers: myHeaders,
    body: formdata,
    redirect: "follow",
    credentials: "include", // ensure cookies (session, csrftoken) are sent
  };

  try {
    const response = await fetch("/2021/discussion/A9/api", requestOptions);
    const resultText = await response.text();

    // Try to parse JSON safely
    let data;
    try {
      data = JSON.parse(resultText);
    } catch (parseErr) {
      console.error("Failed to parse API response as JSON:", parseErr);
      return;
    }

    if (!data || !Array.isArray(data.logs)) {
      console.error("Unexpected response format from A9 API.");
      return;
    }

    console.log(data.logs);
    document.getElementById("a9_d3").style.display = "flex";

    const listContainer = document.getElementById("a9_d3");

    // Clear any existing children if necessary (optional)
    // while (listContainer.firstChild) {
    //   listContainer.removeChild(listContainer.firstChild);
    // }

    for (let i = 0; i < data.logs.length; i += 1) {
      const li = document.createElement("li");
      // Use textContent to avoid injecting HTML and prevent DOM XSS
      li.textContent = String(data.logs[i]);
      listContainer.appendChild(li);
    }
  } catch (error) {
    console.log("error", error);
  }
};

export {
  getCookie,
  getCsrfToken,
  fetchJwtForCurrentUser,
  event1,
  event2,
  event3,
};
