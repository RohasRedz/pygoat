/**
 * introduction/static/js/a7.js
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

async function callProtectedApi() {
  try {
    const token = await fetchJwtForCurrentUser();

    const response = await fetch("/api/protected/resource", {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error("Failed to call protected API");
    }

    const result = await response.json();
    const outputEl = document.getElementById("a7-output");
    if (outputEl) {
      outputEl.textContent = JSON.stringify(result, null, 2);
    }
  } catch (err) {
    const outputEl = document.getElementById("a7-output");
    if (outputEl) {
      outputEl.textContent = "An error occurred while loading data.";
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("a7-load-btn");
  if (btn) {
    btn.addEventListener("click", () => {
      void callProtectedApi();
    });
  }
});

export { fetchJwtForCurrentUser, callProtectedApi };
