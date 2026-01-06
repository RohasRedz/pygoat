import { fetchJwtForCurrentUser, callProtectedApi } from "../a7";

describe("a7.js JWT handling (delta tests)", () => {
  beforeEach(() => {
    global.fetch = jest.fn();
    document.body.innerHTML = "";
    jest.clearAllMocks();
  });

  test("fetchJwtForCurrentUser obtains token from backend and does not use hardcoded value", async () => {
    const backendToken = "backend-issued-token";
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ token: backendToken }),
    });

    const token = await fetchJwtForCurrentUser();

    expect(global.fetch).toHaveBeenCalledWith(
      "/api/auth/token",
      expect.objectContaining({
        method: "GET",
        credentials: "include",
      })
    );
    expect(token).toBe(backendToken);
  });

  test("fetchJwtForCurrentUser throws when backend does not return a token", async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    });

    await expect(fetchJwtForCurrentUser()).rejects.toThrow("Invalid token response");
  });

  test("callProtectedApi uses JWT in Authorization header and writes safe text output", async () => {
    const backendToken = "backend-issued-token";
    const protectedData = { message: "hello" };

    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: backendToken }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => protectedData,
      });

    document.body.innerHTML = `
      <button id="a7-load-btn">Load</button>
      <pre id="a7-output"></pre>
    `;

    await callProtectedApi();

    expect(global.fetch).toHaveBeenNthCalledWith(
      2,
      "/api/protected/resource",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: `Bearer ${backendToken}`,
        }),
      })
    );

    const outputEl = document.getElementById("a7-output");
    expect(outputEl).not.toBeNull();
    expect(outputEl.textContent).toContain('"message": "hello"');
  });

  test("callProtectedApi shows generic error message on failure", async () => {
    global.fetch.mockResolvedValueOnce({
      ok: false,
    });

    document.body.innerHTML = `<pre id="a7-output"></pre>`;

    await callProtectedApi();

    const outputEl = document.getElementById("a7-output");
    expect(outputEl.textContent).toContain("An error occurred while loading data.");
  });
});
