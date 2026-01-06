// File: introduction/static/js/__tests__/a9.test.js
// NOTE: This test file covers only the behavior changed in BATCH-006:
// - Removal of hardcoded JWT/CSRF tokens
// - Runtime retrieval of JWT via /api/auth/token
// - Runtime retrieval of CSRF token from cookie/DOM
// - Safe log rendering via textContent instead of innerHTML

// TODO: Adjust import path if bundler/test setup differs.
import {
  getCookie,
  getCsrfToken,
  fetchJwtForCurrentUser,
  event3,
} from '../a9';

describe('a9.js security delta tests', () => {
  beforeEach(() => {
    // Reset DOM and mocks before each test
    document.body.innerHTML = `
      <input id="a9_log" value="LOG_CODE_VALUE" />
      <input id="a9_api" value="API_CODE_VALUE" />
      <div id="a9_d3" style="display:none"></div>
      <input type="hidden" id="csrf-token" value="DOM_CSRF_TOKEN" />
    `;

    jest.resetAllMocks();
    jest.clearAllMocks();
  });

  describe('getCookie', () => {
    it('returns cookie value when present', () => {
      document.cookie = 'csrftoken=ABC123; other=xyz';

      const value = getCookie('csrftoken');

      expect(value).toBe('ABC123');
    });

    it('returns null when cookie not present', () => {
      document.cookie = 'other=xyz';

      const value = getCookie('csrftoken');

      expect(value).toBeNull();
    });
  });

  describe('getCsrfToken', () => {
    it('prefers csrftoken from cookie when present', () => {
      document.cookie = 'csrftoken=COOKIE_TOKEN';

      const token = getCsrfToken();

      expect(token).toBe('COOKIE_TOKEN');
    });

    it('falls back to DOM hidden input when cookie missing', () => {
      document.cookie = ''; // no csrftoken cookie
      // csrf-token input already in DOM from beforeEach

      const token = getCsrfToken();

      expect(token).toBe('DOM_CSRF_TOKEN');
    });

    it('falls back to input[name=csrfmiddlewaretoken] when id not present', () => {
      document.body.innerHTML = `
        <input id="a9_log" value="LOG_CODE_VALUE" />
        <input id="a9_api" value="API_CODE_VALUE" />
        <div id="a9_d3" style="display:none"></div>
        <input type="hidden" name="csrfmiddlewaretoken" value="NAME_CSRF_TOKEN" />
      `;
      document.cookie = '';

      const token = getCsrfToken();

      expect(token).toBe('NAME_CSRF_TOKEN');
    });

    it('returns null when no cookie or DOM token found', () => {
      document.body.innerHTML = `
        <input id="a9_log" value="LOG_CODE_VALUE" />
        <input id="a9_api" value="API_CODE_VALUE" />
        <div id="a9_d3" style="display:none"></div>
      `;
      document.cookie = '';

      const token = getCsrfToken();

      expect(token).toBeNull();
    });
  });

  describe('fetchJwtForCurrentUser', () => {
    it('calls backend with credentials and returns token on success', async () => {
      const mockToken = 'RUNTIME_JWT_TOKEN';
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ token: mockToken }),
      });

      const token = await fetchJwtForCurrentUser();

      expect(global.fetch).toHaveBeenCalledWith('/api/auth/token', {
        method: 'GET',
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      expect(token).toBe(mockToken);
    });

    it('throws when response not ok', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        json: jest.fn(),
      });

      await expect(fetchJwtForCurrentUser()).rejects.toThrow(
        /Failed to obtain JWT from server/
      );
    });

    it('throws when token field is missing or invalid', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ not_token: 'x' }),
      });

      await expect(fetchJwtForCurrentUser()).rejects.toThrow(
        /Invalid token response from server/
      );
    });
  });

  describe('event3', () => {
    it('aborts without calling fetch when CSRF token is missing', async () => {
      // Ensure getCsrfToken will fail
      document.body.innerHTML = `
        <input id="a9_log" value="LOG_CODE_VALUE" />
        <input id="a9_api" value="API_CODE_VALUE" />
        <div id="a9_d3" style="display:none"></div>
      `;
      document.cookie = '';
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      global.fetch = jest.fn();

      await event3();

      expect(global.fetch).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'CSRF token not found. Aborting request for safety.'
      );
    });

    it('aborts without calling fetch when JWT fetch fails', async () => {
      // Provide a CSRF token but make JWT fetch fail
      document.cookie = 'csrftoken=COOKIE_TOKEN';
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      global.fetch = jest
        .fn()
        .mockRejectedValueOnce(new Error('network failure')); // used by fetchJwtForCurrentUser

      await event3();

      expect(global.fetch).toHaveBeenCalledTimes(1); // only /api/auth/token
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Unable to fetch JWT from server:',
        expect.any(Error)
      );
    });

    it('sends runtime tokens and renders logs safely as text', async () => {
      document.cookie = 'csrftoken=COOKIE_TOKEN';

      const apiResponseBody = JSON.stringify({
        logs: ['log-1 <b>xss</b>', 'log-2 & more'],
      });

      // First call: JWT endpoint; Second call: A9 API
      global.fetch = jest
        .fn()
        .mockResolvedValueOnce({
          ok: true,
          json: jest.fn().mockResolvedValue({ token: 'RUNTIME_JWT' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          text: jest.fn().mockResolvedValue(apiResponseBody),
        });

      // Spy on Headers and FormData to assert usage
      const originalHeaders = global.Headers;
      const originalFormData = global.FormData;

      const appendedHeaders = [];
      global.Headers = class {
        constructor() {
          this.map = {};
        }
        append(k, v) {
          appendedHeaders.push([k, v]);
          this.map[k] = v;
        }
      };

      const formDataEntries = [];
      global.FormData = class {
        append(k, v) {
          formDataEntries.push([k, v]);
        }
      };

      await event3();

      // Verify two fetch calls in order: token endpoint then A9 API
      expect(global.fetch).toHaveBeenNthCalledWith(
        1,
        '/api/auth/token',
        expect.any(Object)
      );
      expect(global.fetch).toHaveBeenNthCalledWith(
        2,
        '/2021/discussion/A9/api',
        expect.objectContaining({
          method: 'POST',
          body: expect.any(Object),
          credentials: 'include',
          headers: expect.any(Object),
        })
      );

      // Ensure no hardcoded tokens, but runtime ones are used
      const headerMap = Object.fromEntries(appendedHeaders);
      expect(headerMap['X-CSRFToken']).toBe('COOKIE_TOKEN');
      expect(headerMap['Authorization']).toBe('Bearer RUNTIME_JWT');
      // No hardcoded JWT or CSRF strings
      expect(JSON.stringify(headerMap)).not.toMatch(/eyJ0eXAiOiJKV1Qi/);
      expect(JSON.stringify(headerMap)).not.toMatch(/5fVOTXh2HNahtvJFJNRSrKkwPAgPM9YCHlrCGprAxhAAKOUWMxqMnWm8BUomv0Yd/);

      // FormData contains runtime CSRF and user fields
      const fdMap = Object.fromEntries(formDataEntries);
      expect(fdMap['csrfmiddlewaretoken']).toBe('COOKIE_TOKEN');
      expect(fdMap['log_code']).toBe('LOG_CODE_VALUE');
      expect(fdMap['api_code']).toBe('API_CODE_VALUE');

      // Verify logs are rendered as text (no HTML interpretation)
      const listContainer = document.getElementById('a9_d3');
      expect(listContainer.style.display).toBe('flex');
      const items = Array.from(listContainer.querySelectorAll('li'));
      expect(items).toHaveLength(2);
      expect(items[0].textContent).toBe('log-1 <b>xss</b>');
      expect(items[1].textContent).toBe('log-2 & more');
      // innerHTML of li should not interpret <b> as markup when we used textContent
      expect(items[0].innerHTML).toBe('log-1 &lt;b&gt;xss&lt;/b&gt;');

      // Restore globals
      global.Headers = originalHeaders;
      global.FormData = originalFormData;
    });
  });
});
