/**
 * Shared auth utilities for the UI.
 * Manages tokens in localStorage and provides API helpers.
 */

const AUTH = (() => {
  const ACCESS_KEY = "access_token";
  const REFRESH_KEY = "refresh_token";

  function getAccessToken() {
    return localStorage.getItem(ACCESS_KEY);
  }

  function getRefreshToken() {
    return localStorage.getItem(REFRESH_KEY);
  }

  function saveTokens(tokenPair) {
    localStorage.setItem(ACCESS_KEY, tokenPair.access_token);
    localStorage.setItem(REFRESH_KEY, tokenPair.refresh_token);
  }

  function clearTokens() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  }

  function isLoggedIn() {
    return !!getAccessToken() && !!getRefreshToken();
  }

  /** Fetch wrapper that attaches the Bearer token automatically. */
  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...options.headers };
    const token = getAccessToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const res = await fetch(path, { ...options, headers });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw { status: res.status, detail: body.detail || res.statusText };
    }
    return res.json();
  }

  /** Redirect to login, preserving the current page as ?redirect= */
  function redirectToLogin() {
    const current = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = "/ui/login/?redirect=" + current;
  }

  /** If not logged in, redirect to login. Call on protected pages. */
  function requireAuth() {
    if (!isLoggedIn()) {
      redirectToLogin();
      return false;
    }
    return true;
  }

  return {
    getAccessToken,
    getRefreshToken,
    saveTokens,
    clearTokens,
    isLoggedIn,
    api,
    redirectToLogin,
    requireAuth,
  };
})();
