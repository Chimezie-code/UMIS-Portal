/* umis-auth.js — shared client-side auth utilities */

const UMIS_AUTH = (() => {
  const TOKEN_KEY = 'umis_token';
  const USER_KEY  = 'umis_user';
  const API       = 'http://localhost:3000/api';

  function saveSession(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }

  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function getUser() {
    const u = localStorage.getItem(USER_KEY);
    return u ? JSON.parse(u) : null;
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  function isLoggedIn() {
    const token = getToken();
    if (!token) return false;
    try {
      // Decode payload (no verification — server validates)
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 > Date.now();
    } catch {
      return false;
    }
  }

  // Call at the top of any protected page
  function requireAuth(expectedRole) {
    if (!isLoggedIn()) {
      window.location.href = 'login.html';
      return null;
    }
    const user = getUser();
    if (expectedRole && user.role !== expectedRole) {
      // Wrong role — send to correct dashboard or home
      if (user.role === 'student') {
        window.location.href = 'Academic_page.html';
      } else {
        window.location.href = 'Lecturer_page.html';
      }
      return null;
    }
    return user;
  }

  function logout() {
    clearSession();
    window.location.href = 'login.html';
  }

  async function authFetch(url, options = {}) {
    return fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`,
        ...(options.headers || {})
      }
    });
  }

  return { saveSession, getToken, getUser, clearSession, isLoggedIn, requireAuth, logout, authFetch, API };
})();