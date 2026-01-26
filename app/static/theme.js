/*
  AD Portal — Theme toggle
  Uses Bootstrap 5.3 color mode attribute: data-bs-theme="light|dark".
  - Initial theme is applied as early as possible via a small inline snippet in templates.
  - This file wires the toggle button and keeps the icon in sync.
*/

(function () {
  const STORAGE_KEY = "adportal_theme";

  function getTheme() {
    return document.documentElement.getAttribute("data-bs-theme") || "light";
  }

  function setTheme(theme) {
    document.documentElement.setAttribute("data-bs-theme", theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) {
      // ignore
    }
    syncToggles();
  }

  function sunSvg() {
    return (
      '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' +
      '<path fill="currentColor" d="M12 18a6 6 0 1 1 0-12 6 6 0 0 1 0 12Zm0-2a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0-14a1 1 0 0 1 1 1v1a1 1 0 1 1-2 0V3a1 1 0 0 1 1-1Zm0 18a1 1 0 0 1 1 1v1a1 1 0 1 1-2 0v-1a1 1 0 0 1 1-1Zm10-9a1 1 0 0 1-1 1h-1a1 1 0 1 1 0-2h1a1 1 0 0 1 1 1ZM4 12a1 1 0 0 1-1 1H2a1 1 0 1 1 0-2h1a1 1 0 0 1 1 1Zm14.95-6.95a1 1 0 0 1 0 1.41l-.71.71a1 1 0 1 1-1.41-1.41l.71-.71a1 1 0 0 1 1.41 0ZM7.17 16.83a1 1 0 0 1 0 1.41l-.71.71a1 1 0 1 1-1.41-1.41l.71-.71a1 1 0 0 1 1.41 0Zm11.07 1.41a1 1 0 0 1-1.41 0l-.71-.71a1 1 0 0 1 1.41-1.41l.71.71a1 1 0 0 1 0 1.41ZM7.88 7.88a1 1 0 0 1-1.41 0l-.71-.71A1 1 0 0 1 7.17 5.76l.71.71a1 1 0 0 1 0 1.41Z"/>' +
      "</svg>"
    );
  }

  function moonSvg() {
    return (
      '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' +
      '<path fill="currentColor" d="M21 14.7A8.1 8.1 0 0 1 9.3 3a1 1 0 0 0-1.24 1.23A8.1 8.1 0 1 0 19.77 15.9 1 1 0 0 0 21 14.7Zm-2.4.6A6.1 6.1 0 1 1 8.7 5.4a10.2 10.2 0 0 0 9.9 9.9Z"/>' +
      "</svg>"
    );
  }

  function syncToggles() {
    const theme = getTheme();
    const toggles = document.querySelectorAll("[data-theme-toggle]");
    toggles.forEach((btn) => {
      const isDark = theme === "dark";
      btn.innerHTML = isDark ? sunSvg() : moonSvg();
      btn.setAttribute("aria-label", isDark ? "Светлая тема" : "Тёмная тема");
      btn.setAttribute("title", isDark ? "Светлая тема" : "Тёмная тема");
      btn.setAttribute("data-theme", theme);
    });
  }

  function toggleTheme() {
    const current = getTheme();
    setTheme(current === "dark" ? "light" : "dark");
  }

  document.addEventListener("click", function (e) {
    const btn = e.target && e.target.closest ? e.target.closest("[data-theme-toggle]") : null;
    if (!btn) return;
    e.preventDefault();
    toggleTheme();
  });

  // Keep in sync if system preference changes and user has no explicit choice.
  // (If localStorage has a value, we consider it explicit.)
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored && window.matchMedia) {
      const mql = window.matchMedia("(prefers-color-scheme: dark)");
      mql.addEventListener("change", function (ev) {
        document.documentElement.setAttribute("data-bs-theme", ev.matches ? "dark" : "light");
        syncToggles();
      });
    }
  } catch (e) {
    // ignore
  }

  syncToggles();
})();
