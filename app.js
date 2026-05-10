/**
 * INADI Recursos — Lógica de aplicación
 * Marcos: OWASP Top 10 2025 · NIST SP 800-53 · ISO 27001 · CIS Controls v8
 */

/* ════════════════════════════════════════════════════════════════════════
   SELF-XSS CONSOLE WARNING — OWASP WSTG-CLIENT-011
   ════════════════════════════════════════════════════════════════════════ */
(function _consoleWarning() {
  console.log(
    "%c⛔ ADVERTENCIA DE SEGURIDAD",
    "color:#ff4d4d;font-size:22px;font-weight:bold;"
  );
  console.log(
    "%cEsta consola es para desarrolladores.\nSi alguien te pidió pegar algo aquí,\nes un intento de robar tu cuenta (Self-XSS).\n¡No lo hagas!",
    "color:#ffcc00;font-size:14px;line-height:1.6;"
  );
})();


/* ════════════════════════════════════════════════════════════════════════
   AUDIT LOG — NIST SP 800-53 AU-2 · CIS Control 8
   Registra eventos de seguridad sin datos sensibles (sin hashes ni nombres).
   ════════════════════════════════════════════════════════════════════════ */
const AuditLog = (function () {
  const PREFIX = "[INADI·AUDIT]";

  function log(event, detail = {}) {
    const entry = { ts: new Date().toISOString(), event, ...detail };
    console.info(PREFIX, JSON.stringify(entry));
  }

  return { log };
})();


/* ════════════════════════════════════════════════════════════════════════
   MÓDULO DE SEGURIDAD — OWASP · NIST · ISO 27001 · CIS
   ════════════════════════════════════════════════════════════════════════ */
const Security = (function () {

  /* ── Anti-clickjacking — OWASP A05 / CIS Control 12 ────────────────── */
  (function _frameGuard() {
    if (window.self !== window.top) {
      AuditLog.log("FRAME_INJECTION_DETECTED");
      window.top.location = window.self.location;
    }
  })();

  /* ── Rate Limiting — OWASP A07 / NIST AC-7 / CIS Control 6 ─────────── */
  const RATE_KEY    = "__rl_fails";
  const RATE_TS_KEY = "__rl_ts";
  const MAX_FAILS   = 5;
  const BLOCK_MS    = 30_000;

  function _getFailCount() {
    return parseInt(sessionStorage.getItem(RATE_KEY) || "0", 10);
  }

  function _getBlockTime() {
    return parseInt(sessionStorage.getItem(RATE_TS_KEY) || "0", 10);
  }

  function isBlocked() {
    const fails = _getFailCount();
    if (fails < MAX_FAILS) return false;
    const elapsed = Date.now() - _getBlockTime();
    if (elapsed >= BLOCK_MS) {
      sessionStorage.removeItem(RATE_KEY);
      sessionStorage.removeItem(RATE_TS_KEY);
      return false;
    }
    return true;
  }

  function remainingBlockMs() {
    return Math.max(0, BLOCK_MS - (Date.now() - _getBlockTime()));
  }

  function recordFail() {
    const fails = _getFailCount() + 1;
    sessionStorage.setItem(RATE_KEY, String(fails));
    if (fails >= MAX_FAILS) {
      sessionStorage.setItem(RATE_TS_KEY, String(Date.now()));
      AuditLog.log("RATE_LIMIT_TRIGGERED", { fails });
    }
  }

  function resetFails() {
    sessionStorage.removeItem(RATE_KEY);
    sessionStorage.removeItem(RATE_TS_KEY);
  }

  /* ── SHA-256 + Salt — OWASP A02 / NIST IA-5 / ISO 27001 A.9.4 ──────── */
  async function sha256salted(salt, str) {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(salt + str));
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /* ── Sanitización XSS — OWASP A03 / NIST SI-10 ─────────────────────── */
  function escapeHtml(str) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(String(str)));
    return d.innerHTML;
  }

  /* ── Validación de URL — OWASP A03 / CIS Control 9 ─────────────────── */
  function isSafeUrl(raw) {
    try {
      const u = new URL(raw);
      // Permite http:// y https:// para compatibilidad con recursos internos
      return u.protocol === "https:" || u.protocol === "http:";
    } catch (_) {
      return false;
    }
  }

  /* ── Limpieza de sesión — NIST AC-12 / CIS Control 16 ──────────────── */
  function clearSession() {
    const rlFails = sessionStorage.getItem(RATE_KEY);
    const rlTs    = sessionStorage.getItem(RATE_TS_KEY);
    sessionStorage.clear();
    if (rlFails) sessionStorage.setItem(RATE_KEY, rlFails);
    if (rlTs)    sessionStorage.setItem(RATE_TS_KEY, rlTs);
  }

  return {
    isBlocked,
    remainingBlockMs,
    recordFail,
    resetFails,
    sha256salted,
    escapeHtml,
    isSafeUrl,
    clearSession,
  };

})();


/* ════════════════════════════════════════════════════════════════════════
   SESSION MANAGER — NIST SP 800-53 AC-12 / CIS Control 16.11
   Cierra sesión automáticamente tras SESSION_TIMEOUT_MS de inactividad.
   El timer se reinicia ante cualquier interacción del usuario.
   ════════════════════════════════════════════════════════════════════════ */
const SessionManager = (function () {

  const TIMEOUT_MS  = _cfg.getSessionTimeout(); // 15 min
  const WARN_AT_MS  = 5 * 60 * 1000;            // aviso visual a 5 min
  const DANGER_AT_MS = 60 * 1000;               // aviso crítico a 1 min

  let _timer      = null;
  let _expireAt   = 0;
  let _timerEl    = null;
  let _tickId     = null;
  let _warnShown  = false;

  const _activityEvents = ["mousemove", "keydown", "click", "scroll", "touchstart"];

  function _onExpire() {
    AuditLog.log("SESSION_TIMEOUT_EXPIRED");
    Toast.show("Sesión cerrada por inactividad.", "warn", 5000);
    logout();
  }

  function _updateDisplay() {
    if (!_timerEl) return;
    const remaining = Math.max(0, _expireAt - Date.now());
    const mins = Math.floor(remaining / 60_000);
    const secs = Math.floor((remaining % 60_000) / 1_000);
    _timerEl.textContent = `Sesión: ${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;

    if (remaining <= DANGER_AT_MS) {
      _timerEl.className = "session-timer danger";
    } else if (remaining <= WARN_AT_MS) {
      _timerEl.className = "session-timer warn";
      if (!_warnShown) {
        _warnShown = true;
        Toast.show("Tu sesión cierra en 5 minutos.", "warn", 5000);
        AuditLog.log("SESSION_WARN_5MIN");
      }
    } else {
      _timerEl.className = "session-timer";
    }
  }

  function _reset() {
    if (!_timer) return;
    clearTimeout(_timer);
    _expireAt  = Date.now() + TIMEOUT_MS;
    _warnShown = false;
    _timer     = setTimeout(_onExpire, TIMEOUT_MS);
  }

  function start(timerEl) {
    _timerEl   = timerEl;
    _expireAt  = Date.now() + TIMEOUT_MS;
    _warnShown = false;
    _timer     = setTimeout(_onExpire, TIMEOUT_MS);

    _activityEvents.forEach(evt =>
      document.addEventListener(evt, _reset, { passive: true })
    );

    _tickId = setInterval(_updateDisplay, 1_000);
    _updateDisplay();
    AuditLog.log("SESSION_STARTED");
  }

  function stop() {
    clearTimeout(_timer);
    clearInterval(_tickId);
    _timer    = null;
    _expireAt = 0;

    _activityEvents.forEach(evt =>
      document.removeEventListener(evt, _reset)
    );

    if (_timerEl) {
      _timerEl.textContent = "";
      _timerEl.className   = "session-timer";
    }
  }

  return { start, stop };

})();


/* ════════════════════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS — UX
   ════════════════════════════════════════════════════════════════════════ */
const Toast = (function () {

  let _container = null;

  function _getContainer() {
    if (!_container) _container = document.getElementById("toastContainer");
    return _container;
  }

  function show(msg, type = "info", durationMs = 4_000) {
    const c = _getContainer();
    if (!c) return;

    const t = document.createElement("div");
    t.className   = `toast toast-${type}`;
    t.textContent = msg;  // textContent — XSS safe
    c.appendChild(t);

    requestAnimationFrame(() => t.classList.add("toast-show"));

    setTimeout(() => {
      t.classList.remove("toast-show");
      t.addEventListener("transitionend", () => t.remove(), { once: true });
    }, durationMs);
  }

  return { show };

})();


/* ════════════════════════════════════════════════════════════════════════
   FETCH CON TIMEOUT — NIST SI-3 / CIS Control 12
   AbortController cancela la solicitud si el backend no responde en 10s.
   ════════════════════════════════════════════════════════════════════════ */
async function fetchWithTimeout(url, options = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}


/* ════════════════════════════════════════════════════════════════════════
   ESTADO DE LA APLICACIÓN
   ════════════════════════════════════════════════════════════════════════ */
let _currentUser = "";
let _isAdmin     = false;
let _resources   = [];
let _endpoint    = "";
let _salt        = "";
let _searchQuery = "";

const MAX_RESPONSE_BYTES = _cfg.getMaxResponseSize(); // 512 KB — NIST SI-3


/* ════════════════════════════════════════════════════════════════════════
   INICIALIZACIÓN
   ════════════════════════════════════════════════════════════════════════ */
(function init() {
  _endpoint = _cfg.getEndpoint();
  _salt     = _cfg.getSalt();

  /* ── Botones — adjuntar via addEventListener (CSP bloquea onclick inline) ── */
  document.getElementById("loginBtn")
    .addEventListener("click", login);

  document.getElementById("logoutBtn")
    .addEventListener("click", logout);

  document.getElementById("addButton")
    .addEventListener("click", openModal);

  document.getElementById("cancelBtn")
    .addEventListener("click", closeModal);

  document.getElementById("saveBtn")
    .addEventListener("click", addResource);

  /* ── Teclado ──────────────────────────────────────────────────────────── */
  document.getElementById("username")
    .addEventListener("keydown", e => { if (e.key === "Enter") login(); });

  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeModal();
  });

  /* ── Cerrar modal al hacer click en el fondo ─────────────────────────── */
  document.getElementById("modal")
    .addEventListener("click", e => {
      if (e.target === document.getElementById("modal")) closeModal();
    });

  /* ── Búsqueda en tiempo real ─────────────────────────────────────────── */
  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      _searchQuery = searchInput.value.trim().toLowerCase();
      renderResources();
    });
  }
})();


/* ════════════════════════════════════════════════════════════════════════
   AUTENTICACIÓN
   ════════════════════════════════════════════════════════════════════════ */

async function login() {
  const btn     = document.getElementById("loginBtn");
  const errorEl = document.getElementById("loginError");

  /* ── Rate limiting — NIST AC-7 ──────────────────────────────────────── */
  if (Security.isBlocked()) {
    const secs = Math.ceil(Security.remainingBlockMs() / 1000);
    _showError(errorEl, `Demasiados intentos. Esperá ${secs}s.`);
    AuditLog.log("LOGIN_BLOCKED", { reason: "rate_limit" });
    return;
  }

  const rawInput = document.getElementById("username").value.trim();

  if (!rawInput) {
    _showError(errorEl, "Ingresá tu nombre y apellido.");
    return;
  }

  btn.disabled    = true;
  btn.textContent = "Verificando…";

  try {
    /* ── SHA-256 + Salt — OWASP A02 / NIST IA-5 ────────────────────────── */
    const inputHash = await Security.sha256salted(_salt, rawInput);
    const hashes    = _cfg.getUserHashes();
    const adminHash = _cfg.getAdminHash();

    if (!hashes.includes(inputHash)) {
      Security.recordFail();
      _showError(errorEl, "Usuario no autorizado.");
      AuditLog.log("LOGIN_FAIL", { reason: "unauthorized" });
      return;
    }

    /* ── Login exitoso ──────────────────────────────────────────────────── */
    Security.resetFails();
    errorEl.style.display = "none";

    _currentUser = rawInput;
    _isAdmin     = (inputHash === adminHash);

    sessionStorage.setItem("__sess_active", "1");
    sessionStorage.setItem("__sess_role", _isAdmin ? "admin" : "student");

    AuditLog.log("LOGIN_SUCCESS", { role: _isAdmin ? "admin" : "student" });

    _applySession();
    loadResources();

  } catch (err) {
    _showError(errorEl, "Error interno. Intentá de nuevo.");
    console.warn("[INADI] login:", err.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = "Ingresar";
  }
}

function _applySession() {
  document.getElementById("loginScreen").classList.add("hidden");
  document.getElementById("panel").classList.remove("hidden");
  document.getElementById("welcomeText").textContent = `Bienvenido, ${_currentUser}`;
  document.getElementById("roleBadge").textContent   = _isAdmin ? "Administrador" : "Estudiante";
  document.getElementById("addButton").classList.toggle("hidden", !_isAdmin);

  /* ── Iniciar session timeout — NIST AC-12 / CIS 16.11 ──────────────── */
  SessionManager.start(document.getElementById("sessionTimer"));
}

function logout() {
  AuditLog.log("LOGOUT");
  SessionManager.stop();

  /* ── Cerrar modal si estaba abierto ─────────────────────────────────── */
  closeModal();

  _currentUser = "";
  _isAdmin     = false;
  _resources   = [];
  _searchQuery = "";

  Security.clearSession();

  /* ── Limpiar contenedor de recursos con removeChild (CSP-safe) ──────── */
  const container = document.getElementById("resourcesContainer");
  while (container.firstChild) container.removeChild(container.firstChild);

  document.getElementById("panel").classList.add("hidden");
  document.getElementById("loginScreen").classList.remove("hidden");
  document.getElementById("username").value             = "";
  document.getElementById("addButton").classList.add("hidden");
  document.getElementById("emptyMessage").style.display = "block";
  document.getElementById("emptyMessage").textContent   = "No hay recursos agregados todavía.";
  document.getElementById("loginError").style.display   = "none";
  document.getElementById("welcomeText").textContent    = "";
  document.getElementById("roleBadge").textContent      = "";

  const searchInput = document.getElementById("searchInput");
  if (searchInput) searchInput.value = "";

  /* ── Enfocar el campo de usuario para facilitar nuevo ingreso ────────── */
  const usernameInput = document.getElementById("username");
  if (usernameInput) usernameInput.focus();
}


/* ════════════════════════════════════════════════════════════════════════
   RECURSOS
   ════════════════════════════════════════════════════════════════════════ */

async function loadResources() {
  _renderSkeleton();

  try {
    /* ── Fetch con timeout — CIS Control 12 ─────────────────────────── */
    const res = await fetchWithTimeout(_endpoint, { credentials: "omit" }, 10_000);

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    /* ── Validar tamaño de respuesta — NIST SI-3 / CIS Control 13 ────── */
    const contentLength = res.headers.get("content-length");
    if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
      throw new Error("Respuesta demasiado grande");
    }

    const text = await res.text();
    if (text.length > MAX_RESPONSE_BYTES) {
      throw new Error("Respuesta demasiado grande");
    }

    const data = JSON.parse(text);
    if (!Array.isArray(data)) throw new Error("Respuesta inesperada de la API");

    _resources = data;
    AuditLog.log("RESOURCES_LOADED", { count: _resources.length });
    renderResources();

  } catch (err) {
    _clearSkeleton();
    const emptyEl = document.getElementById("emptyMessage");
    emptyEl.textContent = err.name === "AbortError"
      ? "El servidor tardó demasiado. Intentá de nuevo."
      : "No se pudieron cargar los recursos. Intentá más tarde.";
    emptyEl.style.display = "block";
    console.warn("[INADI] loadResources:", err.message);
  }
}

function _renderSkeleton() {
  const container = document.getElementById("resourcesContainer");
  const emptyEl   = document.getElementById("emptyMessage");

  while (container.firstChild) container.removeChild(container.firstChild);
  emptyEl.style.display = "none";

  for (let i = 0; i < 6; i++) {
    const card = document.createElement("div");
    card.className = "resource-card skeleton-card";

    const t = document.createElement("div");
    t.className = "skeleton-line skeleton-title";
    card.appendChild(t);

    const b = document.createElement("div");
    b.className = "skeleton-line skeleton-body";
    card.appendChild(b);

    container.appendChild(card);
  }
}

function _clearSkeleton() {
  document.querySelectorAll(".skeleton-card")
    .forEach(s => s.remove());
}

function renderResources() {
  const container = document.getElementById("resourcesContainer");
  const emptyEl   = document.getElementById("emptyMessage");

  while (container.firstChild) container.removeChild(container.firstChild);

  /* ── Filtrar por búsqueda ──────────────────────────────────────────── */
  const filtered = _searchQuery
    ? _resources.filter(r =>
        String(r.nombre ?? "").toLowerCase().includes(_searchQuery) ||
        String(r.link   ?? "").toLowerCase().includes(_searchQuery)
      )
    : _resources;

  if (!filtered.length) {
    emptyEl.textContent   = _searchQuery
      ? "No se encontraron recursos para esa búsqueda."
      : "No hay recursos agregados todavía.";
    emptyEl.style.display = "block";
    return;
  }

  emptyEl.style.display = "none";

  filtered.forEach((resource, idx) => {
    if (typeof resource !== "object" || resource === null) return;

    /* ── Validar longitudes — NIST SI-10 ────────────────────────────── */
    const rawNombre = String(resource.nombre ?? "Sin nombre").slice(0, 200);
    const rawLink   = String(resource.link   ?? "").slice(0, 2048);

    /* ── DOM seguro: nunca innerHTML con datos externos — OWASP A03 ─── */
    const card = document.createElement("div");
    card.className = "resource-card card-enter";
    card.style.animationDelay = `${idx * 55}ms`;

    const title = document.createElement("h3");
    title.textContent = rawNombre;
    card.appendChild(title);

    if (Security.isSafeUrl(rawLink)) {
      const link       = document.createElement("a");
      link.href        = rawLink;
      link.textContent = "Abrir recurso";
      link.target      = "_blank";
      link.rel         = "noopener noreferrer";  // previene tabnapping — OWASP A05
      card.appendChild(link);
    } else {
      const warn       = document.createElement("span");
      warn.className   = "link-invalid";
      warn.textContent = "Enlace no disponible";
      card.appendChild(warn);
    }

    container.appendChild(card);
  });
}


/* ════════════════════════════════════════════════════════════════════════
   MODAL — AGREGAR RECURSO (solo admin)
   ════════════════════════════════════════════════════════════════════════ */

function openModal() {
  if (!_isAdmin) return;
  document.getElementById("modal").classList.remove("hidden");
  document.getElementById("resourceName").focus();
}

function closeModal() {
  document.getElementById("modal").classList.add("hidden");
  document.getElementById("resourceName").value       = "";
  document.getElementById("resourceLink").value       = "";
  document.getElementById("modalError").style.display = "none";
}

async function addResource() {
  if (!_isAdmin) return;

  const modalErr = document.getElementById("modalError");
  const name     = document.getElementById("resourceName").value.trim();
  const link     = document.getElementById("resourceLink").value.trim();

  if (!name) {
    _showError(modalErr, "El nombre del recurso no puede estar vacío.");
    return;
  }
  if (name.length > 120) {
    _showError(modalErr, "El nombre es demasiado largo (máx. 120 caracteres).");
    return;
  }
  if (!link) {
    _showError(modalErr, "El link no puede estar vacío.");
    return;
  }
  if (!Security.isSafeUrl(link)) {
    _showError(modalErr, "El link debe ser una URL válida (https:// o http://).");
    return;
  }

  modalErr.style.display = "none";

  const saveBtn = document.querySelector("#modal .btn:not(.secondary)");
  saveBtn.disabled    = true;
  saveBtn.textContent = "Guardando…";

  try {
    /* ── POST con timeout — CIS Control 12 ─────────────────────────── */
    const resp = await fetchWithTimeout(
      _endpoint,
      {
        method:      "POST",
        credentials: "omit",
        body: JSON.stringify({ nombre: name, link }),
      },
      10_000
    );

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    AuditLog.log("RESOURCE_ADDED");
    Toast.show("Recurso guardado correctamente.", "success");
    closeModal();
    await loadResources();

  } catch (err) {
    const msg = err.name === "AbortError"
      ? "El servidor tardó demasiado. Intentá de nuevo."
      : "Error al guardar el recurso. Intentá de nuevo.";
    _showError(modalErr, msg);
    console.warn("[INADI] addResource:", err.message);
  } finally {
    saveBtn.disabled    = false;
    saveBtn.textContent = "Guardar";
  }
}


/* ════════════════════════════════════════════════════════════════════════
   UTILIDADES UI
   ════════════════════════════════════════════════════════════════════════ */

function _showError(el, msg) {
  el.textContent   = msg;
  el.style.display = "block";
}
