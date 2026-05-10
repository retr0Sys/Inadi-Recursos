/**
 * INADI Recursos — Lógica de aplicación
 * Controles de seguridad OWASP 2025.
 */

/* ════════════════════════════════════════════════════════════════════════
   SELF-XSS CONSOLE WARNING
   Advierte al usuario si alguien le pide pegar código en la consola.
   ════════════════════════════════════════════════════════════════════════ */
(function _consoleWarning() {
  const s = [
    "%c⛔ ADVERTENCIA DE SEGURIDAD",
    "color:#ff4d4d;font-size:22px;font-weight:bold;",
  ];
  const b = [
    "%cEsta consola es para desarrolladores.\nSi alguien te pidió pegar algo aquí,\nes un intento de robar tu cuenta (Self-XSS).\n¡No lo hagas!",
    "color:#ffcc00;font-size:14px;line-height:1.6;",
  ];
  console.log(...s);
  console.log(...b);
})();


/* ════════════════════════════════════════════════════════════════════════
   MÓDULO DE SEGURIDAD
   ════════════════════════════════════════════════════════════════════════ */

const Security = (function () {

  /* ── Anti-clickjacking ──────────────────────────────────────────────── */
  (function _frameGuard() {
    if (window.self !== window.top) {
      window.top.location = window.self.location;
    }
  })();

  /* ── Rate Limiting ──────────────────────────────────────────────────── */
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
    }
  }

  function resetFails() {
    sessionStorage.removeItem(RATE_KEY);
    sessionStorage.removeItem(RATE_TS_KEY);
  }

  /* ── SHA-256 + Salt via Web Crypto API ──────────────────────────────── */
  async function sha256salted(salt, str) {
    // SHA-256( salt + input ) — salt obtenido de _cfg.getSalt()
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(salt + str));
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /* ── Sanitización de texto (prevención XSS) ─────────────────────────── */
  function escapeHtml(str) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(String(str)));
    return d.innerHTML;
  }

  /* ── Validación de URL ───────────────────────────────────────────────── */
  function isSafeUrl(raw) {
    try {
      const u = new URL(raw);
      return u.protocol === "https:" || u.protocol === "http:";
    } catch (_) {
      return false;
    }
  }

  /* ── Limpieza de sesión ─────────────────────────────────────────────── */
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
   FETCH CON TIMEOUT
   AbortController cancela la solicitud si el backend no responde en 10s.
   ════════════════════════════════════════════════════════════════════════ */
async function fetchWithTimeout(url, options = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
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


/* ════════════════════════════════════════════════════════════════════════
   INICIALIZACIÓN
   ════════════════════════════════════════════════════════════════════════ */

(function init() {
  _endpoint = _cfg.getEndpoint();
  _salt     = _cfg.getSalt();

  document.getElementById("username")
    .addEventListener("keydown", e => { if (e.key === "Enter") login(); });

  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeModal();
  });

  document.getElementById("modal")
    .addEventListener("click", e => {
      if (e.target === document.getElementById("modal")) closeModal();
    });
})();


/* ════════════════════════════════════════════════════════════════════════
   AUTENTICACIÓN
   ════════════════════════════════════════════════════════════════════════ */

async function login() {
  const btn     = document.getElementById("loginBtn");
  const errorEl = document.getElementById("loginError");

  /* ── Rate limiting ─────────────────────────────────────────────────── */
  if (Security.isBlocked()) {
    const secs = Math.ceil(Security.remainingBlockMs() / 1000);
    _showError(errorEl, `Demasiados intentos. Esperá ${secs}s.`);
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
    /* ── Hash + Salt ───────────────────────────────────────────────────
       Se calcula SHA-256( salt + input ) y se compara contra los hashes
       almacenados en config.js. El salt nunca viaja en texto plano:
       se decodifica de Base64 en runtime y vive solo en memoria.
       ─────────────────────────────────────────────────────────────── */
    const inputHash = await Security.sha256salted(_salt, rawInput);
    const hashes    = _cfg.getUserHashes();
    const adminHash = _cfg.getAdminHash();

    if (!hashes.includes(inputHash)) {
      Security.recordFail();
      _showError(errorEl, "Usuario no autorizado.");
      return;
    }

    /* ── Login exitoso ─────────────────────────────────────────────── */
    Security.resetFails();
    errorEl.style.display = "none";

    _currentUser = rawInput;
    _isAdmin     = (inputHash === adminHash);

    sessionStorage.setItem("__sess_active", "1");
    sessionStorage.setItem("__sess_role", _isAdmin ? "admin" : "student");

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
}

function logout() {
  _currentUser = "";
  _isAdmin     = false;
  _resources   = [];

  Security.clearSession();

  document.getElementById("panel").classList.add("hidden");
  document.getElementById("loginScreen").classList.remove("hidden");
  document.getElementById("username").value             = "";
  document.getElementById("addButton").classList.add("hidden");
  document.getElementById("resourcesContainer").innerHTML = "";
  document.getElementById("emptyMessage").style.display  = "block";
  document.getElementById("loginError").style.display    = "none";
  document.getElementById("welcomeText").textContent      = "";
  document.getElementById("roleBadge").textContent        = "";
}


/* ════════════════════════════════════════════════════════════════════════
   RECURSOS
   ════════════════════════════════════════════════════════════════════════ */

async function loadResources() {
  const emptyEl = document.getElementById("emptyMessage");
  emptyEl.textContent   = "Cargando recursos…";
  emptyEl.style.display = "block";

  try {
    /* ── Fetch con timeout de 10 segundos ──────────────────────────── */
    const res = await fetchWithTimeout(_endpoint, { credentials: "omit" }, 10_000);

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const data = await res.json();

    if (!Array.isArray(data)) throw new Error("Respuesta inesperada de la API");

    _resources = data;
    renderResources();

  } catch (err) {
    if (err.name === "AbortError") {
      emptyEl.textContent = "El servidor tardó demasiado. Intentá de nuevo.";
    } else {
      emptyEl.textContent = "No se pudieron cargar los recursos. Intentá más tarde.";
    }
    emptyEl.style.display = "block";
    console.warn("[INADI] loadResources:", err.message);
  }
}

function renderResources() {
  const container = document.getElementById("resourcesContainer");
  const empty     = document.getElementById("emptyMessage");

  while (container.firstChild) container.removeChild(container.firstChild);

  if (!_resources.length) {
    empty.textContent   = "No hay recursos agregados todavía.";
    empty.style.display = "block";
    return;
  }

  empty.style.display = "none";

  _resources.forEach((resource, index) => {
    if (typeof resource !== "object" || resource === null) return;

    const rawNombre = String(resource.nombre ?? "Sin nombre");
    const rawLink   = String(resource.link ?? "");

    const card = document.createElement("div");
    card.className = "resource-card";

    const header = document.createElement("div");
    header.className = "resource-header";

    const title = document.createElement("h3");
    title.textContent = rawNombre;

    header.appendChild(title);

    if (_isAdmin) {
      const menuWrapper = document.createElement("div");
      menuWrapper.className = "menu-wrapper";

      const menuBtn = document.createElement("button");
      menuBtn.className = "menu-btn";
      menuBtn.textContent = "⋮";

      const menu = document.createElement("div");
      menu.className = "resource-menu hidden";

      const editBtn = document.createElement("button");
      editBtn.textContent = "✏️ Editar";
      editBtn.onclick = () => editResource(index);

      const deleteBtn = document.createElement("button");
      deleteBtn.textContent = "🗑️ Eliminar";
      deleteBtn.onclick = () => deleteResource(index);

      menu.appendChild(editBtn);
      menu.appendChild(deleteBtn);

      menuBtn.onclick = (e) => {
        e.stopPropagation();

        document.querySelectorAll(".resource-menu").forEach(m => {
          if (m !== menu) m.classList.add("hidden");
        });

        menu.classList.toggle("hidden");
      };

      menuWrapper.appendChild(menuBtn);
      menuWrapper.appendChild(menu);
      header.appendChild(menuWrapper);
    }

    card.appendChild(header);

    if (Security.isSafeUrl(rawLink)) {
      const link = document.createElement("a");
      link.href = rawLink;
      link.textContent = "Abrir recurso";
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      card.appendChild(link);
    } else {
      const warn = document.createElement("span");
      warn.className = "link-invalid";
      warn.textContent = "Enlace no disponible";
      card.appendChild(warn);
    }

    container.appendChild(card);
  });

  document.addEventListener("click", () => {
    document.querySelectorAll(".resource-menu")
      .forEach(menu => menu.classList.add("hidden"));
  });
}

async function editResource(index) {
  if (!_isAdmin) return;

  const resource = _resources[index];
  const newName = prompt("Nuevo nombre del recurso:", resource.nombre);

  if (newName === null) return;

  const trimmedName = newName.trim();

  if (!trimmedName) {
    alert("El nombre no puede estar vacío.");
    return;
  }

  try {
    const resp = await fetchWithTimeout(
      _endpoint,
      {
        method: "POST",
        credentials: "omit",
        body: JSON.stringify({
          action: "edit",
          index,
          nombre: trimmedName,
          link: resource.link
        }),
      },
      10000
    );

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    await loadResources();

  } catch (err) {
    console.warn("[INADI] editResource:", err.message);
    alert("No se pudo editar el recurso.");
  }
}

async function deleteResource(index) {
  if (!_isAdmin) return;

  const confirmDelete = confirm("¿Eliminar este recurso?");
  if (!confirmDelete) return;

  try {
    const resp = await fetchWithTimeout(
      _endpoint,
      {
        method: "POST",
        credentials: "omit",
        body: JSON.stringify({
          action: "delete",
          index
        }),
      },
      10000
    );

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    await loadResources();

  } catch (err) {
    console.warn("[INADI] deleteResource:", err.message);
    alert("No se pudo eliminar el recurso.");
  }
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
  document.getElementById("resourceName").value  = "";
  document.getElementById("resourceLink").value  = "";
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
    /* ── POST con timeout de 10 segundos ───────────────────────────── */
    const resp = await fetchWithTimeout(
      _endpoint,
      {
        method:      "POST",
        credentials: "omit",
        body: JSON.stringify({ action: "add", nombre: name, link }),
      },
      10_000
    );

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    closeModal();
    await loadResources();

  } catch (err) {
    if (err.name === "AbortError") {
      _showError(modalErr, "El servidor tardó demasiado. Intentá de nuevo.");
    } else {
      _showError(modalErr, "Error al guardar el recurso. Intentá de nuevo.");
    }
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
