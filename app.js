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

  /* ── Rate Limiting (localStorage — persiste entre pestañas) ──────────
     CIS Control 5.4 | OWASP A07:2025 | NIST PR.AA-05
     Usar localStorage en lugar de sessionStorage evita que un atacante
     eluda el bloqueo abriendo una nueva pestaña.
     ──────────────────────────────────────────────────────────────────── */
  const RATE_KEY    = "__inadi_rl_fails";
  const RATE_TS_KEY = "__inadi_rl_ts";
  const MAX_FAILS   = 5;
  const BLOCK_MS    = 30_000;

  function _getFailCount() {
    return parseInt(localStorage.getItem(RATE_KEY) || "0", 10);
  }

  function _getBlockTime() {
    return parseInt(localStorage.getItem(RATE_TS_KEY) || "0", 10);
  }

  function isBlocked() {
    const fails = _getFailCount();
    if (fails < MAX_FAILS) return false;
    const elapsed = Date.now() - _getBlockTime();
    if (elapsed >= BLOCK_MS) {
      localStorage.removeItem(RATE_KEY);
      localStorage.removeItem(RATE_TS_KEY);
      return false;
    }
    return true;
  }

  function remainingBlockMs() {
    return Math.max(0, BLOCK_MS - (Date.now() - _getBlockTime()));
  }

  function recordFail() {
    const fails = _getFailCount() + 1;
    localStorage.setItem(RATE_KEY, String(fails));
    if (fails >= MAX_FAILS) {
      localStorage.setItem(RATE_TS_KEY, String(Date.now()));
    }
  }

  function resetFails() {
    localStorage.removeItem(RATE_KEY);
    localStorage.removeItem(RATE_TS_KEY);
  }

  /* ── PBKDF2-SHA256 via Web Crypto API ───────────────────────────────
     NIST SP 800-132 | OWASP Password Storage Cheat Sheet 2025
     PBKDF2(password=nombre, salt=salt_bytes, iterations=200 000, PRF=SHA-256)
     Cumple con FIPS 140-2 y es resistente a ataques de diccionario/GPU.
     El login tardará ~150-200 ms — aceptable; dificulta brute-force.
     ──────────────────────────────────────────────────────────────────── */
  async function pbkdf2salted(saltStr, str) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(str),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name:       "PBKDF2",
        salt:       enc.encode(saltStr),
        iterations: _cfg.getPbkdf2Iters(),
        hash:       "SHA-256",
      },
      keyMaterial,
      256
    );
    return Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /* ── Sanitización de texto (prevención XSS) ─────────────────────────── */
  function escapeHtml(str) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(String(str)));
    return d.innerHTML;
  }

  /* ── Validación de URL (solo HTTPS) ────────────────────────────────── */
  function isSafeUrl(raw) {
    try {
      const u = new URL(raw);
      return u.protocol === "https:";
    } catch (_) {
      return false;
    }
  }

  /* ── Limpieza de sesión ─────────────────────────────────────────────── */
  function clearSession() {
    // Preserva los contadores de rate limiting (en localStorage, no en sessionStorage)
    sessionStorage.clear();
  }

  return {
    isBlocked,
    remainingBlockMs,
    recordFail,
    resetFails,
    pbkdf2salted,
    escapeHtml,
    isSafeUrl,
    clearSession,
  };

})();

/* Animación de carga */
function showSkeletons() {
  const container = document.getElementById("resourcesContainer");

  // Usar DocumentFragment evita reparsear el DOM en cada iteración (más seguro y eficiente)
  const frag = document.createDocumentFragment();

  for (let i = 0; i < 10; i++) {
    const card = document.createElement("div");
    card.className = "skeleton-card";
    card.style.setProperty("--i", i); // stagger animation

    ["skeleton-line title", "skeleton-line", "skeleton-line", "skeleton-line short"].forEach(cls => {
      const line = document.createElement("div");
      line.className = cls;
      card.appendChild(line);
    });

    frag.appendChild(card);
  }

  container.innerHTML = "";
  container.appendChild(frag);
}


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

let _currentUser        = "";
let _isAdmin            = false;
let _resources          = [];
let _endpoint           = "";
let _salt               = "";
let _searchQuery        = "";
let _editingIndex       = null; // índice del recurso en edición
let _pendingDeleteIndex = null; // índice del recurso pendiente de borrado



/* ════════════════════════════════════════════════════════════════════════
   INICIALIZACIÓN
   ════════════════════════════════════════════════════════════════════════ */

(function init() {
  _endpoint = _cfg.getEndpoint();
  _salt     = _cfg.getSalt();

  /* ── Listeners: Login ───────────────────────────────────────────────── */
  document.getElementById("username")
    .addEventListener("keydown", e => { if (e.key === "Enter") login(); });

  document.getElementById("loginBtn").addEventListener("click", login);
  document.getElementById("logoutBtn").addEventListener("click", logout);

  /* ── Listeners: Modal agregar ───────────────────────────────────────── */
  document.getElementById("addButton").addEventListener("click", openModal);
  document.getElementById("cancelModalBtn").addEventListener("click", closeModal);
  document.getElementById("saveModalBtn").addEventListener("click", addResource);

  document.getElementById("modal")
    .addEventListener("click", e => {
      if (e.target === document.getElementById("modal")) closeModal();
    });

  /* ── Listeners: Modal editar ────────────────────────────────────────── */
  document.getElementById("cancelEditModalBtn").addEventListener("click", closeEditModal);
  document.getElementById("saveEditModalBtn").addEventListener("click", saveEditResource);

  ["editResourceName", "editResourceLink"].forEach(id => {
    document.getElementById(id)
      .addEventListener("keydown", e => { if (e.key === "Enter") saveEditResource(); });
  });

  document.getElementById("editModal")
    .addEventListener("click", e => {
      if (e.target === document.getElementById("editModal")) closeEditModal();
    });

  /* ── Listeners: Modal confirmar borrado ─────────────────────────────── */
  document.getElementById("cancelDeleteModalBtn").addEventListener("click", closeDeleteModal);
  document.getElementById("confirmDeleteBtn").addEventListener("click", confirmDeleteResource);

  document.getElementById("deleteModal")
    .addEventListener("click", e => {
      if (e.target === document.getElementById("deleteModal")) closeDeleteModal();
    });

  /* ── Escape cierra cualquier modal abierto ───────────────────────────── */
  document.addEventListener("keydown", e => {
    if (e.key !== "Escape") return;
    closeModal();
    closeEditModal();
    closeDeleteModal();
  });

  /* ── Búsqueda de recursos ────────────────────────────────────────────── */
  const searchInput    = document.getElementById("searchInput");
  const searchClearBtn = document.getElementById("searchClearBtn");

  searchInput.addEventListener("input", () => {
    _searchQuery = searchInput.value.trim();
    searchClearBtn.classList.toggle("hidden", _searchQuery === "");
    renderResources();
  });

  searchClearBtn.addEventListener("click", () => {
    searchInput.value = "";
    _searchQuery = "";
    searchClearBtn.classList.add("hidden");
    searchInput.focus();
    renderResources();
  });

  _initIdleTimeout();

  /* ── Restaurar sesión tras recarga de página ─────────────────────────
     Si sessionStorage contiene una sesión válida, la reanuda sin pedir
     el nombre de nuevo. La sesión persiste solo en la pestaña actual.
     ─────────────────────────────────────────────────────────────────── */
  const sessUser = sessionStorage.getItem("__sess_user");
  const sessRole = sessionStorage.getItem("__sess_role");
  if (sessionStorage.getItem("__sess_active") && sessUser) {
    _currentUser = sessUser;
    _isAdmin     = sessRole === "admin";
    _applySession(() => {
    loadResources();
    });

    _resetIdleTimer();
    }
})();


/* ════════════════════════════════════════════════════════════════════════
   IDLE SESSION TIMEOUT
   ISO 27001:2022 A.8.5 | NIST PR.AA-02 | CIS Control 5.3
   Auto-logout tras 15 minutos sin actividad del usuario.
   ════════════════════════════════════════════════════════════════════════ */
const IDLE_TIMEOUT_MS = 15 * 60 * 1_000; // 15 minutos
let   _idleTimer      = null;

function _resetIdleTimer() {
  clearTimeout(_idleTimer);
  // Solo activar si hay sesión abierta
  if (sessionStorage.getItem("__sess_active")) {
    _idleTimer = setTimeout(() => {
      console.warn("[INADI] Sesión cerrada por inactividad.");
      logout();
    }, IDLE_TIMEOUT_MS);
  }
}

function _initIdleTimeout() {
  ["mousemove", "keydown", "click", "scroll", "touchstart"].forEach(evt => {
    document.addEventListener(evt, _resetIdleTimer, { passive: true });
  });
}


/* ════════════════════════════════════════════════════════════════════════
   AUTENTICACIÓN
   ════════════════════════════════════════════════════════════════════════ */

function disableLoginButtonCountdown(btn, errorEl) {

  btn.disabled = true;

  const updateButton = () => {

    const secs = Math.ceil(Security.remainingBlockMs() / 1000);

    _showError(
      errorEl,
      `Demasiados intentos. Esperá ${secs}s.`
    );

    if (secs <= 0) {

      clearInterval(interval);

      btn.disabled = false;
      btn.textContent = "Ingresar";

      errorEl.style.display = "none";
    }
  };

  updateButton();

  const interval = setInterval(updateButton, 1000);
}

async function login() {
  const btn     = document.getElementById("loginBtn");
  const errorEl = document.getElementById("loginError");

  /* ── Rate limiting ─────────────────────────────────────────────────── */
  if (Security.isBlocked()) {
    disableLoginButtonCountdown(btn, errorEl);
    return;
  }

  const rawInput = document.getElementById("username").value.trim();

  if (!rawInput) {
    _showError(errorEl, "Ingresá tu nombre y apellido.");
    return;
  }

  // Validación de longitud en JS (defensa en profundidad — no solo atributo HTML)
  if (rawInput.length > 80) {
    _showError(errorEl, "El nombre es demasiado largo.");
    return;
  }

  btn.disabled    = true;
  btn.textContent = "Verificando…";

  try {
    /* ── PBKDF2-SHA256 + Salt ──────────────────────────────────────────
       PBKDF2(password=input, salt=salt_bytes, iter=200 000, PRF=SHA-256)
       El resultado se compara contra los hashes de config.js.
       El salt se decodifica de Base64 en runtime y vive solo en memoria.
       ─────────────────────────────────────────────────────────────── */
    const inputHash = await Security.pbkdf2salted(_salt, rawInput);
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
    sessionStorage.setItem("__sess_user", rawInput);

    _applySession(() => {
    loadResources();
    });

    _resetIdleTimer();

  } catch (err) {

      // Evitar mostrar error si la sesión ya fue creada
      if (!sessionStorage.getItem("__sess_active")) {
        _showError(errorEl, "Error interno. Intentá de nuevo.");
      }

      console.warn("[INADI] login:", err.message);
  } 
  finally {
    btn.disabled    = false;
    btn.textContent = "Ingresar";
  }

  /* Ocultar footer durante la sesión (solo en UI, no en config.js) — estética y para evitar distracciones. */
  document.getElementById("footer").style.display = "none";
}

function _applySession(callback) {
  let user = (_isAdmin)? "Lucas Rangel" : _currentUser;

  // Fade out login
  const loginEl = document.getElementById("loginScreen");
  loginEl.classList.add("fade-out");

  setTimeout(() => {
    loginEl.classList.add("hidden");
    loginEl.classList.remove("fade-out");

    const panelEl = document.getElementById("panel");
    panelEl.classList.remove("hidden");
    panelEl.classList.add("fade-in");
    setTimeout(() => panelEl.classList.remove("fade-in"), 450);

    document.getElementById("welcomeText").textContent = `Bienvenido, ${user}`;

    const badge = document.getElementById("roleBadge");
    badge.textContent = _isAdmin ? "Administrador" : "Estudiante";
    badge.classList.toggle("admin", _isAdmin);

    document.getElementById("addButton").classList.toggle("hidden", !_isAdmin);
    document.getElementById("footer").style.display = "none";
    if (callback) callback();
  }, 260);
}

function logout() {
  _currentUser        = "";
  _isAdmin            = false;
  _resources          = [];
  _searchQuery        = "";
  _editingIndex       = null;
  _pendingDeleteIndex = null;

  Security.clearSession();

  /* Cerrar cualquier modal que estuviese abierto */
  closeModal();
  closeEditModal();
  closeDeleteModal();

  /* Restaurar UI de login */
  const panel     = document.getElementById("panel");
  const login     = document.getElementById("loginScreen");
  const container = document.getElementById("resourcesContainer");
  const emptyMsg  = document.getElementById("emptyMessage");

  panel.classList.add("hidden");
  login.classList.remove("hidden");

  document.getElementById("username").value          = "";
  document.getElementById("addButton").classList.add("hidden");
  document.getElementById("loginError").style.display = "none";
  document.getElementById("loginError").textContent = "";
  document.getElementById("welcomeText").textContent  = "";
  document.getElementById("roleBadge").textContent    = "";

  container.innerHTML       = "";
  emptyMsg.textContent      = "No hay recursos agregados todavía.";
  emptyMsg.style.display    = "block";

  /* Resetear búsqueda */
  const si = document.getElementById("searchInput");
  if (si) si.value = "";
  const sc = document.getElementById("searchClearBtn");
  if (sc) sc.classList.add("hidden");

  /* Mostrar footer */
  document.getElementById("footer").style.display = "block";
}


/* ════════════════════════════════════════════════════════════════════════
   RECURSOS
   ════════════════════════════════════════════════════════════════════════ */

async function loadResources() {
  const emptyEl  = document.getElementById("emptyMessage");
  const container = document.getElementById("resourcesContainer");

  // Estado de carga
  emptyEl.style.display = "none";
  container.innerHTML = "";

  showSkeletons();

  try {
    const res = await fetchWithTimeout(
      _endpoint,
      { credentials: "omit" },
      10_000
    );

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();

    if (!Array.isArray(data)) {
      throw new Error("Respuesta inválida de la API");
    }

    _resources = data;

    renderResources();

  } catch (err) {

    // Limpiar skeletons si falla
    container.innerHTML = "";

    if (err.name === "AbortError") {
      emptyEl.textContent =
        "El servidor tardó demasiado. Intentá de nuevo.";
    } else {
      emptyEl.textContent =
        "No se pudieron cargar los recursos.";
    }

    emptyEl.style.display = "block";

    console.warn("[INADI] loadResources:", err.message);
  }
}

function renderResources() {
  const container = document.getElementById("resourcesContainer");
  const empty     = document.getElementById("emptyMessage");

  while (container.firstChild) container.removeChild(container.firstChild);

  if (!Array.isArray(_resources)) {
    return;
  }

  if (_resources.length === 0) {
    empty.textContent = "No hay recursos agregados todavía.";
    empty.style.display = "block";
    return;
  }

  /* ── Filtrado por búsqueda: nombre Y dominio del link ─────── */
  const query   = _searchQuery.toLowerCase();
  const visible = query
    ? _resources.filter(r => {
        const nombre = String(r.nombre ?? "").toLowerCase();
        let   domain = "";
        try { domain = new URL(String(r.link ?? "")).hostname.toLowerCase(); } catch (_) {}
        return nombre.includes(query) || domain.includes(query);
      })
    : _resources;

  if (!visible.length) {
    empty.textContent   = `No se encontraron recursos para "${_searchQuery}".`;
    empty.style.display = "block";
    return;
  }

  empty.style.display = "none";

  visible.forEach((resource) => {
    if (typeof resource !== "object" || resource === null) return;

    const realIndex = _resources.indexOf(resource);
    const rawNombre = String(resource.nombre ?? "Sin nombre");
    const rawLink   = String(resource.link ?? "");

    const card = document.createElement("div");
    card.className = "resource-card";
    card.dataset.resourceIndex = realIndex; // para animar salida al borrar

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
      editBtn.onclick = () => openEditModal(realIndex);

      const deleteBtn = document.createElement("button");
      deleteBtn.textContent = "🗑️ Eliminar";
      deleteBtn.onclick = () => openDeleteModal(realIndex);

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

    card.style.setProperty("--i", container.children.length); // stagger
    container.appendChild(card);
  });

}

// Cierra todos los menús contextuales al hacer click fuera — registrado una sola vez
(function _initMenuDismiss() {
  document.addEventListener("click", () => {
    document.querySelectorAll(".resource-menu")
      .forEach(menu => menu.classList.add("hidden"));
  });
})();

/* ════════════════════════════════════════════════════════════════════
   MODAL — EDITAR RECURSO (solo admin)
   ════════════════════════════════════════════════════════════════════ */

function openEditModal(index) {
  if (!_isAdmin) return;
  _editingIndex = index;
  const resource = _resources[index];
  document.getElementById("editResourceName").value = resource.nombre ?? "";
  document.getElementById("editResourceLink").value = resource.link   ?? "";
  document.getElementById("editModalError").style.display = "none";
  document.getElementById("editModal").classList.remove("hidden");
  document.getElementById("editResourceName").focus();
}

function closeEditModal() {
  document.getElementById("editModal").classList.add("hidden");
  document.getElementById("editResourceName").value = "";
  document.getElementById("editResourceLink").value = "";
  document.getElementById("editModalError").style.display = "none";
  _editingIndex = null;
}

async function saveEditResource() {
  if (!_isAdmin || _editingIndex === null) return;

  const editErr = document.getElementById("editModalError");
  const name    = document.getElementById("editResourceName").value.trim();
  const link    = document.getElementById("editResourceLink").value.trim();

  /* ── Validaciones ──────────────────────────────────────────── */
  if (!name) {
    _showError(editErr, "El nombre no puede estar vacío.");
    return;
  }
  if (name.length > 120) {
    _showError(editErr, "El nombre es demasiado largo (máx. 120 caracteres).");
    return;
  }
  if (!link) {
    _showError(editErr, "El link no puede estar vacío.");
    return;
  }
  if (!Security.isSafeUrl(link)) {
    _showError(editErr, "El link debe ser una URL válida (https://).");
    return;
  }

  editErr.style.display = "none";

  const saveBtn = document.getElementById("saveEditModalBtn");
  saveBtn.disabled    = true;
  saveBtn.textContent = "Guardando…";

  try {
    const resp = await fetchWithTimeout(
      _endpoint,
      {
        method:      "POST",
        credentials: "omit",
        body: JSON.stringify({ action: "edit", index: _editingIndex, nombre: name, link }),
      },
      10_000
    );

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    closeEditModal();
    await loadResources();

  } catch (err) {
    if (err.name === "AbortError") {
      _showError(editErr, "El servidor tardó demasiado. Intentá de nuevo.");
    } else {
      _showError(editErr, "No se pudo editar el recurso. Intentá de nuevo.");
    }
    console.warn("[INADI] saveEditResource:", err.message);
  } finally {
    saveBtn.disabled    = false;
    saveBtn.textContent = "Guardar cambios";
  }
}

/* ════════════════════════════════════════════════════════════════════
   MODAL — CONFIRMAR ELIMINACIÓN (solo admin)
   ════════════════════════════════════════════════════════════════════ */

function openDeleteModal(index) {
  if (!_isAdmin) return;
  _pendingDeleteIndex = index;
  const resource = _resources[index];
  /* textContent — nunca innerHTML, previene XSS */
  document.getElementById("deleteResourceName").textContent = resource.nombre ?? "este recurso";
  document.getElementById("deleteModalError").style.display = "none";
  document.getElementById("deleteModal").classList.remove("hidden");
}

function closeDeleteModal() {
  document.getElementById("deleteModal").classList.add("hidden");
  document.getElementById("deleteModalError").style.display = "none";
  _pendingDeleteIndex = null;
}

async function confirmDeleteResource() {
  if (!_isAdmin || _pendingDeleteIndex === null) return;

  const index      = _pendingDeleteIndex;
  const deleteErr  = document.getElementById("deleteModalError");
  const confirmBtn = document.getElementById("confirmDeleteBtn");

  confirmBtn.disabled    = true;
  confirmBtn.textContent = "Eliminando…";

  /* Animar salida de la tarjeta mientras el fetch viaja al servidor */
  const card = document.querySelector(`[data-resource-index="${index}"]`);
  if (card) card.classList.add("card-removing");

  try {
    /* Esperar tanto el fetch como la duración de la animación (350 ms) */
    const [resp] = await Promise.all([
      fetchWithTimeout(
        _endpoint,
        {
          method:      "POST",
          credentials: "omit",
          body: JSON.stringify({ action: "delete", index }),
        },
        10_000
      ),
      new Promise(resolve => setTimeout(resolve, 350)),
    ]);

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    closeDeleteModal();
    await loadResources();

  } catch (err) {
    /* Revertir animación si el servidor falló */
    if (card) card.classList.remove("card-removing");
    _showError(deleteErr, "No se pudo eliminar el recurso. Intentá de nuevo.");
    console.warn("[INADI] confirmDeleteResource:", err.message);
  } finally {
    confirmBtn.disabled    = false;
    confirmBtn.textContent = "Eliminar";
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
    _showError(modalErr, "El link debe ser una URL válida (https://).");
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
