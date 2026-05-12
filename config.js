/**
 * INADI Recursos — Configuración
 * No contiene credenciales, URLs ni nombres en texto plano.
 */

const _cfg = Object.freeze((function () {

  /* ── API URL ──────────────────────────────────────────────────────────
     URL dividida en 3 segmentos Base64, almacenados fuera de orden.
     Se reconstruye en runtime con atob() + sort por índice.
     ──────────────────────────────────────────────────────────────────── */
  const _s = [
    [0, "aHR0cHM6Ly9zY3JpcHQuZ29vZ2xlLmNvbS9tYWNyb3Mv"],
    [1, "cy9BS2Z5Y2J4em1aOUJFcGtHVlU5TTJqY255Nm40Nl9jNktULW1seFZmQVBQZnM1VmgxWndsS2hoSW9uV21zdUZOWDllQ1NvSEg="],
    [2, "L2V4ZWM="],
  ];

  function _d(b64) {
    try { return atob(b64); } catch (_) { return ""; }
  }

  function _buildEndpoint() {
    return _s.slice().sort((a, b) => a[0] - b[0]).map(x => _d(x[1])).join("");
  }

  /* ── SALT ─────────────────────────────────────────────────────────────
     Salt aleatorio de 32 bytes generado offline con secrets.token_hex(32).
     Almacenado en Base64. Se usa como salt para PBKDF2:
       PBKDF2-SHA256( password=nombre, salt=salt_bytes, iter=200 000 )
     Sin conocer el salt, los hashes no pueden revertirse por diccionario.
     ──────────────────────────────────────────────────────────────────── */
  const _saltB64 = "ZmNkNDNjYTJkNGEzODNmNTRkOGM4MmNiNDA0MTU2ZWY4MzU3NzY1MTZkNTVhZjU2OGQ3NzgxYjZmZWEyZWY0OQ==";

  function _getSalt() {
    try { return atob(_saltB64); } catch (_) { return ""; }
  }

  /* ── ITERACIONES PBKDF2 ───────────────────────────────────────────────
     NIST SP 800-132 recomienda ≥ 1000; OWASP recomienda ≥ 210 000 para
     PBKDF2-SHA256 en 2025. Usamos 200 000 como compromiso rendimiento/
     seguridad para una SPA (login tardará ~150-200 ms en hardware moderno).
     ──────────────────────────────────────────────────────────────────── */
  const PBKDF2_ITERATIONS = 200_000;

  /* ── HASHES DE USUARIOS ───────────────────────────────────────────────
     PBKDF2-SHA256( salt, nombre, 200 000 iter ) — generados offline.
     Ningún nombre original aparece en este archivo.
     Algoritmo: hashlib.pbkdf2_hmac('sha256', name.encode(), salt, 200000)
     ──────────────────────────────────────────────────────────────────── */
  const _h = [
    "57ae734083d23950f279b0c1279741fe914d765fb0dea11daab78019eac5ccc8",
    "1224566ab11c5b357f5a2fa2234356084d7aa3490482be8ffe6bb326a91320c4",
    "20b978840aada171e7f5fda3eea2cbd410cef16835fafa5ab5c31f33bf30c89c",
    "be22a0ddea24209d184987f42fe6d11067b773d38c902a21e8c42fe50f6a7994",
    "3b3aa363cbb7566d8e530ed5745591d7d4c59b7be76eafaca3c7d08cae30b557",
    "e5eeb24d465113fe1a98a1b3fa7a71995726265dcb139be9116dddff4dd4d3cf",
    "977ffd3a008059da69d98f7a8f14001b97e264fdea4590f1d33db36d9c8ea989",
    "b721356966482e6aff8b710d705e242e0c8bf40ecdf6341cbc9e8c864fcc8f37",
    "898d128f783fe3b2fb901daec23f9890649449976f2b45f055ba654b9cb40b6c", // admin
  ];

  // Hash del administrador (último de la lista)
  const _adminHash = "898d128f783fe3b2fb901daec23f9890649449976f2b45f055ba654b9cb40b6c";

  return {
    getEndpoint: _buildEndpoint,
    getSalt: _getSalt,
    getUserHashes: () => [..._h],
    getAdminHash: () => _adminHash,
    getPbkdf2Iters: () => PBKDF2_ITERATIONS,
  };

})());
