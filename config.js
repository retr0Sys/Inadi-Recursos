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

  /* ── HASH DEL ADMINISTRADOR ───────────────────────────────────────────
     PBKDF2-SHA256( salt, nombre, 200 000 iter ) — generado offline.
     Algoritmo: hashlib.pbkdf2_hmac('sha256', name.encode(), salt, 200000)
     ──────────────────────────────────────────────────────────────────── */
  const _adminHash = "898d128f783fe3b2fb901daec23f9890649449976f2b45f055ba654b9cb40b6c";

  return {
    getEndpoint: _buildEndpoint,
    getSalt: _getSalt,
    getAdminHash: () => _adminHash,
    getPbkdf2Iters: () => PBKDF2_ITERATIONS,
  };

})());
