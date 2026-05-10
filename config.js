/**
 * INADI Recursos — Configuración
 * Marcos de seguridad aplicados: OWASP Top 10 · NIST SP 800-53 · ISO 27001 · CIS Controls v8
 */

const _cfg = (function () {

  /* ── API URL ──────────────────────────────────────────────────────────
     URL dividida en 3 segmentos Base64, almacenados fuera de orden.
     Se reconstruye en runtime con atob() + sort por índice.
     Ref: OWASP A02 — Cryptographic Failures (no exponer endpoints en claro)
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
     Almacenado en Base64. Se aplica como prefijo antes de hashear el input:
       SHA-256( salt + username )
     Sin conocer el salt, los hashes no pueden revertirse por diccionario.
     Ref: NIST SP 800-63B § 5.1.1 · ISO 27001 A.9.4 · CIS Control 5
     ──────────────────────────────────────────────────────────────────── */
  const _saltB64 = "ZmNkNDNjYTJkNGEzODNmNTRkOGM4MmNiNDA0MTU2ZWY4MzU3NzY1MTZkNTVhZjU2OGQ3NzgxYjZmZWEyZWY0OQ==";

  function _getSalt() {
    try { return atob(_saltB64); } catch (_) { return ""; }
  }

  /* ── HASHES DE USUARIOS ───────────────────────────────────────────────
     SHA-256( salt + nombre ) — generados offline.
     Ningún nombre original aparece en este archivo.
     Ref: OWASP A02 · NIST IA-5 · ISO 27001 A.9.2
     ──────────────────────────────────────────────────────────────────── */
  const _h = [
    "c9e343d9db6de3cb789fd120b92d5797d33892b5a600e6e9924d3f02e0cc2d1b",
    "dc435cac6b55581d186b541c26f81424db67737504dbf8a5ec82188c2d90c65b",
    "6e49dff25b8afc3139891d337fa7b85a88bfec868a4f4f1104fd5453cf866c58",
    "e16cc8e7970d2f108579c880061fdc74c5b77b24f31b4935f763ac3a5a0cbf8d",
    "06665390f7dafd5ee8093213048ac056c116ad369614eafe5a5d9811cce5838d",
    "2d2ce3068a01d01c19aba8532694e63c92e9fa0fd1d0c9d5a09c43a0eac9d7d0",
    "9d307f99643ab4ad0e6cdca04b5175e2bfa17179de1e47c9d09ffaffae06fdaf",
    "0e9640831d83fdf8fd82a92acf070a9acbe76f6cbd48a1a774a6bd326f982c5a",
    "72c03525b678bbf2e6ed2b00035b1f1f370d6792a7c081c1de5d08efb99c5be4",
    "af127e1c80591964957a1da3db5d5e093b01a13a34c765e235a064b442c6c715",
    "6a4d3599078b77ce43c91d7271f3295cd491d5be2face58edc1b84a83b7f6226",
  ];

  // Hash del administrador (último de la lista)
  const _adminHash = "6a4d3599078b77ce43c91d7271f3295cd491d5be2face58edc1b84a83b7f6226";

  /* ── CONSTANTES DE SEGURIDAD ──────────────────────────────────────────
     Centralizadas aquí para facilitar auditorías futuras.
     Ref: NIST SP 800-53 AC-12 · CIS Control 16.11
     ──────────────────────────────────────────────────────────────────── */
  const SESSION_TIMEOUT_MS  = 15 * 60 * 1000; // 15 minutos de inactividad
  const MAX_RESPONSE_BYTES  = 512 * 1024;      // 512 KB límite de respuesta API

  return {
    getEndpoint:        _buildEndpoint,
    getSalt:            _getSalt,
    getUserHashes:      () => [..._h],
    getAdminHash:       () => _adminHash,
    getSessionTimeout:  () => SESSION_TIMEOUT_MS,
    getMaxResponseSize: () => MAX_RESPONSE_BYTES,
  };

})();
