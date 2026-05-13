# 🎮 INADI – GameMaker · Portal de Recursos Educativos

Portal web educativo desarrollado para el **Instituto Nacional de Informática (INADI)**,
diseñado para centralizar y compartir recursos de aprendizaje de GameMaker Studio 2 con
estudiantes y docentes del instituto.

## [Acceso al Portal](https://mrluksr.github.io/Inadi-Recursos/)

---

## ✨ Características

- **Autenticación por nombre** con lista de miembros autorizados y sistema de roles (Admin / Estudiante).
- **Panel de recursos** con tarjetas interactivas, búsqueda en tiempo real y animaciones.
- **Gestión de recursos** (añadir, editar, eliminar) restringida al rol Admin.
- **Backend serverless** integrado con Google Apps Script + Google Sheets como base de datos.
- **Seguridad reforzada**: CSP estricta, hash SHA-256 salteado para credenciales, sin JS inline,
  protección MIME sniffing, Permissions Policy y caché deshabilitada.
- **Diseño responsive** con glassmorphism, gradientes animados y modo de movimiento reducido.

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|---|---|
| Frontend | HTML5 · CSS3 (Vanilla) · JavaScript (ES2022) |
| Tipografía | Google Fonts – Inter |
| Backend | Google Apps Script (Web App) |
| Base de datos | Google Sheets |
| Hosting | GitHub Pages |
| Control de versiones | Git / GitHub |

---

## 📁 Estructura del proyecto

```
ProyectoLucasINADI/
├── Inadi-Recursos/
│   ├── index.html        # Estructura HTML principal (login + panel + modal)
│   ├── styles.css        # Sistema de diseño y estilos (sin frameworks externos)
│   ├── app.js            # Lógica de la aplicación (auth, recursos, UI)
│   ├── config.js         # Configuración de la app (hashes, miembros, endpoint)
│   ├── Logo Inadi con Brillo.png
│   └── Logo Inadi Link.png
├── LICENSE               # MIT
└── README                # Este archivo
```

---

## 🚀 Uso local

El proyecto es completamente estático. Podés abrirlo con cualquier servidor local:

```bash
# Con Live Server (VS Code) — recomendado
# Abrir index.html y presionar "Go Live"

# Con Python
cd Inadi-Recursos
python3 -m http.server 5500
# → http://localhost:5500
```

> ⚠️ No abrir `index.html` directamente como archivo (`file://`) ya que el CSP
> bloqueará la conexión al backend de Google Apps Script.

---

## 🔐 Seguridad

- Credenciales almacenadas como hashes SHA-256 salteados (sin texto plano en el repo).
- Content Security Policy que bloquea scripts, estilos e imágenes de origen no autorizado.
- `noindex, nofollow` en meta robots para evitar indexación pública.
- Sin dependencias externas de JavaScript (zero third-party scripts).

Para más detalles, ver los comentarios en `index.html` y `app.js`.

---

## 👥 Créditos

| Rol | Persona |
|---|---|
| Desarrollo frontend & backend | **Lucas Rangel** |
| Soporte técnico & seguridad| **Thiago Rafael Sosa Olivera** |

Este proyecto utiliza componentes y recursos bajo **licencia MIT**.
Ver [`LICENSE`](./LICENSE) para más información.

---

## 📄 Licencia

MIT © 2026 Lucas David Rangel Silveira
