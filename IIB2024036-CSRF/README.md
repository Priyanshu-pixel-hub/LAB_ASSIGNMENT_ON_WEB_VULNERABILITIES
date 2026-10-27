# CSRF Demo – Cross-Site Request Forgery Lab

> **⚠️ Educational use only.** This application is intentionally vulnerable and must
> never be deployed on a public network. It is designed for a university Cyber Security
> assignment to demonstrate and then fix a GET-based CSRF vulnerability.

---

## 📁 Project Structure

```
IIB2024036-CSRF/
├── package.json
├── server.js              ← Victim app: Student Portal (port 3000)
├── attacker-server.js     ← Attacker's static server (port 4000)
├── attacker/
│   ├── index.html         ← Attacker Wi-Fi page (GET-based exploit)
│   └── styles.css         ← Wi-Fi page styling
├── middleware/
│   └── authentication.js  ← Session auth & CSRF token generator
├── routes/
│   ├── vulnerable.js      ← State-changing GET endpoint
│   └── secure.js          ← Token-protected POST endpoint (405 for GET)
├── views/                 ← Student Portal frontend (login, dashboard)
├── public/                ← Victim app styling
└── README.md
```

---

## 🚀 Installation & Running

### 1. Install dependencies

```bash
npm install
```
<!-- .gitignore -->

**Repository Setup**

The repository includes a **.gitignore** file to exclude generated files and dependencies from version control, such as:

- `node_modules/`
- `dist/`
- `.env` files
- IDE folders (`.idea/`, `.vscode/`)
- Log files (`npm-debug.log`, `yarn-debug.log`, `yarn-error.log`)

This helps keep the repository clean and avoids committing large, unnecessary files.


### 2. Run in **Vulnerable** mode (default)

Open **two** terminals:

```bash
# Terminal 1 – Victim app (Student Portal)
npm start
# → http://localhost:3000

# Terminal 2 – Attacker server (Wi-Fi Portal)
npm run attacker
# → http://localhost:4000
```

*(Note: `npm run start:attacker` can also be used for Terminal 2)*

### 3. Run in **Secure** mode

```bash
# Terminal 1 – Victim app (secure)
npm run start:secure
# → http://localhost:3000 (with SECURE banner)

# Terminal 2 – Attacker server (unchanged)
npm run attacker
# → http://localhost:4000
```

### 4. Run automated test suite

```bash
npm test
# → Executes all 14 automated security and functional test cases
```

---

## 🧪 Step-by-Step Demo

### A. Vulnerable Mode

1. Start both servers in **vulnerable** mode (see above).
2. Open **http://localhost:3000** in your browser. Log in as **student / Password123!**.
3. Note the registered email on the dashboard: **alex.johnson@university.edu**.
4. **Without logging out**, open a new tab and visit **http://localhost:4000**.
5. You see a harmless-looking "Free Public Wi-Fi" page – but behind the scenes clicking **Connect Now** triggers `GET /api/vulnerable/change-email?email=attacker@evil.com`.
6. Go back to the dashboard tab and **refresh**. The email is now **attacker@evil.com**.
7. Check the victim server terminal – you'll see the state change was logged:
   `[LAB AUDIT] | Endpoint: /api/vulnerable/change-email | Method: GET | Authenticated: YES | Email Changed: YES`
8. Click **🔄 Reset Email to Default** to restore the original state.

### B. Secure Mode

1. Stop the victim server. Restart it with `npm run start:secure`.
2. Log in as **student / Password123!** again. Note the green **🔒 MODE: SECURE** banner.
3. Open **http://localhost:4000** in a new tab and click **Connect Now**.
4. Go back and refresh the dashboard – **email is still alex.johnson@university.edu**. The GET was blocked with **405 Method Not Allowed** (`Allow: POST`).
5. If an attacker attempts an unauthorized cross-site POST form without a token, the server returns **403 Forbidden** (`CSRF_TOKEN_MISSING`).
6. Back on the dashboard, use the **legitimate email update form** to change the email – it **succeeds (200 OK)** because the form includes the correct `_csrf` / `x-csrf-token`.

---

## 🔍 Root Cause

The vulnerable app uses a **state-changing GET request** (`GET /api/vulnerable/change-email`) that relies
solely on the session cookie for authentication. Because browsers attach cookies to
every request to a domain — even requests initiated by a different origin — an attacker
page can silently trigger the email update using a link, hidden `<img>`, or `<iframe>`.

---

## 🛡️ Mitigations Implemented

| Defence | How it works in this demo |
|---|---|
| **Synchronizer Token** | A random 32-byte hex token is generated per session, embedded in the request form/header as `_csrf` / `x-csrf-token`, and verified on `POST /api/secure/change-email` using `crypto.timingSafeEqual`. |
| **Reject GET for state changes** | `GET /api/secure/change-email` returns `405 Method Not Allowed` with header `Allow: POST` in secure mode. |
| **SameSite cookie defense** | Session cookie is configured with `sameSite: 'lax'` (or `'strict'`), preventing cross-site state-changing requests from sending session cookies. |

### Other Mitigations (Theory)

- **SameSite Cookies (`Lax` / `Strict`):** Modern browsers default to `SameSite=Lax`, which blocks cookies on cross-site sub-requests (images, iframes) but still allows them on top-level navigations. `Strict` blocks cookies on all cross-site requests entirely. While effective as defense-in-depth, they should not be the sole protection because older browsers may not support them.

- **Re-authentication for Sensitive Actions:** Requiring the user to re-enter their password (or complete a CAPTCHA / 2FA challenge) before executing high-value operations like fund transfers or email changes ensures that even a forged request cannot succeed without active user participation.

- **Avoiding State-Changing GET Requests:** The HTTP specification states that GET should be safe and idempotent. Using POST/PUT/DELETE for state changes is a fundamental design principle that eliminates the simplest class of CSRF attacks (via `<img>`, `<script src>`, etc.), though POST-based CSRF is still possible without tokens.

---

## 👥 Ownership Declaration

| Member Name | Roll Number | Category | Variant Implemented |
|---|---|---|---|
| Vikas Thatikonda | IIB2024036 | CSRF | GET-based forged action |

---

## 📚 References

- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- MDN: SameSite cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
