# Web Server Security — Exploitation and Mitigation of Four Vulnerability Categories

## 1. Overview

This repository is our group's submission for the Web Server Security assignment. We selected one variant from each of four vulnerability categories covered in class — **SQL Injection**, **OS Command Injection**, **Cross-Site Scripting (XSS)**, and **Cross-Site Request Forgery (CSRF)**.

For each category, we built a local demonstration, tested the vulnerability, and implemented a mitigation to show how the attack can be prevented.

---

## 2. Ownership Declaration

| Member name | Roll number | Category | Variant implemented | Folder |
|---|---|---|---|---|
| Priyanshu | IIB2024037 | SQL Injection | Variant 1 — Authentication Bypass | [`SQL-Injection-Auth-Bypass`](./SQL-Injection-Auth-Bypass) |
| Haneesh | IIB2024026 | OS Command Injection | Variant 1 — In-band | [`cs_lab_IIB2024026`](./cs_lab_IIB2024026) |
| Praneel Gupta | IIB2024029 | Cross-Site Scripting (XSS) | Variant 2 — Reflected XSS | [`CS_Reflected_XSS`](./CS_Reflected_XSS/) |
| Vikas Thatikonda | IIB2024036 | Cross-Site Request Forgery (CSRF) | GET-based forged action and CSRF token defense | [`IIB2024036-CSRF`](./IIB2024036-CSRF) |

---

## 3. How to Run Each Demonstration

Each member's application is kept in its own folder with its own README and run instructions.

### SQL Injection — Authentication Bypass

```bash
cd SQL-Injection-Auth-Bypass
npm install
npm start
# Open http://127.0.0.1:5000/
```

- **Vulnerable version:** The payload `admin' --` bypasses authentication.
- **Secure version:** Parameterized SQL queries prevent the same payload from bypassing login.

### OS Command Injection — In-band

**Run the vulnerable app:**

```bash
cd cs_lab_IIB2024026/vul_app
npm install
npm start
# Runs on http://localhost:3000
```

**Run the fixed app** in a separate terminal:

```bash
cd cs_lab_IIB2024026/fixed_app
npm install
npm start
# Runs on http://localhost:3001
```

- **Vulnerable version:** Unsanitized input is added to a shell command, allowing command injection.
- **Fixed version:** Input validation and `execFile()` prevent shell metacharacters from being executed as commands.

### Cross-Site Scripting (XSS) — Reflected

```bash
cd CS_Reflected_XSS
npm install
npm start
# Open http://127.0.0.1:3000/
```

- **Vulnerable version:** User input is reflected without HTML encoding.
- **Secure version:** HTML output encoding prevents input from being interpreted as executable HTML.

### Cross-Site Request Forgery (CSRF) — GET-based forged action

The project demonstrates how an attacker webpage can trigger an unwanted email change in a logged-in user's Student Portal.

**Terminal 1 — Student Portal:**

```bash
cd IIB2024036-CSRF
npm install
npm start
# Open http://localhost:3000/login
```

**Terminal 2 — Attacker Wi-Fi website:**

```bash
cd IIB2024036-CSRF
npm run start:attacker
# Open http://localhost:4000
```

Log in using the demo credentials shown in the CSRF project's README. Note the original email, then click **Connect Now** on the attacker website. In Vulnerable Mode, the email changes to `attacker@evil.com`.

**To test the mitigation:** Stop the Student Portal and restart it with:

```bash
npm run start:secure
```

Keep the attacker server running. In Secure Mode, the forged GET request is rejected with **405 Method Not Allowed**. A POST request without a valid CSRF token is rejected with **403 Forbidden**, while a legitimate update with a valid token succeeds.

Run the CSRF project's automated tests with:

```bash
npm test
```

- **Root cause:** The vulnerable endpoint changes account data through GET without CSRF token validation.
- **Mitigation:** The secure endpoint requires POST and validates a session-bound synchronizer CSRF token.

---

## 4. Safety Note

These projects are intended for educational demonstrations in a local environment only. Do not deploy the intentionally vulnerable applications on a public network.
