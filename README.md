# Web Server Security — Exploitation and Mitigation of Four Vulnerability Categories

## 1. Overview

This repository is our group's submission for the assignment on Web Server
Security. As a group, we picked one variant each from four vulnerability
categories covered in class — **SQL Injection**, **OS Command Injection**,
**Cross-Site Scripting (XSS)**, and **Cross-Site Request Forgery (CSRF)** —
and for each variant we:

1. Built a small, intentionally vulnerable local web application.
2. Exploited the vulnerability with a working payload, with evidence
   (screenshots / video).
3. Implemented one mitigation of our choice and showed the same payload
   now failing against the fixed code.

---

## 2. Ownership declaration 

| Member name | Roll number | Category               | Variant implemented                          | Folder |
|-------------|-------------|-------------------------|-----------------------------------------------|--------|
| Priyanshu    | IIB2024037  | SQL Injection            | Variant 1 — Authentication Bypass             | [`/SQL-Injection-Auth-Bypass`](./sqli-auth-bypass-js) |
| [Name 2]    | [Roll No.]  | OS Command Injection     | [Variant 1 — In-band / Variant 2 — Blind]     | [`/<folder-name>`](./) |
| [Name 3]    | [Roll No.]  | Cross-Site Scripting     | [Variant 1 — Stored / Variant 2 — Reflected]  | [`/<folder-name>`](./) |
| [Name 4]    | [Roll No.]  | Cross-Site Request Forgery | [Variant 1 — GET-based / Variant 2 — POST-based] | [`/<folder-name>`](./) |

---

## 3. How to run each exploit

Each member's application is self-contained in its own folder, with its
own dependencies and its own run instructions in that folder's README.
General steps:

```bash
cd <member-folder>
# follow the "How to run" section in that folder's README.md
```

### SQL Injection — Authentication Bypass

```bash
cd SQL-Injection-Auth-Bypass
npm install
npm start
# open http://127.0.0.1:5000/
```
- On the **vulnerable** login form, use username `admin' --` with any
  password → logs in as admin without the real password.
- On the **secure** login form, the same payload fails, because the
  query uses parameterized placeholders instead of string concatenation.

### OS Command Injection

```bash
cd <os-command-injection-folder>
# fill in install + run steps once this part is built
```
- *(fill in: the payload used, and which endpoint/form to try it on)*

### Cross-Site Scripting (XSS)

```bash
cd <xss-folder>
# fill in install + run steps once this part is built
```
- *(fill in: the payload used, and which endpoint/form to try it on)*

### Cross-Site Request Forgery (CSRF)

```bash
cd <csrf-folder>
# fill in install + run steps once this part is built
```
- *(fill in: the payload/forged request used, and which endpoint to try it on)*
