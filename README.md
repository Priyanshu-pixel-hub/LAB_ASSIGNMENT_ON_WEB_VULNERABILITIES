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
| Priyanshu    | IIB2024037  | SQL Injection            | Variant 1 — Authentication Bypass             | [`/SQL-Injection-Auth-Bypass`](./SQL-Injection-Auth-Bypass) |
| Haneesh   | IIB2024026  | OS Command Injection     | Variant 1 — In-band     | [`/cs_lab_IIB2024026/fixed_app/server.js`](./cs_lab_IIB2024026) |
| [Praneel Gupta]    | [IIB2024029]  | Cross-Site Scripting     | [Variant 2 — Reflected]  |  [`CS_Reflected_XSS`](./CS_Reflected_XSS/) |
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

# Web Server Security Lab: OS Command Injection (In-Band)

This project demonstrates an **In-Band OS Command Injection** vulnerability on a web server, along with its proper security fix.

## Project Structure

```text
.
├── vul_app/       # Vulnerable application (Port 3000)
│   ├── server.js
│   ├── package.json
│   └── public/
│       └── index.html
└── fixed_app/     # Secured application (Port 3001)
    ├── server.js
    ├── package.json
    └── public/
        └── index.html

```

---

## 1. Vulnerable Application (`vul_app`)

The application provides a basic network diagnostic ping utility.

### Vulnerable Code Path

In `vul_app/server.js`:

```javascript
app.post('/api/ping', (req, res) => {
    const targetHost = req.body.host;
    
    // User input concatenated directly into system command string
    const command = `ping ${targetHost}`;

    // Spawns system shell (/bin/sh or cmd.exe)
    exec(command, (error, stdout, stderr) => {
        res.json({
            executedCommand: command,
            output: stdout || stderr || (error ? error.message : 'No output')
        });
    });
});

```

### Root Cause

1. **Unsanitized String Concatenation:** The backend takes raw user input (`req.body.host`) and concatenates it straight into a shell command.
2. **Shell Invocation (`exec`):** The `exec()` function launches a system shell interpreter. This allows shell control characters (like `;`, `|`, or `&&`) to chain arbitrary operating system commands.
3. **In-Band Output:** Standard output (`stdout`) and error output (`stderr`) are sent directly back inside the HTTP JSON response, exposing sensitive system data on the webpage.

### Working Exploits

#### Exploit 1: List Files (`ls -la`)

* **Payload:** `127.0.0.1; ls -la`
* **Constructed Command:** `ping 127.0.0.1; ls -la`
* **Result:** The shell pings local loopback, then immediately lists directory contents and returns them in the browser output.

#### Exploit 2: Read System Users (`cat /etc/passwd`)

* **Payload:** `127.0.0.1; cat /etc/passwd`
* **Constructed Command:** `ping 127.0.0.1; cat /etc/passwd`
* **Result:** The server dumps host user accounts directly to the response window.

#### Exploit 3: Check Current User (`whoami`)

* **Payload:** `127.0.0.1 | whoami`
* **Constructed Command:** `ping 127.0.0.1 | whoami`
* **Result:** Pipes ping output to `whoami`, returning server user privileges (e.g., `www-data`).

---

## 2. Fixed Application (`fixed_app`)

The secured version prevents command injection using strict input validation and parameterized execution.

### Secured Code Path

In `fixed_app/server.js`:

```javascript
app.post('/api/ping', (req, res) => {
    const targetHost = req.body.host;

    // 1. Strict Allow-List Validation
    const validHostPattern = /^([a-zA-Z0-9.-]+)$/;
    if (!validHostPattern.test(targetHost)) {
        return res.status(400).json({ error: 'Security Exception: Malicious input detected!' });
    }

    // 2. Parameterized Execution (No Command Shell)
    const binary = 'ping';
    const args = [targetHost];

    execFile(binary, args, (error, stdout, stderr) => {
        res.json({
            output: stdout || stderr
        });
    });
});

```

### How the Fix Works

* **Strict Allow-Listing:** A regular expression check (`/^([a-zA-Z0-9.-]+)$/`) validates input at the application boundary. Any input with spaces, semicolons, pipes, or command metacharacters is immediately rejected with HTTP `400`.
* **Parameterized Execution (`execFile`):** Instead of `exec()`, we use `execFile()`. This executes the `ping` binary directly without launching a command shell. `targetHost` is passed inside an argument array vector (`args`), forcing the operating system to treat the input strictly as literal string data rather than executable directives.

---

## 3. Alternative Mitigation Options (Theory)

Beyond argument vectors and allow-listing, other defense controls include:

* **Avoid System Calls / Use Native APIs:** Replace external command calls entirely with built-in language modules (such as Node.js `net.Socket` or Python `socket`) to test network connectivity safely.
* **Principle of Least Privilege:** Run the web application server under a restricted system account (e.g., `www-data`) with minimal OS privileges to restrict what files or binaries an attacker can access if execution occurs.

---

## Running the Apps Locally

### Run Vulnerable App

```bash
cd vul_app
npm install
npm start
# Runs on http://localhost:3000

```

### Run Fixed App

```bash
cd fixed_app
npm install
npm start
# Runs on http://localhost:3001

```

```

```

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

# Reflected XSS Security Demonstration

Demonstrates **Reflected Cross-Site Scripting (XSS)** using a vulnerable and a secured web page.

- **Technologies:** Node.js, Express.js, HTML, CSS, JavaScript.
- **Vulnerable version:** Reflects user input without HTML encoding.
- **Secured version:** Uses `encodeHTML()` to prevent script execution.
- **Testing:** Run `npm install`, `npm test`, and `npm start`.
- **Access:** `http://127.0.0.1:3000/`

**Mitigation:** HTML output encoding prevents user input from being interpreted as executable HTML.

**Safety:** For educational use on localhost only.

**Student:** Praneel | **Roll No.:** IIB2024029  
**Assignment:** Web Server Security | **Variant:** Reflected XSS