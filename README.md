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
| [Praneel Gupta]    | [IIB2024029]  | Cross-Site Scripting     | [Variant 2 — Reflected]  | [./CS_Reflected_XSS] |
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

## 1. Overview

This project demonstrates **Reflected Cross-Site Scripting (XSS)**, a web vulnerability in which user input is reflected in an HTTP response without proper output encoding, potentially allowing JavaScript to execute in the browser.

The project includes two versions:
- **Vulnerable:** Reflects user input without HTML encoding.
- **Secured:** Uses HTML output encoding to prevent the demonstrated payload from executing.

## 2. Technologies Used

- Node.js
- Express.js
- HTML, CSS, JavaScript

No database is required.

## 3. Project Structure

```text
03-Reflected-XSS/
├── server.js
├── package.json
├── src/
│   ├── routes/
│   │   ├── home.js
│   │   ├── vulnerable.js
│   │   └── secure.js
│   └── views/
│       ├── layout.js
│       ├── pages.js
│       └── utils.js
├── public/
│   ├── css/style.css
│   └── js/lab.js
├── test/
│   └── test.js
└── README.md
```

## 4. Installation and Setup

Make sure Node.js and npm are installed.

Open a terminal in this folder and run:

```bash
npm install
npm test
npm start
```

Open the website at:

- Home: http://127.0.0.1:3000/
- Vulnerable version: http://127.0.0.1:3000/vulnerable
- Secured version: http://127.0.0.1:3000/secure

## 5. Demonstration

1. Open the vulnerable version and submit a normal search query.
2. Enter the following harmless test payload and submit it:

   ```html
   <script>alert('Reflected XSS Detected!')</script>
   ```

3. Observe the JavaScript alert, demonstrating the vulnerability.
4. Submit the same payload on the secured version.
5. Observe that the payload is displayed as text instead of executing.

## 6. Root Cause and Mitigation

**Root cause:** In `src/views/pages.js`, the vulnerable page inserts the user query directly into the HTML response without encoding it.

**Mitigation:** The secured page uses the `encodeHTML()` function from `src/views/utils.js` before inserting the query into the HTML.

This function converts special characters such as `<` and `>` into HTML entities, preventing the demonstrated input from being interpreted as HTML in the results text.

Other possible defenses include framework auto-escaping, HTML sanitization, and Content Security Policy (CSP).

## 7. Testing

Run `npm test` to execute the automated tests. They check normal queries and test payloads against both routes and verify that the secured route encodes the input.

## 8. Safety Note

This application is intended only for educational testing on localhost. Do not deploy the intentionally vulnerable route on a public server.

## 9. Student Details

- **Name:** Praneel
- **Roll Number:** IIB2024029
- **Assignment:** Web Server Security
- **Vulnerability:** Cross-Site Scripting (XSS)
- **Variant:** Reflected XSS
