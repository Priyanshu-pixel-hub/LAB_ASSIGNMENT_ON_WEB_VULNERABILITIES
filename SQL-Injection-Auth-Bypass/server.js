/**
 * SQL Injection - Authentication Bypass (Variant 1)
 * Cyber Security (IT-30001) Assignment - Web Server Security
 * JavaScript / Node.js version (Express + built-in node:sqlite)
 *
 * Exposes TWO login endpoints so the same exploit payload can be
 * demonstrated against both the vulnerable code path and the
 * mitigated code path, side by side:
 *
 *   POST /login_vulnerable  -> builds SQL with raw string concatenation (FLAWED)
 *   POST /login_secure      -> uses a parameterized/prepared statement (MITIGATED)
 *
 * Run it, open http://127.0.0.1:5000/ and try the payload against both.
 *
 * THIS APP IS INTENTIONALLY VULNERABLE. Run it only on localhost / your
 * own machine for the purpose of this assignment demo. Do not deploy it
 * to the public internet or test anyone else's infrastructure.
 */

const express = require("express");
const path = require("path");
const { DatabaseSync } = require("node:sqlite"); // built into Node.js 22+

const app = express();
const PORT = 5000;

app.use(express.urlencoded({ extended: true })); // parse HTML form POSTs
app.use(express.static(path.join(__dirname, "public")));

// --------------------------------------------------------------------------
// In-memory SQLite database, seeded fresh every time the server starts.
// --------------------------------------------------------------------------
const db = new DatabaseSync(":memory:");

function initDb() {
  db.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    );
  `);
  const insert = db.prepare(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
  );
  insert.run("admin", "SuperSecret123!", "admin");
  insert.run("alice", "alicepw456", "user");
  insert.run("bob", "bobpw789", "user");
  console.log("[+] In-memory database seeded with demo users.");
}
initDb();

// --------------------------------------------------------------------------
// HTML helpers (kept dependency-free: no template engine needed)
// --------------------------------------------------------------------------
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function resultPage(mode, query, success, message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login Result - ${escapeHtml(mode)}</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 760px; margin: 40px auto; color: #222; }
  .ok { color: #27ae60; font-weight: bold; }
  .fail { color: #c0392b; font-weight: bold; }
  pre { background: #222; color: #eee; padding: 14px; border-radius: 6px; white-space: pre-wrap; word-break: break-all; }
  a { display: inline-block; margin-top: 20px; }
</style>
</head>
<body>
  <h1>Mode: ${escapeHtml(mode)}</h1>
  <p>Actual SQL executed against the database:</p>
  <pre>${escapeHtml(query)}</pre>
  <p class="${success ? "ok" : "fail"}">${escapeHtml(message)}</p>
  <a href="/">&larr; Back to demo</a>
</body>
</html>`;
}

// --------------------------------------------------------------------------
// Routes
// --------------------------------------------------------------------------

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---- (a) VULNERABLE implementation ---------------------------------------
// Root cause (c): user-controlled input (username, password) is concatenated
// directly into the SQL string instead of being passed as bound parameters.
// This lets an attacker inject SQL meta-characters (', --, OR 1=1, etc.)
// that change the *structure* of the query, not just its data -> the
// WHERE clause can be made to always evaluate true, bypassing the
// password check entirely (authentication bypass).
app.post("/login_vulnerable", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";

  const query =
    "SELECT * FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";

  let row;
  try {
    row = db.prepare(query).get(); // query string built by concatenation, then run as-is
  } catch (err) {
    return res.send(resultPage("VULNERABLE", query, false, `DB error: ${err.message}`));
  }

  if (row) {
    res.send(
      resultPage(
        "VULNERABLE",
        query,
        true,
        `Login SUCCESS - logged in as '${row.username}' (role: ${row.role})`
      )
    );
  } else {
    res.send(
      resultPage("VULNERABLE", query, false, "Login FAILED - invalid username or password")
    );
  }
});

// ---- (d) MITIGATION implemented: parameterized / prepared statement ------
// The username/password are passed as bound parameters ("?"), so the
// database driver sends them to the DB engine separately from the SQL
// command text. The input is always treated as DATA, never as part of
// the SQL grammar, so injected quotes/operators cannot change the query
// structure. The exact same payload that worked above now fails safely.
app.post("/login_secure", (req, res) => {
  const username = req.body.username || "";
  const password = req.body.password || "";

  const queryShown = `SELECT * FROM users WHERE username = ? AND password = ?  -- params: (${JSON.stringify(
    username
  )}, ${JSON.stringify(password)})`;

  let row;
  try {
    const stmt = db.prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    row = stmt.get(username, password);
  } catch (err) {
    return res.send(resultPage("SECURE", queryShown, false, `DB error: ${err.message}`));
  }

  if (row) {
    res.send(
      resultPage(
        "SECURE",
        queryShown,
        true,
        `Login SUCCESS - logged in as '${row.username}' (role: ${row.role})`
      )
    );
  } else {
    res.send(
      resultPage(
        "SECURE",
        queryShown,
        false,
        "Login FAILED - invalid username or password (injection payload neutralised)"
      )
    );
  }
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`[+] Server running at http://127.0.0.1:${PORT}/`);
});
