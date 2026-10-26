# SQL Injection — Authentication Bypass (Variant 1) — JavaScript / Node.js version

**Course:** Cyber Security
**Assignment:** Web Server Security — Exploitation and Mitigation of Four Vulnerability Categories
**Category covered here:** SQL Injection → Variant 1 (Authentication Bypass)
**Stack:** Node.js + Express + the built-in `node:sqlite` module (no native build/npm install needed for the DB driver)

---

## 1. How to run

### Requirements

- **Node.js 22.5+** (for the built-in `node:sqlite` module). Check with `node -v`.
- npm

### Steps

```bash
# 1. Unzip and enter the folder
cd sqli-auth-bypass-js

# 2. Install dependencies (just Express — the DB layer is built into Node)
npm install

# 3. Run the app
npm start
# (equivalent to: node --experimental-sqlite server.js)
```

Then open **http://127.0.0.1:5000/** in your browser. The database is
in-memory and reseeded fresh every time the server starts.

> If your Node version is newer than 22.11 or so, `node:sqlite` may no
> longer be flagged experimental and the `--experimental-sqlite` flag
> becomes a harmless no-op — `npm start` works either way.

The home page has two forms side by side:

- **`/login_vulnerable`** — the flawed implementation
- **`/login_secure`** — the same login, mitigated with a parameterized/prepared statement

Seeded accounts:

| username | password        | role  |
| -------- | --------------- | ----- |
| admin    | SuperSecret123! | admin |
| alice    | alicepw456      | user  |
| bob      | bobpw789        | user  |

---

## 2. (a) Vulnerable implementation

File: `server.js`, route `POST /login_vulnerable`:

```javascript
const query =
  "SELECT * FROM users WHERE username = '" +
  username +
  "' AND password = '" +
  password +
  "'";

const row = db.prepare(query).get();
```

The username and password typed into the form are concatenated directly
into the SQL text with no escaping and no parameter binding — the whole
string is then compiled and run as-is.

## 3. (b) Working exploit

With **any password**, enter one of the following as the **username**:

```
admin' --
```

or

```
' OR '1'='1
```

This resolves to the executed SQL (shown live on the result page):

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
```

`--` starts an SQL comment, so everything after `admin'` (including the
password check) is discarded. The query effectively becomes
`SELECT * FROM users WHERE username = 'admin'`, which returns the admin
row with no valid password supplied — **authentication bypass**.

The `' OR '1'='1` payload instead makes the `WHERE` clause always true,
so the first matching row (here, `admin`) is returned regardless of
the password.

Take a screenshot of this (or record it in the video) for item (b).

## 4. (c) Root cause

User-controlled input is concatenated directly into the SQL command
string instead of being treated as data. Because the database cannot
distinguish injected SQL syntax (`'`, `--`, `OR`, etc.) from the
programmer's intended query text, an attacker can change the **structure**
of the query — not just its values — and force the `WHERE` clause to
evaluate to true without knowing any real password.

## 5. (d) Mitigation implemented: parameterized / prepared statement

File: `server.js`, route `POST /login_secure`:

```javascript
const stmt = db.prepare(
  "SELECT * FROM users WHERE username = ? AND password = ?",
);
const row = stmt.get(username, password);
```

Here the SQL text (`... WHERE username = ? AND password = ?`) is
compiled once by SQLite as a **prepared statement**; `username` and
`password` are then bound as pure data values at execution time. The
database engine already has a fixed query plan before it ever sees the
values, so injected quotes/operators inside `username`/`password` can
never change the SQL grammar — they are matched literally against the
`username`/`password` columns instead.

**Proof it blocks the same payload:** submit `admin' --` (or
`' OR '1'='1`) with any password on `/login_secure`. The login fails,
and the result page shows the query template was unchanged
(`username = ? AND password = ?`), with the raw payload bound as a
literal string value that matches no row. Take a screenshot of this for
item (d).

 

## 6. Project structure

```
sqli-auth-bypass-js/
├── server.js               # Express app: vulnerable + secure login routes
├── package.json
├── README.md                 # this file
├── public/
│   └── index.html            # home page with both login forms           
```
