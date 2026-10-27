/**
 * server.js
 * 
 * Simple Express Server for Student Portal CSRF Assignment
 * Variant 1: GET-Based Forged Action & Synchronizer Token Mitigation
 */

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const path = require("path");

const authRoutes = require("./routes/auth");
const vulnerableRoutes = require("./routes/vulnerable");
const secureRoutes = require("./routes/secure");
const labRoutes = require("./routes/lab");
const { requireAuth, getLabMode } = require("./middleware/authentication");

const app = express();
const PORT = process.env.PORT || 3000;

// Body & cookie parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Dedicated Insecure Demonstration Configuration:
// By default, SameSite is "lax" (RFC 6265bis).
// In modern browsers, SameSite=Lax cookies are sent on top-level GET navigations (e.g. clicking a link
// or submitting a GET form in a new tab), which makes state-changing GET endpoints inherently vulnerable to CSRF.
// For isolated lab demonstrations requiring cross-site subresource cookie inclusion, the INSECURE_CSRF_DEMO_COOKIE
// flag can be enabled (sets sameSite: false). In default mode, sameSite remains 'lax'.
const INSECURE_CSRF_DEMO_COOKIE = process.env.INSECURE_CSRF_DEMO_COOKIE === "true";

if (INSECURE_CSRF_DEMO_COOKIE) {
  console.warn("⚠️  [SECURITY WARNING] INSECURE_CSRF_DEMO_COOKIE is active.");
  console.warn("⚠️  Session cookie SameSite restriction is disabled (sameSite: false) for educational testing only.");
  console.warn("⚠️  Never deploy this demonstration configuration to a public environment!");
}

const sessionCookieConfig = {
  httpOnly: true,
  sameSite: INSECURE_CSRF_DEMO_COOKIE ? false : "lax",
  secure: false, // Localhost development (SameSite=None requires HTTPS; rejected over plain HTTP)
  maxAge: 1000 * 60 * 60 * 2 // 2 hours
};

app.use(
  session({
    name: "student_portal_sid",
    secret: "csrf-lab-secret-key-2026",
    resave: false,
    saveUninitialized: false,
    cookie: sessionCookieConfig
  })
);

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// Mount API routes
app.use("/api/auth", authRoutes);
app.use("/api/vulnerable", vulnerableRoutes);
app.use("/api/secure", secureRoutes);
app.use("/api/lab", labRoutes);

// Page Routes
app.get("/", (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect("/dashboard");
  }
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  if (req.session && req.session.user) {
    return res.redirect("/dashboard");
  }
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

// Single unified student profile page
app.get(["/dashboard", "/profile", "/email-settings", "/csrf-lab"], requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "profile.html"));
});

// Start server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Student Portal running at: http://localhost:${PORT}`);
    console.log(`Active Startup Mode: [${getLabMode().toUpperCase()} MODE]`);
    console.log(`Test credentials: username="student", password="Password123!"`);
  });
}

module.exports = app;
