/**
 * middleware/authentication.js
 * 
 * Authentication and session verification middleware for the Student Portal.
 * Verifies that incoming requests are bound to an active authenticated session.
 */

// In-memory student profile data store
const DEFAULT_STUDENT = {
  id: "STU-2026-8942",
  username: "student",
  password: "Password123!", // Fictional test credentials
  name: "Alex Johnson",
  email: "alex.johnson@university.edu",
  department: "Computer Science & Information Technology",
  program: "B.Tech Cyber Security",
  semester: "Semester 5",
  academicYear: "2026-2027",
  advisor: "Dr. Sarah Mitchell",
  enrollmentStatus: "Active"
};

// Mutable runtime state (in-memory)
let currentStudent = { ...DEFAULT_STUDENT };

// Lab mode state: initialized from MODE or APP_MODE environment variable
// Defaults to 'vulnerable' for standard university assignment startup (npm start)
const startupMode = (process.env.MODE || process.env.APP_MODE || "vulnerable").toLowerCase() === "secure" ? "secure" : "vulnerable";
let currentLabMode = startupMode;

/**
 * Get the current student data.
 */
function getStudent() {
  return currentStudent;
}

/**
 * Update the student's email address.
 * @param {string} newEmail
 */
function updateStudentEmail(newEmail) {
  const previousEmail = currentStudent.email;
  currentStudent.email = newEmail;
  return { previousEmail, currentEmail: newEmail };
}

/**
 * Reset student data to initial state.
 */
function resetStudentData() {
  currentStudent = { ...DEFAULT_STUDENT };
  return currentStudent;
}

/**
 * Get current educational lab mode.
 */
function getLabMode() {
  return currentLabMode;
}

/**
 * Set educational lab mode ('secure' or 'vulnerable').
 * @param {'secure' | 'vulnerable'} mode
 */
function setLabMode(mode) {
  if (mode === "secure" || mode === "vulnerable") {
    currentLabMode = mode;
  }
  return currentLabMode;
}

const { logLabAudit } = require("./auditLogger");

/**
 * Authentication middleware.
 * Ensures that the user has an active session before accessing protected resources.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }

  // If request expects JSON (API calls), return 401 Unauthorized
  if (req.xhr || (req.headers.accept && req.headers.accept.includes("application/json")) || req.path.startsWith("/api/")) {
    logLabAudit({
      endpoint: req.originalUrl || req.path,
      method: req.method,
      authenticated: false,
      csrfValidation: "N/A",
      emailChanged: "NO (401 Unauthorized — Session Absent)"
    });

    return res.status(401).json({
      success: false,
      error: "Authentication required",
      message: "You must be logged in to access this resource."
    });
  }

  // Otherwise redirect browser to login page
  return res.redirect("/login");
}

module.exports = {
  DEFAULT_STUDENT,
  getStudent,
  updateStudentEmail,
  resetStudentData,
  getLabMode,
  setLabMode,
  requireAuth
};
