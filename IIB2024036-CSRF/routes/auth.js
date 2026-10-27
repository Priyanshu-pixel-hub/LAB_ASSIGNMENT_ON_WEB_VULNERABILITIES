/**
 * routes/auth.js
 * 
 * Authentication endpoints for the Student Portal.
 * Handles login, session establishment, session invalidation (logout),
 * and student identity retrieval.
 */

const express = require("express");
const crypto = require("crypto");
const router = express.Router();
const { getStudent, requireAuth, getLabMode } = require("../middleware/authentication");

/**
 * Helper to generate a cryptographically secure CSRF token
 */
function generateCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * POST /api/auth/login
 * Validates credentials and initializes an authenticated session.
 */
router.post("/login", (req, res) => {
  const { username, password } = req.body;
  const student = getStudent();

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: "Missing credentials",
      message: "Please enter both username and password."
    });
  }

  // Check against fictional test account credentials
  if (username.trim() === student.username && password === student.password) {
    // Regenerate session ID to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: "Session error",
          message: "Failed to initialize session."
        });
      }

      // Store student user object in session
      req.session.user = {
        id: student.id,
        username: student.username,
        name: student.name,
        email: student.email
      };

      // Generate unpredictable synchronizer token for CSRF defense
      req.session.csrfToken = generateCsrfToken();

      return res.status(200).json({
        success: true,
        message: "Login successful",
        user: {
          id: student.id,
          name: student.name,
          username: student.username,
          email: student.email
        },
        labMode: getLabMode()
      });
    });
  } else {
    return res.status(401).json({
      success: false,
      error: "Invalid credentials",
      message: "Invalid username or password. Check README for test credentials."
    });
  }
});

/**
 * POST /api/auth/logout
 * Destroys the active session and clears the session cookie.
 */
router.post("/logout", requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: "Logout failed",
        message: "Could not destroy session."
      });
    }

    res.clearCookie("student_portal_sid");
    return res.status(200).json({
      success: true,
      message: "Logged out successfully"
    });
  });
});

/**
 * GET /api/auth/me
 * Returns current authenticated user and student profile information.
 */
router.get("/me", requireAuth, (req, res) => {
  const student = getStudent();
  return res.status(200).json({
    success: true,
    user: {
      id: student.id,
      name: student.name,
      username: student.username,
      email: student.email,
      department: student.department,
      program: student.program,
      semester: student.semester,
      academicYear: student.academicYear,
      advisor: student.advisor,
      enrollmentStatus: student.enrollmentStatus
    },
    labMode: getLabMode()
  });
});

module.exports = router;
module.exports.generateCsrfToken = generateCsrfToken;
