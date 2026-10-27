/**
 * routes/lab.js
 * 
 * Educational Security Lab Controller
 * Provides controls for toggling between Vulnerable Demo and Secure Demo modes,
 * resetting test data, and viewing security status diagnostics.
 */

const express = require("express");
const router = express.Router();
const {
  requireAuth,
  getStudent,
  resetStudentData,
  getLabMode,
  setLabMode,
  DEFAULT_STUDENT
} = require("../middleware/authentication");

/**
 * GET /api/lab/status
 * Returns current educational lab configuration and student data.
 */
router.get("/status", requireAuth, (req, res) => {
  return res.status(200).json({
    success: true,
    labMode: getLabMode(),
    student: getStudent(),
    defaultEmail: DEFAULT_STUDENT.email,
    csrfTokenActive: Boolean(req.session && req.session.csrfToken)
  });
});

/**
 * POST /api/lab/mode
 * Toggles educational mode between 'vulnerable' and 'secure'.
 */
router.post("/mode", requireAuth, (req, res) => {
  const { mode } = req.body;

  if (mode !== "vulnerable" && mode !== "secure") {
    return res.status(400).json({
      success: false,
      error: "Invalid mode",
      message: "Lab mode must be either 'vulnerable' or 'secure'."
    });
  }

  const updatedMode = setLabMode(mode);

  return res.status(200).json({
    success: true,
    labMode: updatedMode,
    message: `Educational lab mode switched to ${updatedMode.toUpperCase()} mode.`
  });
});

/**
 * POST /api/lab/reset
 * Resets student profile email back to fictional initial state.
 */
router.post("/reset", requireAuth, (req, res) => {
  const restored = resetStudentData();
  if (req.session.user) {
    req.session.user.email = restored.email;
  }

  return res.status(200).json({
    success: true,
    message: "Student portal data reset to initial fictional baseline.",
    student: restored
  });
});

module.exports = router;
