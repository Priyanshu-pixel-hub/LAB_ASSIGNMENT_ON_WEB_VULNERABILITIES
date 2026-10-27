/**
 * middleware/auditLogger.js
 * 
 * Educational Demonstration Audit Logger
 * 
 * Outputs concise diagnostic logs for incoming state-changing requests and lab operations.
 * Helps students, instructors, and evaluators observe:
 *   1. Which endpoint received the request
 *   2. Which HTTP method was used
 *   3. Whether the request was authenticated
 *   4. Whether CSRF validation passed or failed, where applicable
 *   5. Whether the student email was changed
 * 
 * STRICT SECURITY COMPLIANCE:
 * Never logs session IDs, session-cookie values, or CSRF-token values.
 */

function logLabAudit({ endpoint, method, authenticated, csrfValidation, emailChanged, details }) {
  const parts = [
    `[LAB AUDIT]`,
    `Endpoint: ${endpoint}`,
    `Method: ${method}`,
    `Authenticated: ${authenticated ? "YES" : "NO"}`,
    `CSRF Validation: ${csrfValidation || "N/A"}`,
    `Email Changed: ${emailChanged}`
  ];

  if (details) {
    parts.push(`Details: ${details}`);
  }

  console.log(parts.join(" | "));
}

module.exports = { logLabAudit };
