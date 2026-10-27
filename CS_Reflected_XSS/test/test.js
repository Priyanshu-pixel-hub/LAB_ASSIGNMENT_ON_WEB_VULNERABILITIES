/**
 * Automated Test Suite for Reflected XSS Security Lab
 * 
 * Features:
 * 1. Automatically boots its own Express server instance on an ephemeral port (port 0).
 * 2. Runs without requiring the user to start `server.js` first.
 * 3. Properly URL-encodes test payloads using encodeURIComponent.
 * 4. Verifies response status and unencoded vs encoded reflection in response bodies.
 * 5. Shuts down the server instance cleanly upon completion.
 */

const assert = require('assert');
const app = require('../app');

// Colorful console output helpers
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  bold: '\x1b[1m'
};

async function runTests() {
  console.log(`${colors.cyan}${colors.bold}====================================================${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}   REFLECTED XSS LAB - AUTOMATED TEST SUITE        ${colors.reset}`);
  console.log(`${colors.cyan}${colors.bold}====================================================${colors.reset}\n`);

  let server;
  let testCount = 0;
  let passedCount = 0;

  function runCase(name, testFn) {
    testCount++;
    try {
      testFn();
      console.log(`  ${colors.green}✔ [PASS]${colors.reset} Test ${testCount}: ${name}`);
      passedCount++;
    } catch (err) {
      console.error(`  ${colors.red}✖ [FAIL]${colors.reset} Test ${testCount}: ${name}`);
      console.error(`    ${colors.red}Error: ${err.message}${colors.reset}`);
    }
  }

  // 1. Start server on ephemeral port (port 0) bound to 127.0.0.1
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const address = server.address();
      console.log(`📡 Ephemeral test server active on http://${address.address}:${address.port}\n`);
      resolve();
    });
  });

  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    // ---------------------------------------------------------
    // Test 1: Verify Server Binding Address
    // ---------------------------------------------------------
    runCase('Server binds strictly to 127.0.0.1', () => {
      const address = server.address();
      assert.strictEqual(address.address, '127.0.0.1', 'Server address must be 127.0.0.1');
    });

    // ---------------------------------------------------------
    // Test 2: Landing Page (GET /)
    // ---------------------------------------------------------
    const homeRes = await fetch(`${baseUrl}/`);
    const homeBody = await homeRes.text();
    runCase('Landing Page (GET /) loads with HTTP 200 and links to both routes', () => {
      assert.strictEqual(homeRes.status, 200, 'Home page must return HTTP 200');
      assert.ok(homeBody.includes('Reflected Cross-Site Scripting (XSS)'), 'Must include lab title');
      assert.ok(homeBody.includes('/vulnerable'), 'Must link to vulnerable route');
      assert.ok(homeBody.includes('/secure'), 'Must link to secure route');
    });

    // ---------------------------------------------------------
    // Test 3: Normal Query on Vulnerable Route
    // ---------------------------------------------------------
    const normalQuery = 'CyberSecurity2026';
    const vulnNormalRes = await fetch(`${baseUrl}/vulnerable?q=${encodeURIComponent(normalQuery)}`);
    const vulnNormalBody = await vulnNormalRes.text();
    runCase('Vulnerable Route reflects benign query without alteration', () => {
      assert.strictEqual(vulnNormalRes.status, 200, 'Must return HTTP 200');
      assert.ok(vulnNormalBody.includes(`Search results for: <strong>${normalQuery}</strong>`), 'Normal search term must reflect in body');
    });

    // ---------------------------------------------------------
    // Test 4: Harmless <script> Payload on Vulnerable Route
    // ---------------------------------------------------------
    const scriptPayload = "<script>alert('Vulnerable-XSS')</script>";
    const vulnScriptRes = await fetch(`${baseUrl}/vulnerable?q=${encodeURIComponent(scriptPayload)}`);
    const vulnScriptBody = await vulnScriptRes.text();
    runCase('Vulnerable Route reflects raw unescaped <script> tag (Demonstrating Flaw)', () => {
      assert.strictEqual(vulnScriptRes.status, 200, 'Must return HTTP 200');
      assert.ok(
        vulnScriptBody.includes(`Search results for: <strong>${scriptPayload}</strong>`),
        'Raw <script> tag must be directly reflected in the response body'
      );
    });

    // ---------------------------------------------------------
    // Test 5: Event-Based Payload on Vulnerable Route
    // ---------------------------------------------------------
    const imgPayload = '<img src=x onerror="alert(1)">';
    const vulnImgRes = await fetch(`${baseUrl}/vulnerable?q=${encodeURIComponent(imgPayload)}`);
    const vulnImgBody = await vulnImgRes.text();
    runCase('Vulnerable Route reflects raw unescaped <img> onerror payload', () => {
      assert.strictEqual(vulnImgRes.status, 200, 'Must return HTTP 200');
      assert.ok(
        vulnImgBody.includes(`Search results for: <strong>${imgPayload}</strong>`),
        'Raw <img> tag with onerror must be directly reflected'
      );
    });

    // ---------------------------------------------------------
    // Test 6: Normal Query on Secured Route
    // ---------------------------------------------------------
    const secNormalRes = await fetch(`${baseUrl}/secure?q=${encodeURIComponent(normalQuery)}`);
    const secNormalBody = await secNormalRes.text();
    runCase('Secured Route reflects benign query and preserves search functionality', () => {
      assert.strictEqual(secNormalRes.status, 200, 'Must return HTTP 200');
      assert.ok(secNormalBody.includes(`Search results for: <strong>${normalQuery}</strong>`), 'Normal search term must reflect safely');
    });

    // ---------------------------------------------------------
    // Test 7: Harmless <script> Payload on Secured Route
    // ---------------------------------------------------------
    const secScriptRes = await fetch(`${baseUrl}/secure?q=${encodeURIComponent(scriptPayload)}`);
    const secScriptBody = await secScriptRes.text();
    runCase('Secured Route safely encodes <script> payload to HTML entities', () => {
      assert.strictEqual(secScriptRes.status, 200, 'Must return HTTP 200');
      
      const expectedEncoded = '&lt;script&gt;alert(&#39;Vulnerable-XSS&#39;)&lt;/script&gt;';
      
      // Must contain HTML entity encoded version
      assert.ok(
        secScriptBody.includes(expectedEncoded),
        `Response body must contain safely encoded string: ${expectedEncoded}`
      );

      // Must NOT contain unescaped executable tag
      assert.ok(
        !secScriptBody.includes(`<strong>${scriptPayload}</strong>`),
        'Response body MUST NOT contain executable <script> tags inside results'
      );
    });

    // ---------------------------------------------------------
    // Test 8: Event-Based Payload on Secured Route
    // ---------------------------------------------------------
    const secImgRes = await fetch(`${baseUrl}/secure?q=${encodeURIComponent(imgPayload)}`);
    const secImgBody = await secImgRes.text();
    runCase('Secured Route safely encodes <img> onerror payload (&quot;, &lt;, &gt;)', () => {
      assert.strictEqual(secImgRes.status, 200, 'Must return HTTP 200');
      
      const expectedEncodedImg = '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;';
      
      // Must contain HTML entity encoded version
      assert.ok(
        secImgBody.includes(expectedEncodedImg),
        `Response body must contain safely encoded string: ${expectedEncodedImg}`
      );

      // Must NOT contain unescaped <img> tag
      assert.ok(
        !secImgBody.includes(`<strong>${imgPayload}</strong>`),
        'Response body MUST NOT contain unescaped <img> tags inside results'
      );
    });

  } finally {
    // ---------------------------------------------------------
    // Teardown: Stop the ephemeral server cleanly
    // ---------------------------------------------------------
    await new Promise((resolve) => {
      server.close(() => {
        console.log(`\n🛑 Ephemeral test server closed.`);
        resolve();
      });
    });
  }

  // -----------------------------------------------------------
  // Summary
  // -----------------------------------------------------------
  console.log(`\n${colors.bold}----------------------------------------------------${colors.reset}`);
  console.log(`Test Results: ${passedCount}/${testCount} passed`);
  console.log(`${colors.bold}----------------------------------------------------${colors.reset}`);

  if (passedCount === testCount) {
    console.log(`${colors.green}${colors.bold}All automated tests passed successfully!${colors.reset}\n`);
    process.exit(0);
  } else {
    console.error(`${colors.red}${colors.bold}Some tests failed. See output above.${colors.reset}\n`);
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Unexpected test harness error:', err);
  process.exit(1);
});
