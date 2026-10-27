
**# Reflected XSS Security Demonstration**

**## 1. Overview**

This project demonstrates **\*\*Reflected Cross-Site Scripting (XSS)\*\***, a web vulnerability in which user input is reflected in an HTTP response without proper output encoding, potentially allowing JavaScript to execute in the browser.

The project includes two versions:
\- **\*\*Vulnerable:\*\*** Reflects user input without HTML encoding.
\- **\*\*Secured:\*\*** Uses HTML output encoding to prevent the demonstrated payload from executing.

**## 2. Technologies Used**

\- Node.js
\- Express.js
\- HTML, CSS, JavaScript

No database is required.

**## 3. Project Structure**

\`\`\`text
03-Reflected-XSS/
├── server.js
├── package.json
├── src/
│   ├── routes/
│   │   ├── home.js
│   │   ├── vulnerable.js
│   │   └── secure.js
│   └── views/
│       ├── layout.js
│       ├── pages.js
│       └── utils.js
├── public/
│   ├── css/style.css
│   └── js/lab.js
├── test/
│   └── test.js
└── README.md
\`\`\`

**## 4. Installation and Setup**

Make sure Node.js and npm are installed.

Open a terminal in this folder and run:

\`\`\`bash
npm install
npm test
npm start
\`\`\`

Open the website at:

\- Home: [http://127.0.0.1:3000/](http://127.0.0.1:3000/)
\- Vulnerable version: [http://127.0.0.1:3000/vulnerable](http://127.0.0.1:3000/vulnerable)
\- Secured version: [http://127.0.0.1:3000/secure](http://127.0.0.1:3000/secure)

**## 5. Demonstration**

1\. Open the vulnerable version and submit a normal search query.
2\. Enter the following harmless test payload and submit it:

   \`\`\`html
   \<script>alert('Reflected XSS Detected!')\</script>
   \`\`\`

3\. Observe the JavaScript alert, demonstrating the vulnerability.
4\. Submit the same payload on the secured version.
5\. Observe that the payload is displayed as text instead of executing.

**## 6. Root Cause and Mitigation**

**\*\*Root cause:\*\*** In \`src/views/pages.js\`, the vulnerable page inserts the user query directly into the HTML response without encoding it.

**\*\*Mitigation:\*\*** The secured page uses the \`encodeHTML()\` function from \`src/views/utils.js\` before inserting the query into the HTML.

This function converts special characters such as \`<\` and \`>\` into HTML entities, preventing the demonstrated input from being interpreted as HTML in the results text.

Other possible defenses include framework auto-escaping, HTML sanitization, and Content Security Policy (CSP).

**## 7. Testing**

Run \`npm test\` to execute the automated tests. They check normal queries and test payloads against both routes and verify that the secured route encodes the input.

**## 8. Safety Note**

This application is intended only for educational testing on localhost. Do not deploy the intentionally vulnerable route on a public server.

**## 9. Student Details**

\- **\*\*Name:\*\*** Praneel
\- **\*\*Roll Number:\*\*** IIB2024029
\- **\*\*Assignment:\*\*** Web Server Security
\- **\*\*Vulnerability:\*\*** Cross-Site Scripting (XSS)
\- **\*\*Variant:\*\*** Reflected XSS