/**
 * Express Application Configuration
 * Configures middleware, static asset serving, and security lab routes.
 */

const express = require('express');
const path = require('path');

const homeRoute = require('./src/routes/home');
const vulnerableRoute = require('./src/routes/vulnerable');
const secureRoute = require('./src/routes/secure');

const app = express();

// Serve static assets (CSS, client JS)
app.use(express.static(path.join(__dirname, 'public')));

// Mount routes
app.use('/', homeRoute);
app.use('/vulnerable', vulnerableRoute);
app.use('/secure', secureRoute);

// 404 handler
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
      <head><title>404 Not Found</title></head>
      <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h2>404 - Page Not Found</h2>
        <p>The requested route does not exist in the Reflected XSS Lab.</p>
        <p><a href="/">Return to Lab Home</a></p>
      </body>
    </html>
  `);
});

module.exports = app;
