/**
 * Main Server Entry Point
 * 
 * Binds strictly to 127.0.0.1 (localhost) to guarantee that the intentionally
 * vulnerable educational route is NEVER exposed to external networks.
 */

const app = require('./app');

const HOST = '127.0.0.1';
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, HOST, () => {
  console.log('================================================================');
  console.log('🛡️  REFLECTED XSS SECURITY LAB - LOCAL EDUCATIONAL SERVER');
  console.log('================================================================');
  console.log(`📡 Server running at: http://${HOST}:${PORT}/`);
  console.log(`🔴 Vulnerable Route:  http://${HOST}:${PORT}/vulnerable`);
  console.log(`🟢 Secured Route:     http://${HOST}:${PORT}/secure`);
  console.log('----------------------------------------------------------------');
  console.log('⚠️  SECURITY NOTICE: Strictly bound to 127.0.0.1 (Localhost only).');
  console.log('   Do NOT deploy or expose this server on public networks.');
  console.log('   Press Ctrl+C to stop the server.');
  console.log('================================================================');
});

// Graceful shutdown handling
process.on('SIGINT', () => {
  console.log('\nStopping Reflected XSS Lab server...');
  server.close(() => {
    console.log('Server successfully stopped.');
    process.exit(0);
  });
});
