const express = require('express');
const { execFile } = require('child_process');
const path = require('path');

const app = express();
const PORT = 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// SECURE ROUTE
app.post('/api/ping', (req, res) => {
    const targetHost = req.body.host;

    if (!targetHost) {
        return res.status(400).json({ error: 'Host parameter is required.' });
    }

    // MITIGATION STEP 1: Strict Allow-List Input Validation
    // Ensures input contains ONLY alphanumeric characters, dots, and hyphens (Valid IP/Hostname)
    const validHostPattern = /^([a-zA-Z0-9.-]+)$/;
    if (!validHostPattern.test(targetHost)) {
        console.warn(`[FIXED APP] Blocked malicious input: ${targetHost}`);
        return res.status(400).json({
            error: 'Security Exception: Malicious input detected!',
            details: 'Input failed strict regex validation rule.'
        });
    }

    // MITIGATION STEP 2: Parameterized Execution via Argument Vector
    // execFile directly executes the binary binary without spawning a command shell!
    // targetHost is treated as a pure data argument, preventing command chaining.
    const binary = 'ping';
    const args = ['-c', '2', targetHost];

    console.log(`[FIXED APP] Executing binary cleanly: ${binary} ${args.join(' ')}`);

    execFile(binary, args, (error, stdout, stderr) => {
        res.json({
            status: 'Success',
            executedBinary: binary,
            passedArguments: args,
            output: stdout || stderr || (error ? error.message : 'No output')
        });
    });
});

app.listen(PORT, () => {
    console.log(`[+] Fixed app running securely at http://localhost:${PORT}`);
});