const express = require('express');
const { exec } = require('child_process');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// VULNERABLE ROUTE
app.post('/api/ping', (req, res) => {
    const targetHost = req.body.host;

    if (!targetHost) {
        return res.status(400).json({ error: 'Host parameter is required.' });
    }

    // ROOT CAUSE: Unsanitized user input concatenated into shell command!
    // exec() invokes a system shell (/bin/sh or cmd.exe), permitting shell metacharacters like ; | &&
    const command = `ping ${targetHost}`;

    console.log(`[VULNERABLE APP] Executing system command: ${command}`);

    exec(command, (error, stdout, stderr) => {
        // IN-BAND: Output (both stdout and stderr) returned directly back to the user
        res.json({
            executedCommand: command,
            output: stdout || stderr || (error ? error.message : 'No output')
        });
    });
});

app.listen(PORT, () => {
    console.log(`[+] Vulnerable app running at http://localhost:${PORT}`);
});