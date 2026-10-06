/*
 * defender.js -- EMULATION LAYER.
 *
 * A deliberately small model of the two Windows Defender behaviours that make
 * AVOracle (Ryo "icchy" Ichikawa, WCTF 2019 "Gyotaku The Flag") work:
 *
 *   1. Defender scans a file AS A WHOLE. Attacker-controlled bytes and secret
 *      bytes sitting in the same file are evaluated together.
 *   2. Defender's engine emulates anything that looks like script -- JScript
 *      in particular -- including a DOM-ish environment, and matches its
 *      signatures against what the emulated script produces (strings passed to
 *      eval(), written out, ...), not only against the raw bytes on disk.
 *   3. A file that matches a signature is removed from disk.
 *
 * Put together, "the file is gone" is a one-bit read of the secret.
 *
 * The signature used here is FAKE. We deliberately do NOT use the real EICAR
 * test string, because writing EICAR to disk would make the antivirus running
 * on the machine hosting this lab light up for real.
 */

'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');
const vm = require('vm');

const DIR = process.env.SCAN_DIR || '/sessions';
const INTERVAL = Number(process.env.SCAN_INTERVAL_MS || 400);
const PORT = Number(process.env.SCAN_PORT || 8080);

/* A fake signature. Not EICAR. See the README. */
const SIGNATURE = 'PHRACK-STANDARD-ANTIVIRUS-TEST-FILE!';
const THREAT = 'Script/Phrack_Test_File';

const state = { passes: 0, scanned: 0, quarantined: [] };

function log(msg) {
    process.stdout.write(`[${new Date().toISOString()}] ${msg}\n`);
}

/* ------------------------------------------------------------------ */
/* the scan engine                                                     */

/** Everything between <body ...> and </body> (or end of file). */
function extractBody(text) {
    const m = /<body[^>]*>([\s\S]*?)(?:<\/body>|$)/i.exec(text);
    return m ? m[1] : '';
}

function extractScripts(text) {
    const out = [];
    const rx = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    while ((m = rx.exec(text)) !== null) {
        out.push(m[1]);
    }
    return out;
}

/*
 * The emulator. Everything the guest can touch is built INSIDE the vm context
 * so that no host object is reachable from the emulated script; only strings
 * cross the boundary. node's `vm` is not a security sandbox, but this keeps a
 * stray payload from trivially reaching `process`.
 */
function buildContext(body) {
    const ctx = vm.createContext(Object.create(null));
    const boot = `
        var __SIG = ${JSON.stringify(SIGNATURE)};
        var __hit = false;
        function __check(s) {
            if (typeof s === 'string' && s.indexOf(__SIG) !== -1) { __hit = true; }
            return undefined;
        }
        var __body = ${JSON.stringify(body)};
        var document = {
            body: { innerHTML: __body, innerText: __body },
            write: __check,
            writeln: __check,
            getElementById: function () { return { innerHTML: __body }; }
        };
        var WScript = { Echo: __check, Sleep: function () {} };
        var window = this;
        var navigator = { userAgent: 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)' };
        /*
         * The engine does not recursively emulate what eval() is handed; it
         * matches its signatures against the string first. That is exactly the
         * behaviour AVOracle relies on.
         */
        this.eval = __check;
        undefined;
    `;
    vm.runInContext(boot, ctx, { timeout: 500, displayErrors: false });
    return ctx;
}

function emulate(code, body) {
    let ctx;
    try {
        ctx = buildContext(body);
    } catch (e) {
        return false;
    }
    let rv;
    try {
        rv = vm.runInContext(code, ctx, { timeout: 300, displayErrors: false });
    } catch (e) {
        /* A script that throws is simply not detected -- same as the real
         * engine giving up on an emulation. */
    }
    if (ctx.__hit === true) {
        return true;
    }
    return typeof rv === 'string' && rv.indexOf(SIGNATURE) !== -1;
}

/** Returns null (clean) or a short string naming why the file was flagged. */
function scan(buf) {
    const text = buf.toString('latin1');

    if (text.indexOf(SIGNATURE) !== -1) {
        return 'raw signature in file body';
    }
    const scripts = extractScripts(text);
    if (scripts.length === 0) {
        return null;
    }
    const body = extractBody(text);
    for (const code of scripts) {
        if (emulate(code, body)) {
            return 'signature produced by emulated script';
        }
    }
    return null;
}

/* ------------------------------------------------------------------ */
/* real-time protection                                                */

function scanOnce() {
    let entries;
    try {
        entries = fs.readdirSync(DIR);
    } catch (e) {
        state.passes++;
        return;
    }
    for (const name of entries) {
        const p = path.join(DIR, name);
        let buf;
        try {
            if (!fs.statSync(p).isFile()) { continue; }
            buf = fs.readFileSync(p);
        } catch (e) {
            continue;                      /* raced with the writer */
        }
        state.scanned++;
        let verdict = null;
        try {
            verdict = scan(buf);
        } catch (e) {
            verdict = null;
        }
        if (verdict !== null) {
            try {
                fs.unlinkSync(p);
            } catch (e) {
                continue;
            }
            state.quarantined.push({ file: name, reason: verdict, at: Date.now() });
            if (state.quarantined.length > 200) { state.quarantined.shift(); }
            /* Deliberately never log file contents -- that would be a second,
             * much less interesting oracle. */
            log(`EngineScanCallback(): Threat ${THREAT} identified in ${name} (${verdict}); file removed`);
        }
    }
    state.passes++;
}

setInterval(scanOnce, INTERVAL);

/* ------------------------------------------------------------------ */
/* the "Defender status" console                                       */

http.createServer((req, res) => {
    const url = (req.url || '/').split('?')[0];
    res.setHeader('Content-Type', 'application/json');

    if (url === '/scan' || url === '/scan/') {
        /* On-demand scan. Real-time protection already runs on a timer; this
         * only exists so the solver does not have to sleep for a whole scan
         * interval on every oracle query. */
        scanOnce();
        res.end(JSON.stringify({ passes: state.passes }));
        return;
    }
    if (url === '/status' || url === '/') {
        res.end(JSON.stringify({
            engine: 'phrack-defender (emulation)',
            signature: THREAT,
            interval_ms: INTERVAL,
            passes: state.passes,
            files_scanned: state.scanned,
            quarantined: state.quarantined.slice(-20).map((q) => q.file)
        }));
        return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'not found' }));
}).listen(PORT, () => {
    log(`real-time protection on ${DIR}, every ${INTERVAL}ms; console on :${PORT}`);
});
