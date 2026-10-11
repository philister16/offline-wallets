// Interactive (TTY) tests: run the CLI in a pseudo-terminal via `script(1)` and
// type into it. Secrets must never appear in the terminal output.
// All mnemonics here are public test data. Never fund them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

const CLI = fileURLToPath(new URL('../index.js', import.meta.url));
const TEST_JUNK = 'test test test test test test test test test test test junk';
const TEST_JUNK_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const TEST_JUNK_TREZOR_ADDRESS = '0x9313778B3753108128B9c476EBDd42FbD566F4Ed';

const quote = (s) => `'${s.replaceAll("'", `'\\''`)}'`;

// Node passes child stdio as sockets on macOS, which script(1) rejects, so a
// `cat` in front gives it a real pipe.
function ptyCommand(args) {
    const cmd = [process.execPath, CLI, ...args].map(quote).join(' ');
    if (process.platform === 'darwin') return ['sh', ['-c', `cat | script -q /dev/null ${cmd}`]];
    if (process.platform === 'linux') return ['sh', ['-c', `cat | script -qec ${quote(cmd)} /dev/null`]];
    return null;
}

const skip = ptyCommand([]) ? false : 'script(1) pseudo-terminal not supported on this platform';

// Each step waits for `waitFor` to appear in the output (after the previous
// match), then types `send` (a string, or a function of the output so far).
function runPty(args, steps, { allowOnline = true } = {}) {
    const [command, commandArgs] = ptyCommand(allowOnline && args.length ? [...args, '--allow-online'] : args);
    return new Promise((resolve, reject) => {
        const child = spawn(command, commandArgs);
        let output = '';
        let searchFrom = 0;
        let step = 0;
        const timer = setTimeout(() => {
            child.kill();
            reject(new Error(`Timed out at step ${step}. Output:\n${clean(output)}`));
        }, 15000);
        const advance = () => {
            while (step < steps.length) {
                const at = output.indexOf(steps[step].waitFor, searchFrom);
                if (at === -1) return;
                searchFrom = at + steps[step].waitFor.length;
                const { send } = steps[step];
                child.stdin.write(typeof send === 'function' ? send(clean(output)) : send);
                step++;
            }
            // Let cat (and with it script) exit once everything has been typed.
            if (!child.stdin.writableEnded) child.stdin.end();
        };
        child.stdout.on('data', (d) => {
            output += d;
            advance();
        });
        child.on('error', reject);
        child.on('close', (code) => {
            clearTimeout(timer);
            resolve({ code, output: clean(output), raw: output });
        });
    });
}

// Strip ANSI sequences and carriage returns; keep only the last redraw of each line.
function clean(output) {
    return output
        .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
        .split('\n')
        .map((line) => line.split('\r').filter(Boolean).pop() ?? '')
        .join('\n');
}

function assertNoSecrets(output, secrets) {
    for (const secret of secrets) assert.ok(!output.includes(secret), `secret echoed: ${secret}`);
}

test('restore on a TTY: secrets are not echoed, only counts are shown', { skip }, async () => {
    const res = await runPty(['restore'], [
        { waitFor: 'Enter mnemonic: ', send: `${TEST_JUNK}\r` },
        { waitFor: 'Enter passphrase: ', send: 'TREZOR\r' },
    ]);
    assert.equal(res.code, 0, res.output);
    assert.match(res.output, /Enter mnemonic: \[12 words\]/);
    assert.match(res.output, /Enter passphrase: \[6 characters\]/);
    assert.match(res.output, new RegExp(`Address:\\s+${TEST_JUNK_TREZOR_ADDRESS}`));
    assertNoSecrets(res.output, ['test test', 'junk', 'TREZOR']);
});

test('restore on a TTY: backspace, Ctrl-U and arrow keys edit the hidden input', { skip }, async () => {
    const res = await runPty(['restore'], [
        { waitFor: 'Enter mnemonic: ', send: `wrong words\u0015${TEST_JUNK}x\u007f\x1b[D\x1b[C\r` },
        { waitFor: 'Enter passphrase: ', send: 'TREZORX\u007f\r' },
    ]);
    assert.equal(res.code, 0, res.output);
    assert.match(res.output, new RegExp(`Address:\\s+${TEST_JUNK_TREZOR_ADDRESS}`));
});

test('restore on a TTY: pasting mnemonic and passphrase at once works', { skip }, async () => {
    const res = await runPty(['restore'], [
        { waitFor: 'Enter mnemonic: ', send: `${TEST_JUNK}\r\n\r\n` },
    ]);
    assert.equal(res.code, 0, res.output);
    assert.match(res.output, new RegExp(`Address:\\s+${TEST_JUNK_ADDRESS}`));
    assertNoSecrets(res.output, ['test test', 'junk']);
});

test('restore on a TTY: invalid mnemonic and padded passphrase re-prompt', { skip }, async () => {
    const res = await runPty(['restore'], [
        { waitFor: 'Enter mnemonic: ', send: 'test test junk\r' },
        // Wait for the error, not 'Enter mnemonic: ': every keystroke redraws the prompt.
        { waitFor: 'got 3.', send: `${TEST_JUNK}\r` },
        { waitFor: 'Enter passphrase: ', send: ' TREZOR\r' },
        { waitFor: '[y/N] ', send: 'n\r' },
        { waitFor: 'Enter passphrase: ', send: 'TREZOR\r' },
    ]);
    assert.equal(res.code, 0, res.output);
    assert.match(res.output, /Expected 12, 15, 18, 21 or 24 words, got 3\./);
    assert.match(res.output, /Warning: the passphrase \(7 characters\)/);
    assert.match(res.output, new RegExp(`Address:\\s+${TEST_JUNK_TREZOR_ADDRESS}`));
    assertNoSecrets(res.output, ['test test', 'junk', 'TREZOR']);
});

test('restore on a TTY: Ctrl-C aborts with exit code 1', { skip }, async () => {
    const res = await runPty(['restore'], [
        { waitFor: 'Enter mnemonic: ', send: 'test te\u0003' },
    ]);
    assert.equal(res.code, 1, res.output);
    assert.doesNotMatch(res.output, /Address:/);
    assertNoSecrets(res.output, ['test te']);
});

test('restore on a TTY: generated passphrase with a bad checksum asks before using it verbatim', { skip }, async () => {
    const typo = 'BFFB-M987-8PPK-V696-EDNF-7B5X-YAPD';
    const res = await runPty(['restore'], [
        { waitFor: 'Enter mnemonic: ', send: `${TEST_JUNK}\r` },
        { waitFor: 'Enter passphrase: ', send: `${typo}\r` },
        { waitFor: '[y/N] ', send: 'n\r' },
        { waitFor: 'Enter passphrase: ', send: 'bffb m987 8ppk v696 ednf 7b5x yapc\r' },
    ]);
    assert.equal(res.code, 0, res.output);
    assert.match(res.output, /checksum does not match/);
    assert.match(res.output, /Recognised an ofwl passphrase/);
    assert.match(res.output, /Address:\s+0x64F666d162C79234fb3AFfC7e11d7C82D0a1633d/);
    assertNoSecrets(res.output, ['BFFB', 'bffb', 'YAP']);
});

// --- create: backup verification ---

const CLEAR_SCREEN = '\x1b[2J\x1b[3J\x1b[H';
const printed = (output, label) => output.match(new RegExp(`${label}:\\s+(\\S.*)$`, 'm'))[1].trim();
// Output after the last screen clear, i.e. what stays visible once verification starts.
const afterClear = (res) => clean(res.raw.slice(res.raw.lastIndexOf(CLEAR_SCREEN)));

test('create on a TTY: backup verification succeeds with hidden input', { skip }, async () => {
    let mnemonic;
    const res = await runPty(['create'], [
        { waitFor: '[Y/n] ', send: '\r' },
        { waitFor: 'Enter mnemonic: ', send: (out) => `${(mnemonic = printed(out, 'Mnemonic'))}\r` },
    ]);
    assert.equal(res.code, 0, res.output);
    assert.ok(res.raw.includes(CLEAR_SCREEN), 'screen not cleared');
    const visible = afterClear(res);
    assert.match(visible, /Enter mnemonic: \[24 words\]/);
    assert.match(visible, new RegExp(`Backup verified\\. It restores ${printed(res.output, 'Address')} \\(m/44'/60'/0'/0/0\\)`));
    assert.ok(!visible.includes(mnemonic.split(' ')[0] + ' ' + mnemonic.split(' ')[1]), 'mnemonic visible after clear');
    assert.doesNotMatch(visible, /Enter passphrase/);
});

test('create on a TTY: wrong passphrase is reported, shown again, then verified', { skip }, async () => {
    const res = await runPty(['create', '--passphrase'], [
        { waitFor: '[Y/n] ', send: 'y\r' },
        { waitFor: 'Enter mnemonic: ', send: (out) => `${printed(out, 'Mnemonic')}\r` },
        { waitFor: 'Enter passphrase: ', send: 'wrong\r' },
        { waitFor: 'or [q]uit? ', send: 's\r' },
        { waitFor: 'verify again. ', send: '\r' },
        { waitFor: 'Enter mnemonic: ', send: (out) => `${printed(out, 'Mnemonic')}\r` },
        // Lowercase and without dashes: normalised like in restore.
        { waitFor: 'Enter passphrase: ', send: (out) => `${printed(out, 'Passphrase').toLowerCase().replaceAll('-', '')}\r` },
    ]);
    assert.equal(res.code, 0, res.output);
    assert.match(res.output, /Mismatch: the passphrase differs\./);
    assert.match(afterClear(res), /Backup verified/);
});

test('create on a TTY: a valid but different mnemonic names the word position', { skip }, async () => {
    // Swap the last word for another one that still passes the checksum.
    const otherLastWord = (mnemonic) => {
        const words = mnemonic.split(' ');
        const replacement = wordlist.find((w) => w !== words[23] && validateMnemonic([...words.slice(0, 23), w].join(' '), wordlist));
        return [...words.slice(0, 23), replacement].join(' ');
    };
    const res = await runPty(['create'], [
        { waitFor: '[Y/n] ', send: '\r' },
        { waitFor: 'Enter mnemonic: ', send: (out) => `${otherLastWord(printed(out, 'Mnemonic'))}\r` },
        { waitFor: 'or [q]uit? ', send: 'q\r' },
    ]);
    assert.equal(res.code, 1, res.output);
    const visible = afterClear(res);
    assert.match(visible, /Mismatch: word #24 differs\./);
    assert.match(visible, /Backup NOT verified/);
    assert.match(visible, new RegExp(`Address:\\s+${printed(res.output, 'Address')}`));
});

test('create on a TTY: verification can be skipped', { skip }, async () => {
    const skipped = await runPty(['create'], [{ waitFor: '[Y/n] ', send: 'n\r' }]);
    assert.equal(skipped.code, 0, skipped.output);
    assert.match(skipped.output, /Skipped\. Before funding this address, check your backup/);
    assert.ok(!skipped.raw.includes(CLEAR_SCREEN));

    const noVerify = await runPty(['create', '--no-verify'], []);
    assert.equal(noVerify.code, 0, noVerify.output);
    assert.doesNotMatch(noVerify.output, /\[Y\/n\]/);
});

// --- offline check ---

const ONLINE = Object.values(os.networkInterfaces()).flat().some(
    (a) => !a.internal && !(a.family === 'IPv4' ? /^169\.254\./.test(a.address) : /^fe[89ab]/i.test(a.address)),
);
const onlineSkip = skip || (!ONLINE && 'machine is offline; the online warning cannot be triggered');

test('offline check on a TTY: online machine requires typing "yes"', { skip: onlineSkip }, async () => {
    const refused = await runPty(['restore'], [{ waitFor: 'to continue anyway: ', send: 'y\r' }], { allowOnline: false });
    assert.equal(refused.code, 1, refused.output);
    assert.match(refused.output, /WARNING: This computer appears to be online/);
    assert.match(refused.output, /Aborted\./);
    assert.doesNotMatch(refused.output, /Enter mnemonic/);

    const accepted = await runPty(['restore'], [
        { waitFor: 'to continue anyway: ', send: 'yes\r' },
        { waitFor: 'Enter mnemonic: ', send: `${TEST_JUNK}\r` },
        { waitFor: 'Enter passphrase: ', send: '\r' },
    ], { allowOnline: false });
    assert.equal(accepted.code, 0, accepted.output);
    assert.match(accepted.output, new RegExp(`Address:\\s+${TEST_JUNK_ADDRESS}`));
});
