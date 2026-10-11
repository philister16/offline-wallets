// Differential test: the CLI must derive exactly what ethers v6 (the v1.x
// implementation) derives, for random wallets and messy-but-valid input.
// ethers is a devDependency used only here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, randomInt } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Mnemonic, HDNodeWallet } from 'ethers';

const CLI = fileURLToPath(new URL('../index.js', import.meta.url));
const CASES = 120;
const CONCURRENCY = 8;

function run(args, input = '') {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [CLI, ...args]);
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (d) => (stdout += d));
        child.stderr.on('data', (d) => (stderr += d));
        child.on('error', reject);
        child.on('close', (code) => resolve({ code, stdout, stderr }));
        child.stdin.end(input);
    });
}

function field(stdout, label) {
    const match = stdout.match(new RegExp(`${label}:[ \\t]+(\\S.*)$`, 'm'));
    return match ? match[1].trim() : undefined;
}

async function pool(items, worker) {
    const queue = [...items];
    await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
        while (queue.length) await worker(queue.shift());
    }));
}

const PASSPHRASES = [
    () => randomBytes(16).toString('base64'),
    () => '',
    () => 'TREZOR',
    () => ' padded ',
    () => 'Ünïcödé ﬁ ẞ',
    () => randomBytes(randomInt(1, 40)).toString('hex'),
];

// Variations ethers accepts and maps to the same wallet.
const MESSY = [
    (phrase) => phrase,
    (phrase) => phrase.toUpperCase(),
    (phrase) => phrase.replaceAll(' ', '   '),
    (phrase) => phrase.replace(/(\w)(\w*)/g, (_, a, b) => a.toUpperCase() + b),
];

test(`restore matches ethers on ${CASES} random wallets`, async () => {
    const cases = Array.from({ length: CASES }, (_, i) => {
        const entropy = randomBytes([16, 20, 24, 28, 32][i % 5]);
        const passphrase = PASSPHRASES[i % PASSPHRASES.length]();
        const expected = HDNodeWallet.fromMnemonic(Mnemonic.fromEntropy(entropy, passphrase));
        const input = MESSY[randomInt(MESSY.length)](expected.mnemonic.phrase);
        return { input, passphrase, expected };
    });
    await pool(cases, async ({ input, passphrase, expected }) => {
        const res = await run(['restore', '--show-private-key', '--raw-passphrase', '--allow-online'], `${input}\n${passphrase}\n`);
        assert.equal(res.code, 0, res.stderr);
        assert.equal(field(res.stdout, 'Address'), expected.address);
        assert.equal(field(res.stdout, 'Private Key'), expected.privateKey);
    });
});

test('create output matches what ethers derives from the printed secrets', async () => {
    await pool(Array.from({ length: 24 }, (_, i) => i % 2 === 0), async (withPassphrase) => {
        const flags = withPassphrase ? ['--passphrase'] : [];
        const res = await run(['create', '--show-private-key', '--allow-online', ...flags]);
        assert.equal(res.code, 0, res.stderr);
        const wallet = HDNodeWallet.fromPhrase(field(res.stdout, 'Mnemonic'), field(res.stdout, 'Passphrase') ?? '');
        assert.equal(field(res.stdout, 'Address'), wallet.address);
        assert.equal(field(res.stdout, 'Private Key'), wallet.privateKey);
    });
});
