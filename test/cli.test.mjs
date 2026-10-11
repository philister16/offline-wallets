// CLI tests: spawn index.js and drive it through piped stdin.
//
// The vectors below are the guard for "derivation must not change": for any
// (mnemonic, passphrase) pair, restore must return the same address as v1.2.0.
// All mnemonics and keys in this file are public test data. Never fund them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../index.js', import.meta.url));

function run(args, input = '') {
    const res = spawnSync(process.execPath, [CLI, ...args], { input, encoding: 'utf8' });
    return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

function field(stdout, label) {
    // Prompts and output share a line when stdin is piped, so no ^ anchor.
    const match = stdout.match(new RegExp(`${label}:[ \\t]+(\\S.*)$`, 'm'));
    return match ? match[1].trim() : undefined;
}

function restore(mnemonic, passphrase) {
    const res = run(['restore'], `${mnemonic}\n${passphrase}\n`);
    assert.equal(res.code, 0, res.stderr);
    return { address: field(res.stdout, 'Address'), privateKey: field(res.stdout, 'Private Key') };
}

const TEST_JUNK = 'test test test test test test test test test test test junk';

// Standard vectors. Seeds for the TREZOR cases were cross-checked against the
// official BIP-39 vectors; addresses are m/44'/60'/0'/0/0.
const KNOWN_VECTORS = [
    { name: 'Hardhat/Anvil default', mnemonic: TEST_JUNK, passphrase: '', address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' },
    { name: 'abandon ... about', mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', passphrase: '', address: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94' },
    { name: 'BIP-39 128-bit zero, TREZOR', mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', passphrase: 'TREZOR', address: '0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6' },
    { name: 'BIP-39 128-bit 7f, TREZOR', mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow', passphrase: 'TREZOR', address: '0x6006ef1944FB519A746d00cDAf715Cbd27a5a008' },
    { name: 'BIP-39 256-bit zero, TREZOR', mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art', passphrase: 'TREZOR', address: '0x2b5D7A0E9d3EC34D629D07c6bDE5c41fb613c655' },
    { name: 'Unicode passphrase (NFKD)', mnemonic: TEST_JUNK, passphrase: 'Ünïcödé ﬁ', address: '0x5b4287b1aDEcfBd2B477485b81E1D77DB8a2FffE' },
];

// Wallets created by `ofwl create` v1.2.0 (24 words, base64 passphrase).
const FROZEN_V1 = [
    {
        mnemonic: 'item border barely away favorite whip dynamic history glass enter oil void claim lottery cover wish couple marine settle spare impulse remind butter panel',
        passphrase: 'fuIIP2QeNYE8cZ2ypShEPw==',
        address: '0x2798E08f084cE9c77a19f2bcc6f9DB68f7A7fa3E',
        privateKey: '0xeeb0761afc092164ae168ddfa0e52001a7a7f33016c30251e36fa1354897acac',
    },
    {
        mnemonic: 'load path option turtle car orange exile midnight borrow valley employ rose ladder print parade tortoise mind clap off wide flag fringe hungry theme',
        passphrase: 'nZ9W/KzqhV671oeWHz/zqw==',
        address: '0xbaC7D3805668136BAA03E07D7b3664B4E53cf668',
        privateKey: '0x900549fbf34645d96044354e14daaac60cdcce7a9f2fbc55d28d23f580cb5927',
    },
    {
        mnemonic: 'enemy excuse win long parent thought scorpion walk solar across exist story almost whisper rebel sing october rhythm seek magic vault eager gauge cheese',
        passphrase: 'nyWCa47MItTMn7IiA4LL5g==',
        address: '0x9283a33D01500d720D6EdE41D15034eB008890EB',
        privateKey: '0xd02f1dbb5020af95a93c66d26e45a9afa5b8901e8cf5920647aebd532ca8d489',
    },
];

for (const v of KNOWN_VECTORS) {
    test(`restore: ${v.name}`, () => {
        assert.equal(restore(v.mnemonic, v.passphrase).address, v.address);
    });
}

test('restore: private key for the Hardhat/Anvil default', () => {
    assert.equal(restore(TEST_JUNK, '').privateKey, '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
});

for (const [i, v] of FROZEN_V1.entries()) {
    test(`restore: frozen v1.2.0 wallet #${i + 1}`, () => {
        assert.deepEqual(restore(v.mnemonic, v.passphrase), { address: v.address, privateKey: v.privateKey });
    });
}

test('restore: mnemonic is case-insensitive and tolerates repeated inner whitespace', () => {
    const { mnemonic, passphrase, address } = FROZEN_V1[0];
    assert.equal(restore(mnemonic.toUpperCase(), passphrase).address, address);
    assert.equal(restore(mnemonic.replaceAll(' ', '  \t'), passphrase).address, address);
});

test('restore: passphrase is whitespace-sensitive (BIP-39, must not be trimmed)', () => {
    const { mnemonic, passphrase, address } = FROZEN_V1[0];
    assert.notEqual(restore(mnemonic, passphrase + ' ').address, address);
});

test('restore: leading/trailing whitespace around the mnemonic restores correctly', () => {
    const { mnemonic, passphrase, address } = FROZEN_V1[0];
    assert.equal(restore(`  ${mnemonic} \t`, passphrase).address, address);
});

test('restore: passphrase with surrounding whitespace warns but is used verbatim', () => {
    const res = run(['restore'], `${TEST_JUNK}\n TREZOR\n`);
    assert.equal(res.code, 0, res.stderr);
    assert.match(res.stderr, /Warning: the passphrase \(7 characters\) has leading or trailing whitespace/);
    assert.notEqual(field(res.stdout, 'Address'), restore(TEST_JUNK, 'TREZOR').address);
});

test('restore: invalid mnemonics fail with a friendly message, no stack trace, no echo', () => {
    const words = FROZEN_V1[0].mnemonic.split(' ');
    const cases = [
        { input: words.slice(0, 23).join(' '), message: /Expected 12, 15, 18, 21 or 24 words, got 23\./ },
        { input: [...words.slice(0, 5), 'notaword', ...words.slice(6)].join(' '), message: /Word #6 is not in the BIP-39 English word list\./ },
        { input: [words[1], words[0], ...words.slice(2)].join(' '), message: /Checksum mismatch/ },
        { input: '', message: /got 0\./ },
    ];
    for (const { input, message } of cases) {
        const res = run(['restore'], `${input}\nsecret-pass\n`);
        assert.equal(res.code, 1);
        assert.match(res.stderr, message);
        assert.doesNotMatch(res.stderr, /\n\s+at /, 'stack trace printed');
        assert.doesNotMatch(res.stdout + res.stderr, /secret-pass|notaword/, 'input echoed in output');
        if (input) assert.ok(!(res.stdout + res.stderr).includes(input), 'mnemonic echoed in output');
    }
});

test('restore: input ending early exits 1 without deriving', () => {
    for (const input of ['', `${TEST_JUNK}\n`]) {
        const res = run(['restore'], input);
        assert.equal(res.code, 1);
        assert.equal(field(res.stdout, 'Address'), undefined);
    }
});

test('create: output restores to the same wallet', () => {
    const res = run(['create']);
    assert.equal(res.code, 0, res.stderr);
    const mnemonic = field(res.stdout, 'Mnemonic');
    const passphrase = field(res.stdout, 'Passphrase');
    assert.equal(mnemonic.split(' ').length, 24);
    assert.deepEqual(restore(mnemonic, passphrase), {
        address: field(res.stdout, 'Address'),
        privateKey: field(res.stdout, 'Private Key'),
    });
});

test('create: two runs produce different wallets', () => {
    assert.notEqual(field(run(['create']).stdout, 'Mnemonic'), field(run(['create']).stdout, 'Mnemonic'));
});

test('passphrase: default is 16 random bytes', () => {
    const res = run(['passphrase']);
    assert.equal(res.code, 0, res.stderr);
    assert.equal(Buffer.from(field(res.stdout, 'Random passphrase'), 'base64').length, 16);
});

test('passphrase: custom byte length', () => {
    assert.equal(Buffer.from(field(run(['passphrase', '32']).stdout, 'Random passphrase'), 'base64').length, 32);
});

test('passphrase: rejects invalid lengths', () => {
    for (const arg of ['abc', '0', '257']) {
        assert.notEqual(run(['passphrase', arg]).code, 0, `accepted ${arg}`);
    }
});

test('help and version exit 0', () => {
    assert.equal(run(['--help']).code, 0);
    assert.match(run(['--version']).stdout, /^\d+\.\d+\.\d+\s*$/);
});

test('missing or unknown command exits non-zero', () => {
    assert.notEqual(run([]).code, 0);
    assert.notEqual(run(['bogus']).code, 0);
});
