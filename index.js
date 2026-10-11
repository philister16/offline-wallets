#!/usr/bin/env node

import readline from 'node:readline';
import { stdin, stdout } from 'node:process';
import Crypto from 'node:crypto';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import pkg from './package.json' with { type: 'json' };

const DERIVATION_PATH = "m/44'/60'/0'/0/0";
const MNEMONIC_LENGTHS = [12, 15, 18, 21, 24];

// EIP-55: uppercase each hex letter whose nibble in keccak256(lowercase address) is >= 8.
function toChecksumAddress(hex) {
    const hash = bytesToHex(keccak_256(utf8ToBytes(hex)));
    return '0x' + [...hex].map((c, i) => (parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

// BIP-39 seed -> BIP-32 key at the BIP-44 Ethereum path -> address.
// `phrase` must be canonical (see parseMnemonic); the passphrase is used verbatim.
function deriveWallet(phrase, passphrase) {
    const seed = mnemonicToSeedSync(phrase, passphrase);
    const { privateKey } = HDKey.fromMasterSeed(seed).derive(DERIVATION_PATH);
    const publicKey = secp256k1.getPublicKey(privateKey, false);
    const address = toChecksumAddress(bytesToHex(keccak_256(publicKey.subarray(1)).subarray(-20)));
    return { address, privateKey: '0x' + bytesToHex(privateKey) };
}

// Canonicalise user input to lowercase words joined by single spaces, which is
// what ethers (v1.x) did implicitly. Without this, an uppercase phrase would
// seed a different, valid wallet. Error messages never include the input.
function parseMnemonic(input) {
    const trimmed = input.trim();
    const words = trimmed ? trimmed.toLowerCase().split(/\s+/) : [];
    if (!MNEMONIC_LENGTHS.includes(words.length)) {
        return { error: `Expected 12, 15, 18, 21 or 24 words, got ${words.length}.` };
    }
    const unknown = words.findIndex((word) => !wordlist.includes(word));
    if (unknown !== -1) {
        return { error: `Word #${unknown + 1} is not in the BIP-39 English word list.` };
    }
    const phrase = words.join(' ');
    if (!validateMnemonic(phrase, wordlist)) {
        return { error: 'Checksum mismatch: a word is wrong or the words are out of order.' };
    }
    return { phrase };
}

// ask(prompt, { mask }) resolves to the entered line, or null once input ends
// or the user aborts. On a TTY, masked input is never echoed: the prompt only
// shows a live word or character count. Piped input is read line by line.
function createPrompter() {
    return stdin.isTTY ? createTTYPrompter() : createLinePrompter();
}

const MASKS = {
    words: (value) => {
        const count = value.trim() ? value.trim().split(/\s+/).length : 0;
        return `[${count} word${count === 1 ? '' : 's'}]`;
    },
    chars: (value) => {
        const count = [...value].length;
        return `[${count} character${count === 1 ? '' : 's'}]`;
    },
};

// Reads keystrokes in raw mode. Keeps bytes after Enter for the next prompt, so
// pasting "mnemonic\npassphrase\n" in one go works.
function createTTYPrompter() {
    let pending = '';
    let active = null;
    const restore = () => stdin.setRawMode(false);
    process.on('exit', restore);
    stdin.setEncoding('utf8');
    stdin.on('data', (chunk) => {
        pending += chunk;
        if (active) active();
    });

    return {
        ask(prompt, { mask } = {}) {
            const render = mask ? MASKS[mask] : (value) => value;
            let value = '';
            let escape = false;
            const draw = () => stdout.write(`\r\x1b[K${prompt}${value ? render(value) : ''}`);
            stdin.setRawMode(true);
            stdin.resume();
            draw();
            return new Promise((resolve) => {
                const finish = (result) => {
                    active = null;
                    stdin.setRawMode(false);
                    stdin.pause();
                    stdout.write('\n');
                    resolve(result);
                };
                active = () => {
                    while (pending) {
                        const [ch] = pending;
                        pending = pending.slice(ch.length);
                        if (escape) {
                            // Skip ANSI sequences (arrow keys etc.): ESC [ ... final byte.
                            if (ch !== '[' && ch !== 'O' && ch >= '@' && ch <= '~') escape = false;
                            continue;
                        }
                        if (ch === '\r' || ch === '\n') {
                            if (ch === '\r' && pending[0] === '\n') pending = pending.slice(1);
                            return finish(value);
                        }
                        if (ch === '\u0003') return finish(null); // Ctrl-C
                        if (ch === '\u0004' && !value) return finish(null); // Ctrl-D
                        if (ch === '\u007f' || ch === '\b') value = [...value].slice(0, -1).join('');
                        else if (ch === '\u0015') value = ''; // Ctrl-U
                        else if (ch === '\x1b') escape = true;
                        else if (ch >= ' ') value += ch;
                        draw();
                    }
                };
                active();
            });
        },
        close() {
            stdin.pause();
            process.off('exit', restore);
        },
    };
}

// Piped stdin can deliver several lines in one chunk, so lines are queued.
function createLinePrompter() {
    const rl = readline.createInterface({ input: stdin, output: stdout, terminal: false });
    const lines = [];
    const waiting = [];
    let closed = false;
    rl.on('line', (line) => (waiting.length ? waiting.shift()(line) : lines.push(line)));
    rl.on('close', () => {
        closed = true;
        while (waiting.length) waiting.shift()(null);
    });
    return {
        ask(prompt) {
            rl.setPrompt(prompt);
            rl.prompt();
            if (lines.length) return Promise.resolve(lines.shift());
            if (closed) return Promise.resolve(null);
            return new Promise((resolve) => waiting.push(resolve));
        },
        close() {
            rl.close();
        },
    };
}

function printHelp() {
    console.log(`ofwl v${pkg.version}`);
    console.log('');
    console.log('Usage: ofwl <command>');
    console.log('');
    console.log('Commands:');
    console.log('  create              Create a new wallet');
    console.log('  restore             Restore a wallet from mnemonic');
    console.log('  passphrase [bytes]  Generate a random passphrase (default: 16 bytes)');
    console.log('  help                Show this help message');
    console.log('');
    console.log('Options:');
    console.log('  --help | -h         Show help');
    console.log('  --version | -v      Show version number');
}

function create() {
    console.log('Creating a new wallet...');
    const entropy = Crypto.randomBytes(32);
    const passphrase = Crypto.randomBytes(16).toString('base64');
    const phrase = entropyToMnemonic(entropy, wordlist);
    if (!entropy.equals(mnemonicToEntropy(phrase, wordlist))) {
        console.error('Internal error: mnemonic does not round-trip to its entropy.');
        return 1;
    }
    const wallet = deriveWallet(phrase, passphrase);
    console.log('Address:     ', wallet.address);
    console.log('Private Key: ', wallet.privateKey);
    console.log('Mnemonic:    ', phrase);
    console.log('Passphrase:  ', passphrase);
    return 0;
}

async function restore() {
    console.log('Restoring a wallet...');
    const interactive = Boolean(stdin.isTTY);
    const prompter = createPrompter();
    try {
        let phrase;
        while (!phrase) {
            const input = await prompter.ask('Enter mnemonic: ', { mask: 'words' });
            if (input === null) {
                console.error('\nNo mnemonic entered.');
                return 1;
            }
            const result = parseMnemonic(input);
            if (result.error) {
                console.error(result.error);
                if (!interactive) return 1;
            } else {
                phrase = result.phrase;
            }
        }

        let passphrase;
        while (passphrase === undefined) {
            const input = await prompter.ask('Enter passphrase: ', { mask: 'chars' });
            if (input === null) {
                console.error('\nNo passphrase entered (press Enter for none).');
                return 1;
            }
            // BIP-39 treats whitespace as significant, so never trim; warn instead.
            if (input !== input.trim()) {
                console.error(`Warning: the passphrase (${input.length} characters) has leading or trailing whitespace. Whitespace is part of the passphrase and changes the wallet.`);
                if (interactive) {
                    const answer = await prompter.ask('Use it as entered? [y/N] ');
                    if (answer === null) return 1;
                    if (answer.trim().toLowerCase() !== 'y') continue;
                }
            }
            passphrase = input;
        }

        const wallet = deriveWallet(phrase, passphrase);
        console.log('Address:     ', wallet.address);
        console.log('Private Key: ', wallet.privateKey);
        return 0;
    } finally {
        prompter.close();
    }
}

function passphrase(arg) {
    console.log('Generating a passphrase...');
    let passLength = 16;
    if (arg !== undefined) {
        passLength = parseInt(arg, 10);
        if (Number.isNaN(passLength) || passLength < 1 || passLength > 256) {
            console.error('Byte length must be a number between 1 and 256.');
            return 1;
        }
    }
    console.log('Random passphrase: ', Crypto.randomBytes(passLength).toString('base64'));
    return 0;
}

async function main(args) {
    switch (args[0]) {
        case undefined:
            console.error('Expected at least one argument! Use "ofwl help" for usage info.');
            return 1;
        case 'help':
        case '--help':
        case '-h':
            printHelp();
            return 0;
        case '--version':
        case '-v':
            console.log(pkg.version);
            return 0;
        case 'create':
            return create();
        case 'restore':
            return restore();
        case 'passphrase':
            return passphrase(args[1]);
        default:
            console.error('Invalid argument! Use "ofwl help" for usage info.');
            return 1;
    }
}

// Let the process exit naturally so piped stdout is fully flushed. Unexpected
// errors are reported without their message, which could contain secrets.
main(process.argv.slice(2)).then(
    (code) => {
        process.exitCode = code;
    },
    (err) => {
        console.error(`Unexpected error (${err?.name ?? 'unknown'}). Details are hidden because they could contain secrets.`);
        process.exitCode = 1;
    },
);
