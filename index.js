#!/usr/bin/env node

import readline from 'node:readline';
import { stdin, stdout } from 'node:process';
import Crypto from 'node:crypto';
import { parseArgs } from 'node:util';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import pkg from './package.json' with { type: 'json' };

const MNEMONIC_LENGTHS = [12, 15, 18, 21, 24];
const MAX_INDEX = 2 ** 31 - 1;

// Generated passphrases: 26 random Crockford base32 symbols (130 bits) plus 2
// checksum symbols, printed in groups of 4. The printed form is the canonical
// BIP-39 passphrase string.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PASSPHRASE_DATA_SYMBOLS = 26;
const PASSPHRASE_SYMBOLS = PASSPHRASE_DATA_SYMBOLS + 2;

const derivationPath = (index) => `m/44'/60'/0'/0/${index}`;

// EIP-55: uppercase each hex letter whose nibble in keccak256(lowercase address) is >= 8.
function toChecksumAddress(hex) {
    const hash = bytesToHex(keccak_256(utf8ToBytes(hex)));
    return '0x' + [...hex].map((c, i) => (parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

// BIP-39 seed -> BIP-32 key at the BIP-44 Ethereum path -> address.
// `phrase` must be canonical (see parseMnemonic); the passphrase is used verbatim.
function deriveWallet(phrase, passphrase, index = 0) {
    const seed = mnemonicToSeedSync(phrase, passphrase);
    const { privateKey } = HDKey.fromMasterSeed(seed).derive(derivationPath(index));
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

// First 10 bits of SHA-256 over the data symbols, as 2 base32 symbols.
function passphraseChecksum(data) {
    const hash = Crypto.createHash('sha256').update(data).digest();
    const bits = (hash[0] << 2) | (hash[1] >> 6);
    return CROCKFORD[bits >> 5] + CROCKFORD[bits & 31];
}

const groupSymbols = (symbols) => symbols.match(/.{1,4}/g).join('-');

function generatePassphrase() {
    const data = Array.from({ length: PASSPHRASE_DATA_SYMBOLS }, () => CROCKFORD[Crypto.randomInt(32)]).join('');
    return groupSymbols(data + passphraseChecksum(data));
}

// Recognise input shaped like a generated passphrase, forgiving case, dashes,
// spaces and the Crockford look-alikes O->0, I/L->1. Returns null when the
// input is not shaped like one (e.g. a v1.x base64 passphrase), which must then
// be used verbatim. Error messages never include the input.
function parseGeneratedPassphrase(input) {
    if (!/^[0-9A-Za-z\s-]+$/.test(input)) return null;
    const symbols = input.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
    if (symbols.length !== PASSPHRASE_SYMBOLS || [...symbols].some((c) => !CROCKFORD.includes(c))) return null;
    const data = symbols.slice(0, PASSPHRASE_DATA_SYMBOLS);
    if (passphraseChecksum(data) !== symbols.slice(PASSPHRASE_DATA_SYMBOLS)) {
        return { error: 'This looks like an ofwl passphrase, but its checksum does not match. Check it for typos.' };
    }
    return { passphrase: groupSymbols(symbols) };
}

function parseIndex(value) {
    if (value === undefined) return 0;
    const index = /^\d+$/.test(value) ? Number(value) : NaN;
    return index <= MAX_INDEX ? index : null;
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
    console.log('Usage: ofwl <command> [options]');
    console.log('');
    console.log('Commands:');
    console.log('  create                Create a new wallet');
    console.log('  restore               Restore a wallet from its mnemonic (and passphrase, if any)');
    console.log('  passphrase            Generate a random passphrase (130 bits, Crockford base32)');
    console.log('  help                  Show this help message');
    console.log('');
    console.log('Options for create:');
    console.log('  --passphrase          Also generate a passphrase. You need it, and the mnemonic, to restore');
    console.log('');
    console.log('Options for create and restore:');
    console.log("  --index <n>           Address index n in the path m/44'/60'/0'/0/n (default: 0)");
    console.log('  --show-private-key    Also print the raw private key');
    console.log('');
    console.log('Options for restore:');
    console.log('  --raw-passphrase      Use the passphrase exactly as typed, even if it looks like');
    console.log('                        an ofwl passphrase (no case, dash or checksum handling)');
    console.log('');
    console.log('Global options:');
    console.log('  --help | -h           Show help');
    console.log('  --version | -v        Show version number');
}

function printWallet(wallet, index, showPrivateKey) {
    console.log('Address:     ', wallet.address);
    console.log('Path:        ', derivationPath(index));
    if (showPrivateKey) console.log('Private Key: ', wallet.privateKey);
}

function create(options, index) {
    console.log('Creating a new wallet...');
    const entropy = Crypto.randomBytes(32);
    const passphrase = options.passphrase ? generatePassphrase() : '';
    const phrase = entropyToMnemonic(entropy, wordlist);
    if (!entropy.equals(mnemonicToEntropy(phrase, wordlist))) {
        console.error('Internal error: mnemonic does not round-trip to its entropy.');
        return 1;
    }
    printWallet(deriveWallet(phrase, passphrase, index), index, options['show-private-key']);
    console.log('Mnemonic:    ', phrase);
    if (passphrase) console.log('Passphrase:  ', passphrase);
    console.log('');
    console.log('Write down the mnemonic. Anyone who has it controls the funds; without it, they are lost.');
    if (passphrase) {
        console.log('The passphrase is required too. Without it the mnemonic restores a different, empty wallet.');
        console.log('  - Store it separately from the mnemonic.');
        console.log('  - In other wallets, enter it exactly as shown (uppercase, with dashes).');
        console.log('  - If you lose it, the funds are lost. Nobody can recover it.');
    }
    return 0;
}

async function restore(options, index) {
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
            const generated = options['raw-passphrase'] ? null : parseGeneratedPassphrase(input);
            if (generated?.passphrase) {
                if (generated.passphrase !== input) {
                    console.error('Recognised an ofwl passphrase and normalised it to its printed form (uppercase, with dashes).');
                }
                passphrase = generated.passphrase;
                continue;
            }
            if (generated?.error) {
                console.error(generated.error);
                if (!interactive) {
                    console.error('To use the passphrase exactly as entered, pass --raw-passphrase.');
                    return 1;
                }
                const answer = await prompter.ask('Use it exactly as entered instead? [y/N] ');
                if (answer === null) return 1;
                if (answer.trim().toLowerCase() !== 'y') continue;
            } else if (input !== input.trim()) {
                // BIP-39 treats whitespace as significant, so never trim; warn instead.
                console.error(`Warning: the passphrase (${input.length} characters) has leading or trailing whitespace. Whitespace is part of the passphrase and changes the wallet.`);
                if (interactive) {
                    const answer = await prompter.ask('Use it as entered? [y/N] ');
                    if (answer === null) return 1;
                    if (answer.trim().toLowerCase() !== 'y') continue;
                }
            }
            passphrase = input;
        }

        printWallet(deriveWallet(phrase, passphrase, index), index, options['show-private-key']);
        return 0;
    } finally {
        prompter.close();
    }
}

function passphrase() {
    console.log('Generating a passphrase...');
    console.log('Random passphrase: ', generatePassphrase());
    return 0;
}

const HELP_OPTION = { help: { type: 'boolean', short: 'h' } };
const WALLET_OPTIONS = { ...HELP_OPTION, index: { type: 'string' }, 'show-private-key': { type: 'boolean' } };
const COMMANDS = {
    create: { run: create, options: { ...WALLET_OPTIONS, passphrase: { type: 'boolean' } } },
    restore: { run: restore, options: { ...WALLET_OPTIONS, 'raw-passphrase': { type: 'boolean' } } },
    passphrase: { run: passphrase, options: HELP_OPTION },
};

async function main(args) {
    const [name, ...rest] = args;
    if (name === undefined) {
        console.error('Expected at least one argument! Use "ofwl help" for usage info.');
        return 1;
    }
    if (['help', '--help', '-h'].includes(name)) {
        printHelp();
        return 0;
    }
    if (['--version', '-v'].includes(name)) {
        console.log(pkg.version);
        return 0;
    }
    const command = Object.hasOwn(COMMANDS, name) ? COMMANDS[name] : null;
    if (!command) {
        console.error('Invalid argument! Use "ofwl help" for usage info.');
        return 1;
    }

    let options;
    try {
        ({ values: options } = parseArgs({ args: rest, options: command.options, strict: true }));
    } catch (err) {
        console.error(`${err.message}\nUse "ofwl help" for usage info.`);
        return 1;
    }
    if (options.help) {
        printHelp();
        return 0;
    }
    const index = parseIndex(options.index);
    if (index === null) {
        console.error(`--index must be an integer from 0 to ${MAX_INDEX}.`);
        return 1;
    }
    return command.run(options, index);
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
