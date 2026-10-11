#!/usr/bin/env node

import readline from 'node:readline';
import { stdin, stdout } from 'node:process';
import Crypto from 'node:crypto';
import os from 'node:os';
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

// Known-answer self-test, run before create and restore: catches broken or
// tampered crypto libraries in a build. Vectors match test/cli.test.mjs.
function selfTest() {
    const { phrase } = parseMnemonic('TEST test test test test test test test test test test  junk');
    const { passphrase } = parseGeneratedPassphrase('bffb-m987-8ppk-v696-ednf-7b5x-yapc') ?? {};
    const a = Crypto.randomBytes(32);
    const b = Crypto.randomBytes(32);
    return (
        deriveWallet(phrase, '', 0).address === '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' &&
        deriveWallet(phrase, passphrase, 1).address === '0x97EFFd9765BDd5A8749a0ca40ecD52967b794a69' &&
        !a.equals(b) &&
        a.some((byte) => byte !== 0)
    );
}

// Names of interfaces with a routable address. Loopback/internal interfaces
// and link-local addresses (169.254.0.0/16, fe80::/10) are ignored: macOS keeps
// those on awdl0/llw0/en* even when offline. Reads local state only; no sockets.
function onlineInterfaces() {
    const isLinkLocal = ({ family, address }) =>
        family === 'IPv4' ? address.startsWith('169.254.') : /^fe[89ab][0-9a-f]:/i.test(address);
    return Object.entries(os.networkInterfaces())
        .filter(([, addresses]) => addresses.some((a) => !a.internal && !isLinkLocal(a)))
        .map(([name]) => name);
}

async function confirmOffline() {
    const interfaces = onlineInterfaces();
    if (interfaces.length === 0) return true;
    console.error('');
    console.error(`WARNING: This computer appears to be online (network interfaces: ${interfaces.join(', ')}).`);
    console.error('ofwl is meant to run on an offline, air-gapped machine. On a connected machine,');
    console.error('malware or sync and backup software could capture your secrets.');
    console.error('Disconnect from all networks (Wi-Fi, Ethernet, tethering) and run ofwl again.');
    if (!stdin.isTTY) {
        console.error('Refusing to continue without a terminal to confirm. Pass --allow-online to skip this check.');
        return false;
    }
    const prompter = createPrompter();
    try {
        const answer = await prompter.ask('Type "yes" to continue anyway: ');
        console.error('');
        return answer?.trim().toLowerCase() === 'yes';
    } finally {
        prompter.close();
    }
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
    const onData = (chunk) => {
        pending += chunk;
        if (active) active();
    };
    stdin.setEncoding('utf8');
    stdin.on('data', onData);

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
            stdin.off('data', onData);
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
    console.log('  --no-verify           Skip the interactive backup check (skipped anyway without a terminal)');
    console.log('');
    console.log('Options for create and restore:');
    console.log("  --index <n>           Address index n in the path m/44'/60'/0'/0/n (default: 0)");
    console.log('  --show-private-key    Also print the raw private key');
    console.log('  --allow-online        Skip the check that this computer is offline');
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

const CLEAR_SCREEN = '\x1b[2J\x1b[3J\x1b[H'; // screen and scrollback

function printSecrets(phrase, passphrase) {
    console.log('Mnemonic:    ', phrase);
    if (passphrase) console.log('Passphrase:  ', passphrase);
}

async function create(options, index) {
    console.log('Creating a new wallet...');
    const entropy = Crypto.randomBytes(32);
    const passphrase = options.passphrase ? generatePassphrase() : '';
    const phrase = entropyToMnemonic(entropy, wordlist);
    if (!entropy.equals(mnemonicToEntropy(phrase, wordlist))) {
        console.error('Internal error: mnemonic does not round-trip to its entropy.');
        return 1;
    }
    const wallet = deriveWallet(phrase, passphrase, index);
    printWallet(wallet, index, options['show-private-key']);
    printSecrets(phrase, passphrase);
    console.log('');
    console.log('Write down the mnemonic. Anyone who has it controls the funds; without it, they are lost.');
    if (passphrase) {
        console.log('The passphrase is required too. Without it the mnemonic restores a different, empty wallet.');
        console.log('  - Store it separately from the mnemonic.');
        console.log('  - In other wallets, enter it exactly as shown (uppercase, with dashes).');
        console.log('  - If you lose it, the funds are lost. Nobody can recover it.');
    }
    if (options['no-verify'] || !stdin.isTTY) {
        console.log('');
        console.log('Before funding this address, check your backup with "ofwl restore".');
        return 0;
    }
    return verifyBackup({ phrase, passphrase, index, address: wallet.address });
}

// Clear the screen, have the user re-enter the backup with hidden input, and
// compare. Mismatches name word positions, never the words themselves.
async function verifyBackup(expected) {
    const prompter = createPrompter();
    const notVerified = () => {
        console.error('');
        console.error('Backup NOT verified. Do not fund this address until "ofwl restore" with your backup shows it:');
        console.log('Address:     ', expected.address);
        return 1;
    };
    try {
        console.log('');
        const answer = await prompter.ask('Verify your backup now? The screen will be cleared first. [Y/n] ');
        if (answer === null) return notVerified();
        if (answer.trim().toLowerCase().startsWith('n')) {
            console.log('Skipped. Before funding this address, check your backup with "ofwl restore".');
            return 0;
        }
        for (;;) {
            stdout.write(CLEAR_SCREEN);
            console.log('Verify your backup');
            console.log(`Enter the mnemonic${expected.passphrase ? ' and passphrase' : ''} from your written backup.`);
            for (;;) {
                const entered = await promptSecrets(prompter, { interactive: true, askPassphrase: Boolean(expected.passphrase) });
                if (!entered) return notVerified();
                const { address } = deriveWallet(entered.phrase, entered.passphrase, expected.index);
                if (address === expected.address) {
                    console.log(`Backup verified. It restores ${address} (${derivationPath(expected.index)}).`);
                    return 0;
                }
                describeMismatch(expected, entered);
                const choice = (await prompter.ask('[R]etry, [s]how the secrets again, or [q]uit? '))?.trim().toLowerCase();
                if (choice === undefined || choice === 'q') return notVerified();
                if (choice === 's') {
                    printSecrets(expected.phrase, expected.passphrase);
                    if ((await prompter.ask('Correct your backup, then press Enter to clear the screen and verify again. ')) === null) {
                        return notVerified();
                    }
                    break;
                }
            }
        }
    } finally {
        prompter.close();
    }
}

function describeMismatch(expected, entered) {
    if (entered.phrase !== expected.phrase) {
        const want = expected.phrase.split(' ');
        const got = entered.phrase.split(' ');
        if (got.length !== want.length) {
            console.error(`Mismatch: you entered ${got.length} words, the wallet has ${want.length}.`);
        } else {
            const positions = want.flatMap((word, i) => (word === got[i] ? [] : [`#${i + 1}`]));
            console.error(`Mismatch: word${positions.length === 1 ? '' : 's'} ${positions.join(', ')} ${positions.length === 1 ? 'differs' : 'differ'}.`);
        }
    }
    if (entered.passphrase !== expected.passphrase) console.error('Mismatch: the passphrase differs.');
}

// Prompts for the mnemonic and (optionally) the passphrase. Returns
// { phrase, passphrase }, or null after reporting why input was not accepted.
async function promptSecrets(prompter, { interactive, raw = false, askPassphrase = true }) {
    let phrase;
    while (!phrase) {
        const input = await prompter.ask('Enter mnemonic: ', { mask: 'words' });
        if (input === null) {
            console.error('\nNo mnemonic entered.');
            return null;
        }
        const result = parseMnemonic(input);
        if (result.error) {
            console.error(result.error);
            if (!interactive) return null;
        } else {
            phrase = result.phrase;
        }
    }
    if (!askPassphrase) return { phrase, passphrase: '' };

    for (;;) {
        const input = await prompter.ask('Enter passphrase: ', { mask: 'chars' });
        if (input === null) {
            console.error('\nNo passphrase entered (press Enter for none).');
            return null;
        }
        const generated = raw ? null : parseGeneratedPassphrase(input);
        if (generated?.passphrase) {
            if (generated.passphrase !== input) {
                console.error('Recognised an ofwl passphrase and normalised it to its printed form (uppercase, with dashes).');
            }
            return { phrase, passphrase: generated.passphrase };
        }
        if (generated?.error) {
            console.error(generated.error);
            if (!interactive) {
                console.error('To use the passphrase exactly as entered, pass --raw-passphrase.');
                return null;
            }
            const answer = await prompter.ask('Use it exactly as entered instead? [y/N] ');
            if (answer === null) return null;
            if (answer.trim().toLowerCase() !== 'y') continue;
        } else if (input !== input.trim()) {
            // BIP-39 treats whitespace as significant, so never trim; warn instead.
            console.error(`Warning: the passphrase (${input.length} characters) has leading or trailing whitespace. Whitespace is part of the passphrase and changes the wallet.`);
            if (interactive) {
                const answer = await prompter.ask('Use it as entered? [y/N] ');
                if (answer === null) return null;
                if (answer.trim().toLowerCase() !== 'y') continue;
            }
        }
        return { phrase, passphrase: input };
    }
}

async function restore(options, index) {
    console.log('Restoring a wallet...');
    const prompter = createPrompter();
    try {
        const secrets = await promptSecrets(prompter, { interactive: Boolean(stdin.isTTY), raw: options['raw-passphrase'] });
        if (!secrets) return 1;
        printWallet(deriveWallet(secrets.phrase, secrets.passphrase, index), index, options['show-private-key']);
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
const WALLET_OPTIONS = {
    ...HELP_OPTION,
    index: { type: 'string' },
    'show-private-key': { type: 'boolean' },
    'allow-online': { type: 'boolean' },
};
const COMMANDS = {
    create: { run: create, walletCommand: true, options: { ...WALLET_OPTIONS, passphrase: { type: 'boolean' }, 'no-verify': { type: 'boolean' } } },
    restore: { run: restore, walletCommand: true, options: { ...WALLET_OPTIONS, 'raw-passphrase': { type: 'boolean' } } },
    passphrase: { run: passphrase, walletCommand: false, options: HELP_OPTION },
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
    if (command.walletCommand) {
        if (!selfTest()) {
            console.error('Self-test failed: this build of ofwl derives wrong keys or has no working random source. Do not use it.');
            return 1;
        }
        if (!options['allow-online'] && !(await confirmOffline())) {
            console.error('Aborted.');
            return 1;
        }
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
