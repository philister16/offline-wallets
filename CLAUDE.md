# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CLI utility (`ofwl`) for creating and restoring Ethereum wallets offline. Single-file Node.js app (ES module, Node ≥ 20.19) using `@scure/bip39`, `@scure/bip32`, `@noble/curves`, `@noble/hashes` and Node's native `crypto` module. Installed globally via npm and invoked as `ofwl <command>`.

## Commands

- `npm install` — install dependencies
- `node index.js create [--passphrase] [--index n] [--show-private-key]` — create a new wallet (or `ofwl create` if installed globally)
- `node index.js restore [--index n] [--show-private-key] [--raw-passphrase]` — restore wallet from mnemonic (interactive prompts)
- `node index.js passphrase` — generate a random passphrase
- `npm test` — run the CLI test suite (`test/*.test.mjs`, Node's built-in `node:test`). `test/tty.test.mjs` drives the CLI in a pseudo-terminal via `script(1)` (macOS/Linux; skipped elsewhere).
- `npm run build` — build the standalone binary via `build.sh`

No linter configured. Dependencies are pinned to exact versions and locked in `npm-shrinkwrap.json` (published with the package); never use `^`/`~` ranges.

## Security constraints

`SECURITY_AUDIT.md` is the source of truth for the hardening plan (section 7) and maintainer decisions (section 8). Above all: derivation must never change. The vectors in `test/cli.test.mjs` guard it, so run `npm test` after every change.

## Architecture

Everything lives in `index.js` — a single script with a shebang line. `main()` takes the command from `process.argv`, parses its options with Node's built-in `util.parseArgs` (strict, per-command option sets in `COMMANDS`) and dispatches to `create`, `restore`, `passphrase`, `--help`, `--version`; each returns an exit code, which is set via `process.exitCode` (not `process.exit`, so piped stdout is flushed). Only `restore` reads input, through `createPrompter()`: on a TTY it reads keystrokes in raw mode and never echoes masked input (the prompt shows only a word/character count); with piped stdin it reads lines via readline. It re-prompts on invalid input only when interactive. Errors must never print secrets or stack traces.

Derivation: `deriveWallet()` does BIP-39 seed → BIP-32 key at `m/44'/60'/0'/0/0` → keccak256 address with EIP-55 checksum. User-entered mnemonics must go through `parseMnemonic()` (trim, lowercase, collapse whitespace, validate) before seeding, because raw `@scure/bip39` derives a different wallet from an uppercase phrase. Passphrases are used verbatim, with one exception: input shaped like a generated passphrase (26 Crockford base32 data symbols + 2 SHA-256 checksum symbols, printed as 7 dash-separated groups of 4) is normalised to its printed form by `parseGeneratedPassphrase()` unless `--raw-passphrase` is passed. v1.x base64 passphrases never match that shape.

`ethers` is a devDependency used only by `test/ethers-diff.test.mjs` as a reference implementation (it was the runtime dependency in v1.x). The standalone binary is bundled to CommonJS by esbuild (`--format=cjs`), so avoid top-level await and `import.meta` in `index.js`.
