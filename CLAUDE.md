# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CLI utility (`ofwl`) for creating and restoring Ethereum wallets offline. Single-file Node.js app (ES module, Node ≥ 22) using `@scure/bip39`, `@scure/bip32`, `@noble/curves`, `@noble/hashes` and Node's native `crypto` module. Installed globally via npm and invoked as `ofwl <command>`.

## Commands

- `npm install` — install dependencies
- `node index.js create [--passphrase] [--index n] [--show-private-key] [--no-verify] [--allow-online]` — create a new wallet (or `ofwl create` if installed globally)
- `node index.js restore [--index n] [--show-private-key] [--raw-passphrase] [--allow-online]` — restore wallet from mnemonic (interactive prompts)
- `node index.js passphrase` — generate a random passphrase
- `npm test` — run the CLI test suite (`test/*.test.mjs`, Node's built-in `node:test`). `test/tty.test.mjs` drives the CLI in a pseudo-terminal via `script(1)` (macOS/Linux; skipped elsewhere).
- `npm run build` — build the standalone binary `dist/ofwl` via `build.sh`: copies the local `node` (must be an official, self-contained build; checked with `otool -L`/`ldd`), injects the esbuild bundle as a Node SEA, smoke-tests it and prints its SHA-256. It must never download anything. Builds are reproducible; keep `useCodeCache: false` in `sea-config.json` (the V8 code cache is nondeterministic).

CI (`.github/workflows/ci.yml`) runs `npm audit signatures`, `npm audit --omit=dev` and `npm test` on Ubuntu and macOS with Node 22/24/26, then builds the binary twice per OS and fails if the hashes differ. Pin actions by commit SHA.

Releasing: bump the version (`npm version <x.y.z> --no-git-tag-version` updates `package.json` and `npm-shrinkwrap.json`), commit, then push a tag `v<x.y.z>`. `.github/workflows/release.yml` reruns CI, checks the tag matches `package.json` and **stages** the release with `npm stage publish --provenance` via npm trusted publishing (OIDC, environment `npm`). The trusted publisher is stage-only; the maintainer approves the staged version with 2FA on npmjs.com (Staged Packages tab) or `npm stage approve <id>`. Never switch to `npm publish` or add an npm token secret. A staged version occupies its version number, so check `npm stage list` before re-running a failed release.

No linter configured. Dependencies are pinned to exact versions and locked in `npm-shrinkwrap.json` (published with the package); never use `^`/`~` ranges.

## Security constraints

`SECURITY.md` is the user-facing security guide (keep it in sync with CLI behaviour). `SECURITY_AUDIT.md` is the source of truth for the hardening plan (section 7) and maintainer decisions (section 8). Above all: derivation must never change. The vectors in `test/cli.test.mjs` guard it, so run `npm test` after every change.

## Architecture

Everything lives in `index.js` — a single script with a shebang line. `main()` takes the command from `process.argv`, parses its options with Node's built-in `util.parseArgs` (strict, per-command option sets in `COMMANDS`) and dispatches to `create`, `restore`, `passphrase`, `--help`, `--version`; each returns an exit code, which is set via `process.exitCode` (not `process.exit`, so piped stdout is flushed). Only `restore` reads input, through `createPrompter()`: on a TTY it reads keystrokes in raw mode and never echoes masked input (the prompt shows only a word/character count); with piped stdin it reads lines via readline. It re-prompts on invalid input only when interactive. `promptSecrets()` holds the shared mnemonic/passphrase input logic used by `restore` and by `verifyBackup()`, the interactive backup check after `create` (TTY only). `selfTest()` derives known vectors before `create` and `restore` and aborts on mismatch; keep its vectors in sync with the tests. `confirmOffline()` then warns if `onlineInterfaces()` finds a routable address (requires typing `yes` on a TTY, refuses otherwise) unless `--allow-online` is passed; tests pass `--allow-online` by default. Never add a real connectivity probe. Errors must never print secrets or stack traces.

Derivation: `deriveWallet()` does BIP-39 seed → BIP-32 key at `m/44'/60'/0'/0/0` → keccak256 address with EIP-55 checksum. User-entered mnemonics must go through `parseMnemonic()` (trim, lowercase, collapse whitespace, validate) before seeding, because raw `@scure/bip39` derives a different wallet from an uppercase phrase. Passphrases are used verbatim, with one exception: input shaped like a generated passphrase (26 Crockford base32 data symbols + 2 SHA-256 checksum symbols, printed as 7 dash-separated groups of 4) is normalised to its printed form by `parseGeneratedPassphrase()` unless `--raw-passphrase` is passed. v1.x base64 passphrases never match that shape.

`ethers` is a devDependency used only by `test/ethers-diff.test.mjs` as a reference implementation (it was the runtime dependency in v1.x). The standalone binary is bundled to CommonJS by esbuild (`--format=cjs`), so avoid top-level await and `import.meta` in `index.js`.
