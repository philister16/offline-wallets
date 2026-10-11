# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CLI utility (`ofwl`) for creating and restoring Ethereum wallets offline. Single-file Node.js app using ethers.js v6 and Node's native `crypto` module. Installed globally via npm and invoked as `ofwl <command>`.

## Commands

- `npm install` — install dependencies
- `node index.js create` — create a new wallet (or `ofwl create` if installed globally)
- `node index.js restore` — restore wallet from mnemonic (interactive prompts)
- `node index.js passphrase [bytes]` — generate random passphrase (default 16 bytes)
- `npm test` — run the CLI test suite (`test/*.test.mjs`, Node's built-in `node:test`)
- `npm run build` — build the standalone binary via `build.sh`

No linter configured. Dependencies are pinned to exact versions and locked in `npm-shrinkwrap.json` (published with the package); never use `^`/`~` ranges.

## Security constraints

`SECURITY_AUDIT.md` is the source of truth for the hardening plan (section 7) and maintainer decisions (section 8). Above all: derivation must never change. The vectors in `test/cli.test.mjs` guard it, so run `npm test` after every change.

## Architecture

Everything lives in `index.js` — a single script with a shebang line. It parses `process.argv` directly (no argument parsing library) and branches into commands: `create`, `restore`, `passphrase`, `--help`, `--version`. The `restore` command uses readline for interactive input; all others are non-interactive.

Key dependency: `ethers` (devDependency) provides `Mnemonic` and `HDNodeWallet` for BIP-39 mnemonic generation and HD wallet derivation.
