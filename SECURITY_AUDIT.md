# Security Audit: `offline-wallets` (`ofwl`)

| | |
|---|---|
| **Audited revision** | `9ab036a` (v1.2.0, branch `main`) |
| **Audit date** | 2026-10-11 |
| **Scope** | `index.js`, `package.json`, `package-lock.json`, `build.sh`, `sea-config.json`, `readme.md`, published npm tarball `offline-wallets@1.2.0` |
| **Method** | Manual code review, runtime probing of every command, known-answer tests against BIP-39 / BIP-44 vectors, independent seed recomputation with `node:crypto`, `npm audit`, diff of the published npm tarball against the repo, scan of git history for leaked secrets |
| **Intended readers** | AI coding agents and the maintainer. Section 7 is the actionable task list. |

---

## 1. Verdict

**The cryptography is correct and the entropy is sufficient. The tool's risk is in its surroundings, not in the key generation itself.**

- Key generation uses the OS CSPRNG, 256 bits of entropy, standard BIP-39 → BIP-32 → BIP-44 (`m/44'/60'/0'/0/0`). It was verified against known-answer vectors (section 3).
- The main risks, in order:
  1. **Supply-chain integrity of the code that runs.** Dependency versions are not pinned at install time, and `build.sh` downloads the Node runtime without verifying it.
  2. **User-error fund loss.** The mandatory random base64 passphrase is hard to transcribe, nothing checks that the backup was written down correctly, and a mistake is permanent and silent.
  3. **Secret exposure on a general-purpose computer.** The private key is always printed, restore input is echoed, and nothing checks whether the machine is offline.

**Practical recommendation:** the tool is safe for real use only if the following holds:
- It runs on an air-gapped, ephemeral OS (e.g. a live USB with networking disabled).
- It is built from a pinned and verified dependency set.
- The user restores the backup before funding the address.

For significant amounts, a hardware wallet remains the better default, because keys never appear on a general-purpose screen. Once the High findings are fixed, this tool is a reasonable way to generate cold-storage addresses.

### Findings summary

| ID | Severity | Title |
|---|---|---|
| F-01 | **High** | Runtime dependencies are not pinned for end users (`^` range, lockfile not published) |
| F-02 | **High** | `build.sh` downloads the Node.js runtime with no checksum or signature verification |
| F-03 | **High** | Mandatory random passphrase: base64 encoding is error-prone, printed with the mnemonic, no storage guidance |
| F-04 | Medium | No backup verification before the user funds the wallet |
| F-05 | Medium | `restore` echoes mnemonic and passphrase to the terminal |
| F-06 | Medium | Raw private key always printed |
| F-07 | Medium | `restore` crashes on trivial input issues; trailing whitespace in the passphrase silently gives a different wallet |
| F-08 | Medium | No check or warning when the machine is online |
| F-09 | Medium | Large dependency surface (ethers pulls in `ws` with open advisories, provider code, etc.) |
| F-10 | Medium | No tests and no runtime known-answer self-test |
| F-11 | Low | No npm provenance or published release checksums |
| F-12 | Low | `passphrase` command allows output as small as 1 byte (8 bits) |
| F-13 | Low | Derivation path not shown; only account index 0 |
| F-14 | Low | Code hygiene: readline opened for every command, tautological validity check, dead branch |
| F-15 | Low | Documentation is inconsistent with behaviour; no operational security guide |
| F-16 | Info | Secrets cannot be zeroed in JS memory; swap/hibernation exposure |

---

## 2. Threat model

| Asset | Threat | Relevant findings |
|---|---|---|
| Mnemonic + passphrase + private key | Malicious or compromised code (npm dependency, Node binary) exfiltrates or biases keys | F-01, F-02, F-09, F-10, F-11 |
| Same | Network-connected host leaks secrets (malware, sync, telemetry) | F-08, F-16 |
| Same | Shoulder-surfing, terminal scrollback, screen recording, tmux/terminal logs | F-05, F-06 |
| Funds | User cannot restore due to transcription error or lost passphrase | F-03, F-04, F-07 |
| Funds | User restores in another wallet and sees a different address | F-13 |

Out of scope: physical security of paper backups, and compromise of the hardware or firmware of the air-gapped machine.

---

## 3. Entropy and cryptographic correctness (verified)

| Check | Result |
|---|---|
| RNG source | `crypto.randomBytes` → OpenSSL `RAND_bytes`, seeded from the OS (`getrandom`/`getentropy`). Cryptographically secure. On Linux, `getrandom` blocks until the kernel CSPRNG is seeded, so there is no early-boot weakness. |
| Mnemonic entropy | 32 bytes = **256 bits** → 24 words (256 bits + 8 checksum bits). This exceeds secp256k1's ~128-bit security level. |
| Passphrase entropy | 16 bytes = **128 bits**, base64-encoded (24 chars including `==`). |
| BIP-39 phrase | All-zero 256-bit entropy → `abandon ×23 art`. ✅ |
| BIP-39 seed | ethers `computeSeed()` output matches an independent `pbkdf2Sync(NFKD(phrase), "mnemonic"+pass, 2048, 64, sha512)`. ✅ |
| BIP-44 Ethereum address | `test test … junk` → `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` at `m/44'/60'/0'/0/0`. ✅ |
| Passphrase normalisation | ethers applies NFKD per BIP-39. ✅ |
| Error leakage | ethers redacts the mnemonic in errors (`value="[ REDACTED ]"`). ✅ |
| CLI secrets in shell history | `restore` takes secrets via prompt, not argv. ✅ |
| Published package | `offline-wallets@1.2.0` tarball `index.js` is byte-identical to the repo. ✅ |
| Git history | No private keys or mnemonics found (hex/mnemonic pattern scan; hits were only curve constants from a `node_modules` tree that was once committed and later removed). ✅ |

**Conclusion:** entropy is sufficient and derivation is standards-compliant. Wallets created by `ofwl` interoperate with MetaMask, Ledger, Trezor and others, provided the user also enters the passphrase (the "25th word") and uses path `m/44'/60'/0'/0/0`.

---

## 4. Findings

Each finding has a location, the evidence observed, the impact, and a fix with acceptance criteria.

### F-01 · High · Runtime dependencies are not pinned for end users

- **Location:** [package.json](package.json) `"ethers": "^6.16.0"`
- **Evidence:** `npm install -g offline-wallets` ignores `package-lock.json`, which npm never publishes for packages. Each install resolves to the newest `6.x` and all its transitive deps. `npm outdated` already shows ethers `6.17.0` as "wanted", which is not the audited version.
- **Impact:** a compromised ethers or `@noble/*` release (npm account takeovers that target crypto keys have happened, e.g. `@solana/web3.js` in Dec 2024) would run inside the key-generation process on every new install. The audited code is not the code users run.
- **Fix:**
  1. Pin exact versions (`"ethers": "6.x.y"`, no `^`/`~`) for all dependencies.
  2. Add `npm-shrinkwrap.json` (`npm shrinkwrap`); it *is* published and honoured by global installs. Add it to `"files"`.
  3. In the readme, replace `npm install` with `npm ci` for the build path.
- **Acceptance:** `npm pack --dry-run` lists `npm-shrinkwrap.json`. No `^` or `~` remains in `package.json`. A fresh `npm install -g ./offline-wallets-*.tgz` resolves exactly the shrinkwrapped tree.

### F-02 · High · Node.js runtime downloaded without integrity verification

- **Location:** [build.sh:27-29](build.sh#L27-L29)
- **Evidence:** `curl -sL "$DOWNLOAD_URL" -o …` followed directly by `tar -xzf`. There is no SHA-256 check and no GPG check. `-f` is missing, so HTTP errors are not reported as such.
- **Impact:** the downloaded binary *is* the runtime that generates keys on the air-gapped machine. A tampered mirror, compromised CDN, or TLS-intercepting proxy produces a backdoored wallet generator, with no way for the user to detect it.
- **Fix:**
  1. Use `curl -fsSL --proto '=https' --tlsv1.2`.
  2. Download `SHASUMS256.txt` and `SHASUMS256.txt.sig` from the same release directory.
  3. Verify the signature with `gpg --verify` against the Node.js release keys (fetched from the `nodejs/release-keys` repo, or pin the fingerprints in the script). Abort if verification fails.
  4. Verify the tarball with `shasum -a 256 -c` (macOS) or `sha256sum -c` (Linux), filtering `SHASUMS256.txt` to the one tarball line. Abort if it does not match.
  5. Print the final `dist/ofwl` SHA-256 at the end of the build so users can record and compare it.
- **Acceptance:** corrupting one byte of the downloaded tarball makes `build.sh` exit non-zero before `postject` runs. A missing `gpg` binary is a hard error, not a skip.

### F-03 · High · Mandatory random passphrase: encoding, co-location, and loss risk

- **Location:** [index.js:45](index.js#L45), [index.js:52-55](index.js#L52-L55), [index.js:81](index.js#L81)
- **Evidence:**
  - Every wallet gets a 128-bit base64 passphrase, e.g. `XIgfmNNk8QR8dKzOPatmwg==`. In a 10,000-sample run, **91%** contained at least one visually ambiguous or awkward character (`0 O I l 1 + /`). The string is case-sensitive and has no checksum.
  - The passphrase is printed directly beneath the mnemonic, with no guidance that it must be stored separately.
  - A wrong passphrase does not fail. It derives a different valid wallet (verified: an empty passphrase or one trailing space → different address).
- **Impact:**
  - One transcription error means **permanent, undetectable loss of funds**. 128 bits cannot be brute-forced, even with partial knowledge.
  - If the user stores the passphrase next to the mnemonic, it adds no security and only adds failure modes.
  - This is the most likely way a user loses money with this tool.
- **Fix (requires maintainer decision on the default; see T9):**
  1. Encode generated passphrases in a transcription-safe format with built-in error detection. Recommended: **BIP-39 words** (12 words = 128 bits, with a checksum, and users already know how to write these down). The passphrase string is then the space-joined words. Alternative: Crockford base32 in groups of 4.
  2. Add `--no-passphrase` (or make the passphrase opt-in via `--passphrase`), and document the trade-off.
  3. Print an explicit warning after `create`: the passphrase is required for recovery, it is case- and whitespace-sensitive, it should be stored *separately* from the mnemonic, and losing it means losing the funds.
  4. **Do not** change how an existing passphrase string is fed into BIP-39. `restore` must keep producing the same address for every `(mnemonic, passphrase)` pair ever created by v1.x.
- **Acceptance:** `ofwl create` prints the warning. `ofwl create --no-passphrase` yields a wallet restorable with an empty passphrase. Base64 passphrases from v1.x still restore to their original addresses (test vector).

### F-04 · Medium · No backup verification

- **Location:** `create` flow, [index.js:42-57](index.js#L42-L57)
- **Evidence:** `create` prints the secrets and exits. Nothing makes the user prove the backup is correct, and the readme does not tell them to.
- **Impact:** errors are only discovered at recovery time, when they are unfixable. Combined with F-03, this is the main way funds get lost.
- **Fix:**
  1. After printing, prompt (TTY only): "Verify your backup now? [Y/n]". Clear the screen (`\x1b[2J\x1b[3J\x1b[H`) and ask the user to re-enter the mnemonic and passphrase using masked input (F-05). Derive the address and compare. Report match or mismatch, and loop on mismatch.
  2. Add `--no-verify` for scripted or non-TTY use. Skip automatically when `!process.stdin.isTTY`.
  3. Readme: "Always run `ofwl restore` and confirm the address before sending funds."
- **Acceptance:** entering one wrong word or a wrong passphrase character during verification reports a mismatch. A correct entry reports a match.

### F-05 · Medium · `restore` echoes secrets to the terminal

- **Location:** [index.js:61-62](index.js#L61-L62)
- **Evidence:** `rl.question` echoes input. The mnemonic and passphrase stay visible on screen and in terminal scrollback, terminal session logs, and any screen recording.
- **Fix:** read secrets with echo disabled when `process.stdin.isTTY` (raw mode, or a muted readline output stream). Print nothing, or `*` per character, while typing. Keep plain line reading when stdin is piped, so tests can feed input.
- **Acceptance:** in an interactive terminal, typed mnemonic and passphrase characters are not displayed. `printf '…\n…\n' | ofwl restore` still works.

### F-06 · Medium · Raw private key always printed

- **Location:** [index.js:53](index.js#L53), [index.js:65](index.js#L65)
- **Evidence:** both `create` and `restore` print `wallet.privateKey` unconditionally.
- **Impact:** the private key is redundant with mnemonic + passphrase, so printing it doubles the secret material on screen. It also encourages pasting a raw key into hot wallets, which defeats cold storage.
- **Fix:** hide the private key by default and add `--show-private-key`. This changes CLI output, so release it as a **major version** (2.0.0) and note it in the changelog/readme.
- **Acceptance:** default output contains no 64-hex-char private key. With the flag, output is unchanged from v1.x.

### F-07 · Medium · Fragile restore input handling

- **Location:** [index.js:61-68](index.js#L61-L68)
- **Evidence (reproduced):**
  - A mnemonic with a trailing space, which is common when pasting, gives an uncaught `TypeError: invalid mnemonic length` and a stack trace.
  - Any invalid mnemonic crashes the same way. There is no re-prompt.
  - A passphrase with a trailing space → **different address, no warning**.
- **Fix:**
  1. Normalise the mnemonic: `trim()`, collapse internal whitespace, lowercase. Then validate with `Mnemonic.isValidMnemonic`. On failure, print a one-line human error (word count, unknown word, or bad checksum) and re-prompt. Never print the input.
  2. Passphrase: **do not** trim, because BIP-39 treats whitespace as significant. If it has leading or trailing whitespace, print a warning that shows the length and asks for confirmation.
  3. Wrap the flow so no secret-handling path can produce an uncaught exception and stack trace.
- **Acceptance:** a phrase with leading or trailing spaces restores correctly. An invalid phrase produces a friendly message and no stack trace. A passphrase with a trailing space produces a warning.

### F-08 · Medium · No offline check

- **Location:** whole CLI
- **Evidence:** the tool's purpose is offline generation, but it runs silently on a connected machine.
- **Fix:** before `create` or `restore`, enumerate `os.networkInterfaces()`. Ignore `internal` interfaces and link-local addresses (`169.254.0.0/16`, `fe80::/10`), which macOS keeps on `awdl0`/`llw0` even when offline. If any routable address is present, print a prominent warning and require typing `yes` to continue. Add `--allow-online` to skip the prompt. Do **not** make any network request to test connectivity.
- **Acceptance:** with Wi-Fi/Ethernet up, the warning appears. With interfaces down, it does not. No sockets are opened in either case.

### F-09 · Medium · Large dependency surface

- **Location:** [package.json](package.json), dependency tree
- **Evidence:** the only APIs used are `Mnemonic` and `HDNodeWallet`, yet `ethers` brings in `ws` (`npm audit`: 1 high + 1 moderate advisory, GHSA-58qx-3vcg-4xpx and GHSA-96hv-2xvq-fx4p), `aes-js`, `@adraffy/ens-normalize`, `tslib`, plus all provider and JSON-RPC code. esbuild bundles all of it into the SEA binary. The `ws` advisories are not exploitable here because no sockets are opened, but every extra package is code that runs in the key-generation process.
- **Fix (pick one; maintainer decision, see T3):**
  - **Recommended:** replace ethers with `@scure/bip39`, `@scure/bip32`, `@noble/curves` (secp256k1) and `@noble/hashes` (keccak_256). All four are zero-dependency and independently audited, and they are the crypto layer ethers itself uses. The Ethereum address is `0x` + last 20 bytes of `keccak256(uncompressedPubKey[1:])`, with an EIP-55 checksum.
  - **Minimum:** upgrade ethers to the latest 6.x, confirm `npm audit` is clean, and pin it (F-01).
- **Acceptance:** all known-answer tests (T1) pass unchanged. `npm ls --omit=dev --all` lists only the intended packages. `npm audit --omit=dev` reports 0 vulnerabilities.

### F-10 · Medium · No tests or self-test

- **Location:** repo (no test files; [CLAUDE.md](CLAUDE.md) confirms "no tests")
- **Impact:** a dependency upgrade (F-01, F-09) or a refactor could silently change derived addresses. Nothing detects a tampered library inside a built binary.
- **Fix:**
  1. Add tests using the built-in `node:test` runner (no new deps), runnable with `npm test`. Cover:
     - The BIP-39 Trezor vectors (passphrase `TREZOR`), including the 256-bit all-zero case `abandon ×23 art`.
     - The Ethereum vector `test test test test test test test test test test test junk` → `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`.
     - At least one frozen v1.x base64-passphrase vector (generate once, commit the phrase, passphrase and address).
     - A create→restore round-trip.
     - CLI tests that spawn `node index.js` with piped stdin.
  2. Add a **runtime known-answer self-test**: before generating, derive the address for one hardcoded vector and abort if it does not match.
- **Acceptance:** `npm test` passes. Changing one character of the expected vector address makes it fail.

### F-11 · Low · Release integrity

- **Evidence:** the npm tarball has a registry signature (`dist.signatures`), but no provenance attestation. There are no published binaries or checksums; users build their own.
- **Fix:**
  - Publish from GitHub Actions with `npm publish --provenance`.
  - Optionally attach release binaries with `SHA256SUMS`, and document `npm audit signatures`.
  - Longer term, aim for reproducible builds.
- **Acceptance:** the npm package page shows a provenance badge.

### F-12 · Low · Weak minimum for `passphrase` command

- **Location:** [index.js:76](index.js#L76)
- **Evidence:** `ofwl passphrase 1` → `Sw==` (8 bits).
- **Fix:** enforce a minimum of 16 bytes (128 bits), or warn loudly below 16. Also reject trailing garbage, since `parseInt('16abc')` is currently accepted as 16; use `/^\d+$/`. Apply the same encoding decision as F-03.
- **Acceptance:** `ofwl passphrase 8` errors or warns. `ofwl passphrase 16abc` errors.

### F-13 · Low · Derivation path not shown

- **Location:** [index.js:51-55](index.js#L51-L55)
- **Evidence:** the path `m/44'/60'/0'/0/0` is implicit.
- **Fix:** print `Path: m/44'/60'/0'/0/0` in `create` and `restore` output. Optionally add `--index N` to derive `m/44'/60'/0'/0/N`. The default must stay index 0.
- **Acceptance:** output includes the path. The default address is unchanged.

### F-14 · Low · Code hygiene

- **Location:**
  - [index.js:8-11](index.js#L8-L11): the readline interface is created for every command, so stdin is held even for `create`, `help` and `passphrase`.
  - [index.js:47](index.js#L47): `isValidMnemonic` on a phrase just produced by `fromEntropy` is always true, so the check is meaningless.
  - [index.js:86](index.js#L86): this fallback is redundant given the earlier branches.
- **Fix:**
  - Create the readline interface only inside `restore` (and the verification flow), and close it when done.
  - Replace the tautological check with a real round-trip: `HDNodeWallet.fromPhrase(phrase, password).address === wallet.address`.
  - Restructure into a `switch` on the command with a single `default` error.
- **Acceptance:** behaviour is unchanged except for the improvements above, and tests pass.

### F-15 · Low · Documentation gaps and inconsistencies

- **Evidence:**
  - The readme says "If your wallet didn't use a passphrase, leave it blank", but `create` always sets one.
  - The readme says "restore from a 24-word seed phrase", but 12-word phrases also work.
  - [CLAUDE.md](CLAUDE.md) says `ethers` is a devDependency; it is a runtime dependency.
  - The build path uses `npm install` instead of `npm ci`.
  - The help text does not mention the passphrase.
  - There is no `SECURITY.md` or operational guide.
- **Fix:**
  - Correct the inconsistencies.
  - Add a "Safe usage" section to the readme or a `SECURITY.md` that covers:
    - Use a live OS booted from USB with networking disabled. Never run from a resumed VM snapshot.
    - Verify the build hash.
    - Write the mnemonic and passphrase on paper and store them in separate places.
    - Verify the backup with `restore` before funding.
    - Power off afterwards, since secrets remain in RAM until then.
    - Never photograph or digitally store the backup.
  - Document the derivation path and how to import into MetaMask, Ledger and Trezor (the passphrase is the "25th word" / "hidden wallet").
- **Acceptance:** the docs match the CLI behaviour after all other fixes.

### F-16 · Info · Secrets in process memory

- **Evidence:** JS strings are immutable and cannot be zeroed. The mnemonic, passphrase and key live in the V8 heap until the process exits, and may be paged to swap or written to a hibernation image.
- **Fix:** no code fix is practical. Mitigate operationally (F-15 guidance: a live OS without swap, power off after use). Keep the process short-lived, which it already is.

---

## 5. What is done well

- Uses the OS CSPRNG through `node:crypto`. There is no custom randomness and no `Math.random`.
- Generates 256-bit entropy, the maximum BIP-39 strength.
- Uses standard derivation that interoperates with mainstream wallets.
- Takes secrets via prompt, not command-line arguments, so they stay out of shell history.
- Writes no files and makes no network calls in the code path.
- Ships a minimal npm package via the `files` whitelist, and the published code matches the repo.
- The readme correctly warns against `npx`.

---

## 6. Is this a good idea in practice?

**Yes, as a cold-storage address generator, under the following conditions:**

- Run it on an air-gapped, ephemeral OS.
- Build it from pinned, verified inputs (after F-01 and F-02 are fixed).
- Write down the mnemonic and passphrase carefully and verify them by restoring (F-03, F-04).
- Never import the raw private key into an online wallet.

**Prefer a hardware wallet when:**

- the amounts are significant and you want keys never to appear on any general-purpose screen; or
- you cannot guarantee a clean air-gapped environment.

A hardware wallet also gives you on-device address verification, which this tool cannot.

---

## 7. Action plan for AI agents

### Global constraints (apply to every task)

1. **Derivation must not change.** For any `(mnemonic, passphrase)` input, `restore` must produce the same address as v1.2.0. The test vectors from T1 are the guard. Run `npm test` after every change.
2. **No new network activity.** Add no telemetry, update checks, connectivity probes or remote fetches at runtime.
3. **No secret persistence.** Never write secrets to files, logs, environment variables or the clipboard. Never include secrets in error messages.
4. **Dependencies:** pin exact versions. Do not add runtime dependencies beyond those named in T3 without maintainer approval.
5. **Tasks marked `DECISION` need maintainer sign-off** on the stated question before implementation. Implement the recommended option only if approved.
6. Keep the single-file architecture of `index.js` unless a task says otherwise. Tests go in `test/`.
7. Update [CLAUDE.md](CLAUDE.md) when commands, dependencies or tests change.

### Tasks (in dependency order)

| # | Finding(s) | Task | Depends on | Decision? |
|---|---|---|---|---|
| T1 | F-10 | Add a `node:test` suite with the BIP-39, Ethereum and frozen-v1.x vectors, a round-trip test, and CLI tests via piped stdin. Add an `npm test` script. | — | — |
| T2 | F-01 | Pin exact dependency versions, add `npm-shrinkwrap.json` to the repo and to `"files"`, and switch the readme to `npm ci`. | T1 | — |
| T3 | F-09 | **DECISION:** migrate from ethers to `@scure/bip39` + `@scure/bip32` + `@noble/curves` + `@noble/hashes` (recommended), or only upgrade ethers? Then implement, pin, and confirm `npm audit --omit=dev` is clean. | T1, T2 | Yes |
| T4 | F-02 | Harden `build.sh`: `curl -f`, GPG-verify `SHASUMS256.txt`, check the tarball SHA-256, abort on failure, and print the final binary hash. | — | — |
| T5 | F-07, F-14 | Restructure the command dispatch. Create readline lazily. Normalise and validate the mnemonic with a friendly re-prompt. Warn on passphrase whitespace. Make sure no stack traces are possible. | T1 | — |
| T6 | F-05 | Masked secret input when the terminal is a TTY; plain input when piped. | T5 | — |
| T7 | F-06, F-13 | Hide the private key by default (`--show-private-key`), print the derivation path, and optionally add `--index N`. Bump the major version. | T5 | Yes (confirm 2.0.0) |
| T8 | F-04, F-14 | Interactive backup verification after `create` (clear screen, masked re-entry, address compare) with `--no-verify`. Replace the tautological check with a round-trip check. Add the runtime known-answer self-test. | T6 | — |
| T9 | F-03, F-12 | **DECISION:** (a) Keep the passphrase on by default with `--no-passphrase`, or make it opt-in? (b) Encode new passphrases as 12 BIP-39 words (recommended) or Crockford base32? Implement, add the separate-storage warning, and enforce the 16-byte minimum and strict integer parsing for `passphrase`. v1.x base64 passphrases must still restore. | T1, T8 | Yes |
| T10 | F-08 | Detect routable network interfaces (ignoring internal and link-local) and require confirmation; `--allow-online` skips it. | T5 | — |
| T11 | F-15 | Fix the readme, help text and CLAUDE.md inconsistencies. Add `SECURITY.md` with the safe-usage procedure and import instructions for other wallets. | T7–T10 | — |
| T12 | F-11 | GitHub Actions workflow: run `npm test`, then publish with `--provenance` on tag. | T1, T2 | Yes (CI/publishing access) |

### Definition of done (whole plan)

- [ ] `npm test` passes, including all vectors. v1.x-created wallets still restore to the same address.
- [ ] `npm audit --omit=dev` reports 0 vulnerabilities, and every dependency version is pinned in `npm-shrinkwrap.json`.
- [ ] `build.sh` fails closed on a tampered Node tarball.
- [ ] Interactive `create` warns when online, hides the private key, shows the path, warns about passphrase storage, and verifies the backup.
- [ ] Interactive `restore` masks input, tolerates whitespace in the phrase, warns on passphrase whitespace, and never prints a stack trace.
- [ ] The docs describe the actual behaviour and the safe-usage procedure.

---

## 8. Maintainer decisions (2026-10-11)

| Task | Decision |
|---|---|
| T3 | **Migrate** to `@scure/bip39`, `@scure/bip32`, `@noble/curves`, `@noble/hashes` (v2.x, pinned exactly). `index.js` becomes an ES module and the minimum Node version is 20.19. `ethers` stays as a **devDependency only**, used as a differential oracle in tests. Do not add `micro-eth-signer`; the address/EIP-55 code is about 10 lines and is covered by tests. |
| T7 | **Approved.** Hide the private key by default (`--show-private-key`), print the derivation path, and release as **2.0.0** together with the T9 changes. |
| T9a | Passphrase becomes **opt-in** via `create --passphrase`. Default wallets have an empty passphrase, which MetaMask and other wallets without passphrase support can import. |
| T9b | Generated passphrases use **Crockford base32, grouped** (for example `XXXX-XXXX-…`, 128 bits). Not BIP-39 words, because 12 words are about 80 characters and exceed Trezor's 50-character passphrase limit. |
| T12 | Not decided yet. |

### Implementation notes from the 2026-10-11 spike

- A differential run of noble/scure 2.4.0 against ethers 6.16.0 over 10,000 random wallets (12 and 24 words; base64, empty, whitespace, Unicode and `TREZOR` passphrases) matched on every address, private key and phrase.
- **Mnemonic canonicalisation is required in the migration (T3), not only in T5.** ethers lowercases the phrase and splits on `/\s+/`. Raw `@scure/bip39` does not: an **uppercase** phrase silently derives a **different valid address**, and double spaces throw. Canonicalise with `trim()`, lowercase and whitespace collapse, then `validateMnemonic`, before seeding. The CLI tests cover this.
- **Base32 passphrases and BIP-39:** the passphrase string is fed to BIP-39 byte for byte, so the canonical form is exactly what `create` prints (uppercase, with dashes), and other wallets need it typed exactly that way. `restore` may normalise case and dashes **only** when the input matches the ofwl base32 pattern (length and alphabet, ideally with a Crockford check symbol). Any other passphrase, including v1 base64, must pass through unchanged.
- `ethers` 6.x bundles `@noble/curves` 1.2.0 and `@noble/hashes` 1.3.2 (2023), so the migration also moves to current noble releases.

### Progress

- [x] T1: `test/cli.test.mjs` (`node:test`, `npm test`) with standard vectors, frozen v1.2.0 wallets, input-tolerance checks and CLI round-trips. Changing one expected address makes it fail.
- [x] T2: exact versions in `package.json`, `npm-shrinkwrap.json` committed and included in `"files"`, readme uses `npm ci`.
- [x] T3: runtime deps are now `@scure/bip39`, `@scure/bip32`, `@noble/curves`, `@noble/hashes` 2.4.0 (+ `@scure/base` transitively). `npm audit --omit=dev`: 0 vulnerabilities. `test/ethers-diff.test.mjs` compares the CLI with ethers on random wallets and messy input. esbuild bundles to CJS for the SEA binary (bundle about 147 KB).
- [x] T5: `main()` dispatch with exit codes, lazy readline, mnemonic canonicalisation with friendly errors (re-prompt when interactive, exit 1 when piped), passphrase whitespace warning (confirmation when interactive), no stack traces or echoed input in errors.
- [x] T6: on a TTY, `restore` reads the mnemonic and passphrase in raw mode with no echo; the prompt shows only a live word/character count. Backspace, Ctrl-U, Ctrl-C, Ctrl-D, paste of several lines and arrow keys (ignored) are handled. Piped input is unchanged. `test/tty.test.mjs` checks via `script(1)` that no secret reaches the terminal.
- [x] T7: private key hidden unless `--show-private-key`; `Path:` printed; `--index <n>` for `create` and `restore`. Version 2.0.0.
- [x] T9: passphrase opt-in via `create --passphrase`. Format: 26 random Crockford base32 symbols (130 bits) + 2 checksum symbols (first 10 bits of SHA-256 over the data symbols), as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (34 characters). `restore` normalises case, dashes, spaces and O/I/L look-alikes for input of that shape, rejects a bad checksum (asks when interactive; `--raw-passphrase` overrides). Separate-storage warning after `create`. Deviation from the T9 text: `passphrase` takes no byte-length argument any more; it always prints the standard format, so there is no length to validate.
- [x] T8: after `create` on a TTY, optional backup verification (`[Y/n]`, `--no-verify`): clears screen and scrollback, masked re-entry via the shared `promptSecrets()`, address comparison, mismatch reported by word position or passphrase, retry/show-again/quit (quit exits 1 and reprints the address). Non-TTY prints a reminder instead. Runtime known-answer self-test (`selfTest()`) before `create`/`restore`: default path, index 1 with a lowercase generated passphrase, and a sanity check of the random source. (The tautological check was already replaced by an entropy round-trip in T3.)
- [x] T10: before `create`/`restore`, `onlineInterfaces()` reads `os.networkInterfaces()` (no sockets) and ignores internal interfaces, 169.254.0.0/16 and fe80::/10. If any routable address remains, a warning names the interfaces; on a TTY the user must type `yes`, without a TTY ofwl refuses (fail closed). `--allow-online` skips the check. VPN tunnels (e.g. macOS `utun*` with a routable address) count as online.
- [x] T11: `SECURITY.md` (vulnerability reporting, threat model, safe usage procedure, verifying what you run, import into Trezor/Ledger/MetaMask with derivation-path notes) linked from the readme and shipped in the npm package. Readme: 12–24-word restore, case/whitespace tolerance, record the binary hash. The F-15 inconsistencies were fixed during T2–T10.
- [ ] T4: blocked until `gpg` is installed on the build machine (`brew install gnupg`).
