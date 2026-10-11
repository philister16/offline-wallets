# Offline Wallets

A small utility to create and restore Ethereum wallets offline. It uses the audited, zero-dependency [`@scure/bip39`](https://github.com/paulmillr/scure-bip39), [`@scure/bip32`](https://github.com/paulmillr/scure-bip32), [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) libraries and Node's native crypto module under the hood.

## Installation

### Option 1: npm (requires Node.js 20.19+)

```
npm install -g offline-wallets
```

### Option 2: Standalone binary (recommended for air-gapped machines)

Build a self-contained binary that requires no Node.js installation on the target machine. Supports macOS and Linux.

**1. Build on a networked machine** (requires Node.js 22+):

```bash
git clone https://github.com/philister16/offline-wallets.git
cd offline-wallets
npm ci
npm run build
```

This produces `dist/ofwl` (~110 MB, includes the Node.js runtime).

**2. Transfer to the air-gapped machine:**

```bash
# Copy to a USB drive
cp dist/ofwl /Volumes/USB/ofwl    # macOS
cp dist/ofwl /media/usb/ofwl      # Linux

# On the air-gapped machine, copy it off and make it executable
cp /Volumes/USB/ofwl ~/ofwl
chmod +x ~/ofwl

# Run it
./ofwl create

# Optionally, add it to your PATH to use from anywhere
sudo cp ~/ofwl /usr/local/bin/ofwl
```

The binary is platform-specific — it only runs on the same OS and CPU architecture it was built on (e.g. built on macOS arm64 → runs only on macOS arm64). To target a different platform, build on a matching machine.

> **Note:** Do not use `npx ofwl` — it fetches from the network on every run, which defeats the purpose of offline wallet generation.

## Usage

```
ofwl create                     # Create a new wallet (24-word mnemonic, no passphrase)
ofwl create --passphrase        # ...and also generate a passphrase
ofwl restore                    # Restore a wallet from its mnemonic (and passphrase, if any)
ofwl passphrase                 # Generate a random passphrase
ofwl help                       # Show all commands, flags, and current version
```

`create` and `restore` print the address and its derivation path (`m/44'/60'/0'/0/0`, the default in MetaMask, Ledger, Trezor and most other wallets). Further options:

- `--index <n>` uses address index `n` (path `m/44'/60'/0'/0/n`).
- `--no-verify` skips the backup check (see below).
- `--allow-online` skips the offline check (see below).
- `--show-private-key` also prints the raw private key. It is hidden by default: the mnemonic already backs up the wallet, and importing a raw key into an online wallet defeats cold storage.

### Backup check

After `create` prints the wallet, it asks whether to verify your backup. If you agree, it clears the screen (including scrollback), asks you to type the mnemonic (and passphrase) back from your written copy, and checks that it restores the same address. If it doesn't, it tells you which word positions or the passphrase differ, and lets you see the secrets again to correct your copy. The check is skipped with `--no-verify` and when ofwl doesn't run in a terminal.

### Offline check

Before generating or restoring, ofwl checks whether any network interface has a routable address (it only reads the local interface list and never connects anywhere). If so, it warns you and asks you to type `yes` to continue. Without a terminal, for example in a script, it refuses unless you pass `--allow-online`. Link-local addresses are ignored, because macOS keeps them even when offline.

### Self-test

Before generating or restoring, ofwl also runs a quick self-test against known test vectors and refuses to continue if it fails, for example because a build was tampered with.

### Passphrases

A passphrase (sometimes called the "25th word") is optional. With one, the mnemonic alone restores a different, empty wallet, so a stolen mnemonic is useless without it. But you now have two secrets to back up, and **losing the passphrase means losing the funds**. Store it separately from the mnemonic. Not all wallets support passphrases (MetaMask, for example, does not).

Generated passphrases look like `BFFB-M987-8PPK-V696-EDNF-7B5X-YAPC`: 130 random bits in [Crockford base32](https://www.crockford.com/base32.html) (no ambiguous characters such as `I`, `L`, `O` or `U`) plus a 2-character checksum. In other wallets, enter it exactly as printed, uppercase with dashes. `ofwl restore` is more forgiving: it accepts lowercase, missing dashes and `O`/`I`/`L` for `0`/`1`/`1`, and the checksum catches most typos. If you used a passphrase of your own that `ofwl restore` mistakes for a generated one, pass `--raw-passphrase` to use it exactly as typed.

### Restoring

When restoring, you will be prompted for your mnemonic and passphrase. If your wallet didn't use a passphrase, leave it blank. In a terminal, what you type is not shown: the prompt only displays a running word or character count, so the secrets don't end up on screen or in scrollback. Backspace and Ctrl-U (clear) work as usual, and Ctrl-C aborts.

**Always restore your backup and check that the address matches before sending funds to it.**

### Upgrading from 1.x

Wallets created with 1.x, including their base64 passphrases (e.g. `fuIIP2QeNYE8cZ2ypShEPw==`), restore to the same addresses in 2.x. Changes in 2.0:

- `create` no longer generates a passphrase unless you pass `--passphrase`, and generated passphrases use the format above.
- The private key is hidden unless you pass `--show-private-key`.
- `passphrase` no longer takes a byte length.

## License

MIT