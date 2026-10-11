# Security

`ofwl` generates the keys that control your funds. This document explains how to report a vulnerability, how to use the tool safely, and what it can and cannot protect you from.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on the repository page, open **Security → Report a vulnerability**. Do not open a public issue for security problems. Include the version (`ofwl --version`), how you installed it (npm or standalone binary), and steps to reproduce.

## What ofwl protects against, and what it doesn't

ofwl helps you create a cold-storage wallet whose secrets never touch a networked computer. It:

- uses the operating system's cryptographically secure random number generator (256 bits for the mnemonic),
- implements standard BIP-39 / BIP-32 / BIP-44 derivation with small, audited libraries, pinned to exact versions,
- runs a known-answer self-test before generating or restoring,
- warns when the computer appears to be online,
- hides what you type when restoring, and hides the raw private key unless you ask for it,
- makes you verify your written backup before you rely on it.

It cannot protect you from:

- **A compromised computer.** Malware, a keylogger or a tampered operating system on the machine running ofwl can see your secrets. Use a clean, offline, ephemeral OS (see below).
- **A tampered copy of ofwl.** Verify what you run (see [Verifying what you run](#verifying-what-you-run)).
- **Secrets left in memory.** JavaScript cannot reliably erase secrets from memory. They stay in RAM until the machine is powered off, and can end up in swap or a hibernation image.
- **Losing or exposing your backup.** Anyone with your mnemonic (and passphrase, if you use one) controls the funds. If you lose them, nobody can recover the funds.
- **Address substitution on screen.** A hardware wallet can show the receiving address on its own trusted display. ofwl only has your computer's screen.

For large amounts, a hardware wallet that generates its own seed is the safer default, because the keys never appear on a general-purpose computer.

## Safe usage procedure

### 1. Prepare (on a networked computer)

1. Build the standalone binary from a clean checkout. `npm ci` installs exactly the versions locked in `npm-shrinkwrap.json`:

   ```bash
   git clone https://github.com/philister16/offline-wallets.git
   cd offline-wallets
   npm ci
   npm test
   npm run build
   ```

2. Record the binary's SHA-256 and keep it somewhere you trust (e.g. write it down):

   ```bash
   shasum -a 256 dist/ofwl
   ```

3. Copy `dist/ofwl` to a USB drive. Build on the same OS and CPU architecture as the offline machine.

### 2. Generate (on the offline computer)

1. Boot a live operating system from USB (for example Tails or an Ubuntu live image), **without** networking: disable or physically remove Wi-Fi, don't plug in Ethernet, turn off Bluetooth. Don't use a virtual machine snapshot, and don't use a system that swaps or hibernates to disk.
2. Copy `ofwl` from the USB drive, make it executable, and check that its SHA-256 matches the one you recorded:

   ```bash
   shasum -a 256 ofwl   # or: sha256sum ofwl
   chmod +x ofwl
   ```

3. Run `./ofwl create`, or `./ofwl create --passphrase` if you want a passphrase (see the readme for the trade-off). ofwl should **not** warn that the computer is online. If it does, stop and disconnect first.
4. Write the mnemonic on paper, legibly, with the word numbers. If you use a passphrase, write it on a **separate** sheet, exactly as printed. Never photograph your backup, type it into another device, or store it in a file, password manager or cloud service.
5. Complete the backup check that ofwl offers. It clears the screen and asks you to type the backup back in from paper.
6. Note the address. The address is public: you can copy it, photograph it, or write it down.
7. Power off the computer to clear its memory.

### 3. Before funding

1. On another day, boot the offline setup again and run `./ofwl restore` with your paper backup. Check that it shows the same address.
2. Send a small test amount first, and check that it arrives at that address on a block explorer.
3. Store the mnemonic and passphrase in separate, safe places. Consider a fire- and water-resistant (metal) backup for the mnemonic.

To receive more funds later, just send them to the address. You don't need to restore or import anything.

## Verifying what you run

- **Dependencies:** all versions are pinned exactly and locked in `npm-shrinkwrap.json`, which is published with the npm package and honoured by `npm install -g`. After installing from npm, you can check the registry signatures with `npm audit signatures`.
- **Standalone binary:** build it yourself as described above and compare the SHA-256 on the offline machine.
- **Self-test:** every `create` and `restore` first derives known test vectors and aborts if the results are wrong.
- **Tests:** `npm test` checks derivation against standard BIP-39 and Ethereum vectors, wallets created by ofwl 1.x, and an independent reference implementation (ethers).

## Spending: using your wallet in other wallets

ofwl wallets are standard BIP-39 wallets. The address shown by ofwl is at derivation path `m/44'/60'/0'/0/0` (or `m/44'/60'/0'/0/n` with `--index n`). Before moving real funds, always check that the other wallet shows the **same address** as ofwl.

The safest way to spend is to restore the mnemonic (and passphrase) onto a **hardware wallet** and sign there. Typing your mnemonic into a software wallet on an everyday computer makes it a hot wallet.

| Wallet | Mnemonic | Passphrase | Address at `m/44'/60'/0'/0/0` |
|---|---|---|---|
| Trezor | Restore with the recovery seed during setup | Supported ("hidden wallet"); enter it exactly as printed (max. 50 characters; ofwl passphrases are 34) | First Ethereum account |
| Ledger | Restore with the recovery phrase during setup | Supported (passphrase set up on the device); enter it exactly as printed | First Ethereum account. Ledger Live numbers further accounts as `m/44'/60'/n'/0/0`, which differs from ofwl's `--index n` |
| MetaMask | Import using the Secret Recovery Phrase | **Not supported** | First account. Further accounts follow `m/44'/60'/0'/0/n` like ofwl's `--index n` |

Notes:

- **Passphrase wallets and MetaMask:** MetaMask's recovery-phrase import has no passphrase field. Importing the mnemonic alone opens a different, empty wallet. Use a hardware wallet that supports passphrases instead. (Importing the raw private key from `--show-private-key` also works, but it turns your cold wallet into a hot one.)
- **Restoring onto a hardware wallet** replaces the seed on the device, and the wallet is then only as safe as the computer it was generated on.
- **1.x wallets** have a base64 passphrase such as `fuIIP2QeNYE8cZ2ypShEPw==`. It is case-sensitive and must be entered exactly, including the `=` signs.
