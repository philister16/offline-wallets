# Offline Wallets

A small utility to create and restore Ethereum wallets offline. It uses ethers.js and Node's native crypto library under the hood.

## Installation

### Option 1: npm (requires Node.js)

```
npm install -g offline-wallets
```

### Option 2: Standalone binary (recommended for air-gapped machines)

Build a self-contained binary that requires no Node.js installation on the target machine. Supports macOS and Linux.

**1. Build on a networked machine** (requires Node.js 22+):

```bash
git clone https://github.com/philister16/offline-wallets.git
cd offline-wallets
npm install
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
ofwl create              # Create a new wallet
ofwl restore             # Restore a wallet from a 24-word seed phrase
ofwl passphrase [bytes]  # Generate a random passphrase (default: 16 bytes)
ofwl help                # Show all commands, flags, and current version
```

When restoring, you will be prompted for your mnemonic and passphrase. If your wallet didn't use a passphrase, leave it blank.

## License

MIT