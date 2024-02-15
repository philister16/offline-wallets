# Offline Wallets

A small utility to create and restore Ethereum wallets offline. It uses ethers.js and node's native crypto library under the hood.

## Usage

`npm install offline-wallets`

To create a new wallet simply use `ofwl create`.

You can "restore" a wallet from a 24 word seedphrase and passcode with `ofwl restore`.

If your wallet didn't use a passphrase leave it blank.

## License

MIT