# Offline Wallets

A small utility to create and restore Ethereum wallets offline. It uses ethers.js and node's native crypto library under the hood.

## Usage

Install the package locally or globally:

`npm install -g offline-wallets`

To create a new wallet simply use `ofwl create`.

You can "restore" a wallet from a 24 word seedphrase and passcode with `ofwl restore`. If your wallet didn't use a passphrase leave it blank.

If you want to generate a random passphrase use `ofwl passphrase 12`. The number is optional and will default to 12. You can specify how many random bytes to generate.

## License

MIT