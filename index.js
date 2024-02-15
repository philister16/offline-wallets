#!/usr/bin/env node

const readline = require('node:readline');
const { stdin, stdout } = require('node:process');
const Crypto = require('node:crypto');
const { Mnemonic, HDNodeWallet } = require('ethers');

const rl = readline.createInterface({
    input: stdin,
    output: stdout
});

if (process.argv.length < 3) {
    console.error('Expected at least one argument! Use --help for help.');
    process.exit(1);
}

if (process.argv[2] === '--help' || process.argv[2] === '-h') {
    console.log('Usage: node index.js [OPTIONS]');
    console.log('Options:');
    console.log('  create         Create a new wallet');
    console.log('  restore        Restore a wallet from mnemonic');
    console.log('  --help | -h    Show help');
    console.log('  --version | -v Show version number');
    process.exit(0);
}

if (process.argv[2] === '--version' || process.argv[2] === '-v') {
    const version = require('./package.json').version;
    console.log(version);
    process.exit(0);
}

if (process.argv[2] === 'create') {
    console.log('Creating a new wallet...');
    const entropy = Crypto.randomBytes(32);
    const passphrase = Crypto.randomBytes(12).toString('base64');
    const mnemonic = Mnemonic.fromEntropy(entropy, passphrase);
    if (!Mnemonic.isValidMnemonic(mnemonic.phrase)) {
        console.error('Invalid Mnemonic');
        process.exit(1);
    }
    const wallet = HDNodeWallet.fromMnemonic(mnemonic);
    console.log('Address:     ', wallet.address);
    console.log('Private Key: ', wallet.privateKey);
    console.log('Mnemonic:    ', wallet.mnemonic.phrase);
    console.log('Passphrase:  ', wallet.mnemonic.password);
    process.exit(0);
}

if (process.argv[2] === 'restore') {
    console.log('Restoring a wallet...');
    rl.question('Enter mnemonic: ', (mnemonic) => {
        rl.question('Enter passphrase: ', (passphrase) => {
            const restoredWallet = HDNodeWallet.fromPhrase(mnemonic, passphrase);
            console.log('Address:     ', restoredWallet.address);
            console.log('Private Key: ', restoredWallet.privateKey);
            process.exit(0);
        });
    });
}
