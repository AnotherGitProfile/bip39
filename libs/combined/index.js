/* base-x */

module.exports.basex = require('base-x')

/* base32 */

module.exports.base32 = require('base32.js')

/* bchaddrjs */

module.exports.bchaddr = require('bchaddrjs')

/* bchaddrjs slp */

module.exports.bchaddrSlp = require('bchaddrjs-slp')

/* bech32 */

module.exports.bech32 = require('bech32').bech32

/* biginteger */

module.exports.BigInteger = require('javascript-biginteger')

/* bitcoinjs-bip38 */

module.exports.bip38 = require('bip38')

/* bip85 */

module.exports.bip85 = require('bip85')

/* bitcoinjs-lib */

module.exports.bitcoin = require('bitcoinjs-lib')

/* buffer */
const buffer = require('buffer');
module.exports.buffer = buffer;

/* elastos */
// See https://github.com/iancoleman/bip39/pull/368
// and https://github.com/johnnynanjiang/Elastos.SDK.Keypair.Javascript/tree/iancoleman-bip39

module.exports.elastosjs = require('elastos-wallet-js')

/* ethereum-util */

module.exports.ethUtil = require('ethereumjs-util')

/* fast-levenshtein */

module.exports.levenshtein = require('fast-levenshtein')

/* groestlcoin */

module.exports.groestlcoinjs = require('groestlcoinjs-lib')

/* groestlcoin bip38 */

module.exports.groestlcoinjsBip38 = require('bip38grs')

/* kjua qr codes */

module.exports.kjua = require('kjua')

/* nebulas */

try {
module.exports.nebulas = require('nebulas')
}
catch (e) {
    console.warn("Error loading nebulas library");
    console.warn(e);
};

/* stellar-util */

let StellarBase = require('stellar-base');
let edHd = require('ed25519-hd-key');
module.exports.stellarUtil = {
    getKeypair: function (path, seed) {
        const result = edHd.derivePath(path, seed);
        return StellarBase.Keypair.fromRawEd25519Seed(result.key);
    },
    dummyNetwork: {
        bip32: {public: 0, private: 0},
        messagePrefix: '',
        pubKeyHash: 0,
        scriptHash: 0,
        wif: 0,
    },
}

/* zoobc-util */

let base32 = require('base32.js');
let nbl = require('nebulas');
module.exports.zoobcUtil = {
    getKeypair: function (path, seed) {
        const { key, chainCode}  = edHd.derivePath(path, seed);
        const pubKey = edHd.getPublicKey(key);
        return {key,chainCode, pubKey};
    },
    getZBCAddress(publicKey, prefix = "ZBC") {
        const prefixDefault = ["ZBC", "ZNK", "ZBL", "ZTX"];
        const valid = prefixDefault.indexOf(prefix) > -1;
        if (valid) {
          var bytes = new Uint8Array(35);
          for (let i = 0; i < 32; i++) bytes[i] = publicKey[i];
          for (let i = 0; i < 3; i++) bytes[i + 32] = prefix.charCodeAt(i);
          const checksum = nbl.CryptoUtils.sha3(bytes);
          for (let i = 0; i < 3; i++) bytes[i + 32] = Number(checksum[i]);
          var segs = [prefix];
          var b32 = base32.encode(bytes);
          for (let i = 0; i < 7; i++) segs.push(b32.substr(i * 8, 8));
          return segs.join("_");
        } else {
          throw new Error("The Prefix not available!");
        }
      }
}

/* nano-util */

let NanoBase = require('nanocurrency-web');
module.exports.nanoUtil = {
    getKeypair: function (index, seed) {
        const accounts = NanoBase.wallet.accounts(seed, index, index)
        return {privKey: accounts[0].privateKey, pubKey: accounts[0].publicKey, address: accounts[0].address};
    },
    dummyNetwork: {
        bip32: {public: 0, private: 0},
        messagePrefix: '',
        pubKeyHash: 0,
        scriptHash: 0,
        wif: 0,
    },
}

/* unorm */

module.exports.unorm = require('unorm')

/* zxcvbn */

module.exports.zxcvbn = require('zxcvbn')

/* handshake */
module.exports.handshake = require('handshake-util')

/* bs58 */
try {
    module.exports.bs58 = require('bs58')
}
catch (e) {
    console.warn("Error loading bs58 library");
    console.warn(e);
};

/* create-hash */
try {
    module.exports.createHash = require('create-hash')
}
catch (e) {
    console.warn("Error loading create-hash library");
    console.warn(e);
};

const Bip32Ed25519 = require('@stricahq/bip32ed25519')
module.exports.bip32ed25519 = Bip32Ed25519;

const cardano = require('cardano-crypto.js');

module.exports.cardano = {
    ...cardano,
    getAccountExtendedPrivateKey: async function (phrase, purpose, coin, account) {
        const seedBuf = cardano._mnemonicToSeedV2(phrase);
        const rootkeypair = await cardano._seedToKeypairV2(seedBuf, '');
        const xprv = buffer.Buffer.concat([rootkeypair.slice(0, 64), rootkeypair.slice(64 + 32,)]);

        const walletKey = new Bip32Ed25519.Bip32PrivateKey(xprv);
        // This magic constant is hardening key
        const accountKey = walletKey.derive(2147483648 + purpose) // purpose
            .derive(2147483648 + coin) // coin type
            .derive(2147483648 + account); // account index
        const xprvBytes = accountKey.toBytes();
        return module.exports.bs58.encode(xprvBytes);
    },
    getAccountExtendedPublicKey: async function (phrase, purpose, coin, account) {
        const seedBuf = cardano._mnemonicToSeedV2(phrase);
        const rootkeypair = await cardano._seedToKeypairV2(seedBuf, '');
        const xprv = buffer.Buffer.concat([rootkeypair.slice(0, 64), rootkeypair.slice(64 + 32,)]);

        const walletKey = new Bip32Ed25519.Bip32PrivateKey(xprv);
        // This magic constant is hardening key
        const accountKey = walletKey.derive(2147483648 + purpose) // purpose
            .derive(2147483648 + coin) // coin type
            .derive(2147483648 + account); // account index
        const xpubBytes = accountKey.toBip32PublicKey().toBytes();
        return module.exports.bs58.encode(xpubBytes);
    }
}

module.exports.solanaUtil = {
    getKeypair: function (path, seed) {
        const { key, chainCode } = edHd.derivePath(path, seed);
        const pubKey = edHd.getPublicKey(key);
        return { key, pubKey, chainCode };
    },
}

// Bip86 source code
const ecurve = require('ecurve')
const secp256k1 = ecurve.getCurveByName('secp256k1')
const schnorr = require('bip-schnorr')
const bech32 = require('bech32').bech32
const bech32m = require('bech32').bech32m

const getP2TRAddress = (pubkey, testnet = false) => {
  const pubKey = ecurve.Point.decodeFrom(secp256k1, pubkey)
  const taprootPubkey = schnorr.taproot.taprootConstruct(pubKey)
  const words = bech32.toWords(taprootPubkey)
  words.unshift(1)
  return bech32m.encode(testnet ? 'tb' : 'bc', words)
}

module.exports.BIP86 = {
    getP2TRAddress
}