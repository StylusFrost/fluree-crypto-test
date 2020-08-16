const bs58check = require('bs58check')
const cryptoBase = require('@fluree/crypto-base');
const secp256k1= require('secp256k1/elliptic')
const { ecdsaSign, ecdsaRecover, publicKeyConvert } = require('ethereum-cryptography/secp256k1')
const crypto = require('crypto')

function hexToUnit8Array(str) {
  return new Uint8Array(Buffer.from(str, 'hex'))
}

console.log('*********TEST AUTH ID************* ')

/* Fluree doc

Auth Id
Once you have a public-private key-pair, you can generate an auth id using the following steps:

You need to create two items, a pub-prefixed and a checksum.

For the pub-prefixed: ******** Step 1

Convert the public key to bytes.
Hash the result with SHA2-256.
Hash the result with RIPEMD-160.
Prefix the result with [0x0F 0x02].
For the checksum:   ******** Step 2

Hash the pub-prefixed with SHA2-256.
Hash the result with SHA2-256.
******** Step Final
Take the first 4 bytes of the result.
To get the account id, concatenate the pub-prefixed with the checksum, and encode with Base58Check encoding.

*/

console.log('Phase 1 ------------')
console.log('')

// 1) 
// Fluree
const hashSHAF = cryptoBase.sha2_256(hexToUnit8Array("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"));
// Cryto
const hashSHA = crypto.createHash("sha256").update(hexToUnit8Array("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391")).digest("hex")

console.log('*****Step 1****')
console.log('hashSHA        : ' + hashSHA)
console.log('hashSHAFluree  : ' + hashSHAF)
console.log('hashSHAExpected: 816896ed1d3a889753d2c1b3870aa54238c935dbcccb12530af07d41cef889b0')
console.log('*****Step 1*****')
console.log('')

// 2) 
// Fluree
const hashRIPEF = cryptoBase.ripemd_160(hexToUnit8Array(hashSHAF));
// Cryto
const hashRIPE = crypto.createHash("ripemd160").update(hexToUnit8Array(hashSHA)).digest("hex");

console.log('*****Step 2****')
console.log('hashRIPE         : ' + hashRIPE)
console.log('hashRIPEFluree   : ' + hashRIPEF)
console.log('hashRIPEExpected : d486bf7bfa5f659a6654556da61ee1f1a6b64d7f')
console.log('*****Step 2*****')
console.log('')

// 3) 
// Fluree
const pubPrefixedF = '0f' + '02' + hashRIPEF
// Cryto
const pubPrefixed = '0f' + '02' + hashRIPE

console.log('*****Step 3****')
console.log('pubPrefixed        : ' + pubPrefixed)
console.log('pubPrefixedFluree  : ' + pubPrefixedF)
console.log('pubPrefixedExpected: 0f02d486bf7bfa5f659a6654556da61ee1f1a6b64d7f')
console.log('*****Step 3*****')
console.log('')

console.log('Phase 1 ------OK-------')
console.log('')
console.log('Phase 2 ------------')
console.log('')

const pubPrefixedHashSHAF = cryptoBase.sha2_256(hexToUnit8Array(pubPrefixedF));
const pubPrefixedHashSHA = crypto.createHash("sha256").update(hexToUnit8Array(pubPrefixed)).digest("hex");

console.log('*****Step 1****')
console.log('pubPrefixedHashSHA        : ' + pubPrefixedHashSHA)
console.log('pubPrefixedHashSHAFlure   : ' + pubPrefixedHashSHAF)
console.log('pubPrefixedHashSHAExpected: db4d4ce64b247d247761c8aecbbcebbba0453009f8eb82fab984c549b6833be0')
console.log('*****Step 1*****')
console.log('')

const resultHashSHAF = cryptoBase.sha2_256(hexToUnit8Array(pubPrefixedHashSHAF));
const resultHashSHA = crypto.createHash("sha256").update(hexToUnit8Array(pubPrefixedHashSHA)).digest("hex");

console.log('*****Step 2****')
console.log('resultHashSHA        : ' + resultHashSHA)
console.log('resultHashSHAFluree  : ' + resultHashSHAF)
console.log('resultHashSHAExpected:  89520bfa3a3a5a40dc6b88228fe07cbb5a3dacf1bb719494f86c0856a77317f1')
console.log('*****Step 2*****')
console.log('')

const checksumF = resultHashSHAF.slice(0, 8)
const checksum = resultHashSHA.slice(0, 8)

console.log('*****Step 3****')
console.log('checksum        : ' + checksum)
console.log('checksumFluree  : ' + checksumF)
console.log('checksumExpected: 89520bfa')
console.log('*****Step 3*****')
console.log('')


console.log('Phase 2 ------OK-------')
console.log('')

console.log('Phase Final ------OK-------')
console.log('')

const concat = pubPrefixed + checksum
const concatF = pubPrefixedF + checksumF

console.log('*****Step 1A ****Error****')
console.log('concat        : ' + concat)
console.log('concatFluree  : ' + concatF)
console.log('concatExpected: ' + bs58check.decode('TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV').toString('hex')+ '            <<<<<---¿Checksum?')
console.log('*****Step 1A *****Error***')
console.log('')


console.log('*****Step 1B ***OK**')
console.log('concat        : ' + pubPrefixed+ '            <<<<<---Result with only use pub-prefixed')
console.log('concatFluree  : ' + pubPrefixedF+'            <<<<<---Result with only use pub-prefixed')
console.log('concatExpected: ' + bs58check.decode('TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV').toString('hex'))
console.log('*****Step 1B ***OK**')
console.log('')

const account_id_error = bs58check.encode(hexToUnit8Array(concat))
const account_idF_error = bs58check.encode(hexToUnit8Array(concatF))


console.log('*****Step 2A **Error**')
console.log('account_id                  : ' + account_id_error)
console.log('account_idFluree            : ' + account_idF_error)
console.log('account_idFluree_crypto_base: ' + cryptoBase.account_id_from_public("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"))
console.log('account_idExpected          : ' + bs58check.encode(bs58check.decode('TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV')))
console.log('*****Step 2A **Error**')
console.log('')


const account_id = bs58check.encode(hexToUnit8Array(pubPrefixed))
const account_idF = bs58check.encode(hexToUnit8Array(pubPrefixedF))

console.log('*****Step 2B **OK**')
console.log('account_id                  : ' + account_id)
console.log('account_idFluree            : ' + account_idF)
console.log('account_idFluree_crypto_base: ' + cryptoBase.account_id_from_public("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"))
console.log('account_idExpected          : ' + bs58check.encode(bs58check.decode('TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV')))
console.log('*****Step 2B **OK***')
console.log('')

console.log('Phase Final ------ERROR-------')
console.log('')
console.log('*****END *TEST AUTH ID************* ')

console.log('')

console.log('*********TEST SIGN************* ')
console.log('')
/* Fluree doc @fluree/crypto-base

Sign Message
Arguments: message, private-key-as-hex-string
Returns: signature
Given a message and a private key, this will return a signature.

const message = "hi there";
const privateKey = "6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2";

crypto.sign_message(message, privateKey);
This returns:

1b3046022100cbd32e463567fefc2f120425b0224d9d263008911653f50e83953f47cfbef3bc022100fcf81206277aa1b86d2667b4003f44643759b8f4684097efd92d56129cd89ea8


*/

/* Fluree doc Signed Queries

Then, you should get the SHA2-256 hash of that signing string, and sign it using Elliptic Curve Digital Signature Algorithm (ECDSA),
specifically the secp256k1 curve. The resulting signature is DER encoded and returned as a hex-string. 
In addition, after adding 27 to the recoveryByte, that number is converted into a hex string, and prepended to the rest of the signature.

*/


const pk = '6a5f415f49986006815ae7887016275aac8ffb239f9a2fa7172300578582b6c2'
const msg= "hi there"

console.log('*****Step 1****')
console.log('msg: ' + msg)
console.log('pk : ' + pk)
console.log('*****Step 1*****')
console.log('')


// sign msg with cryto-base
const sigBase = cryptoBase.sign_message(msg, pk);

// As the document says with secp256k1 and sha2-256
const signingStringHash = crypto.createHash("sha256").update(hexToUnit8Array(msg)).digest("hex")
sigObj = secp256k1.ecdsaSign(hexToUnit8Array(signingStringHash), hexToUnit8Array(pk))

// Using Ethereum Cryto
const sig = ecdsaSign(hexToUnit8Array(signingStringHash),  hexToUnit8Array(pk))


console.log('*****Step 2*****ERROR****')
console.log('signatureExpected         : ' + '1b3046022100cbd32e463567fefc2f120425b0224d9d263008911653f50e83953f47cfbef3bc022100fcf81206277aa1b86d2667b4003f44643759b8f4684097efd92d56129cd89ea8')
console.log('signatureFlureeCryptoBase : ' + sigBase)
console.log('ethereum-cryptography     : ' + '1b' + Buffer.from(secp256k1.signatureExport(sig.signature)).toString('hex'))
console.log('signatureFlureeDOC        : ' + '1b' + Buffer.from(secp256k1.signatureExport(sigObj.signature)).toString('hex'))
console.log('*****Step 2*****ERROR****')
console.log('')
console.log('*****END*TEST SIGN************* ')

