const bs58check = require('bs58check')
const crypoBase = require('@fluree/crypto-base');
const crypto = require('crypto')

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
function hexToUnit8Array(str) {
  return new Uint8Array(Buffer.from(str, 'hex'))
}

console.log('Phase 1 ------------')
console.log('')

// 1) 
// Fluree
const hashSHAF = crypoBase.sha2_256(hexToUnit8Array("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"));
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
const hashRIPEF = crypoBase.ripemd_160(hexToUnit8Array(hashSHAF));
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

const pubPrefixedHashSHAF = crypoBase.sha2_256(hexToUnit8Array(pubPrefixedF));
const pubPrefixedHashSHA = crypto.createHash("sha256").update(hexToUnit8Array(pubPrefixed)).digest("hex");

console.log('*****Step 1****')
console.log('pubPrefixedHashSHA        : ' + pubPrefixedHashSHA)
console.log('pubPrefixedHashSHAFlure   : ' + pubPrefixedHashSHAF)
console.log('pubPrefixedHashSHAExpected: db4d4ce64b247d247761c8aecbbcebbba0453009f8eb82fab984c549b6833be0')
console.log('*****Step 1*****')
console.log('')

const resultHashSHAF = crypoBase.sha2_256(hexToUnit8Array(pubPrefixedHashSHAF));
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
console.log('account_idFluree_crypto_base: ' + crypoBase.account_id_from_public("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"))
console.log('account_idExpected          : ' + bs58check.encode(bs58check.decode('TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV')))
console.log('*****Step 2A **Error**')
console.log('')


const account_id = bs58check.encode(hexToUnit8Array(pubPrefixed))
const account_idF = bs58check.encode(hexToUnit8Array(pubPrefixedF))

console.log('*****Step 2B **OK**')
console.log('account_id                  : ' + account_id)
console.log('account_idFluree            : ' + account_idF)
console.log('account_idFluree_crypto_base: ' + crypoBase.account_id_from_public("02991719b37817f6108fc8b0e824d3a9daa3d39bc97ecfd4f8bc7ef3b71d4c6391"))
console.log('account_idExpected          : ' + bs58check.encode(bs58check.decode('TfGvAdKH2nRdV4zP4yBz4kJ2R9WzYHDe2EV')))
console.log('*****Step 2B **OK***')
console.log('')

console.log('Phase Final ------ERROR-------')
console.log('')