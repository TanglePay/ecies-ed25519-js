
import { beforeEach, describe, expect, test } from '@jest/globals';
import { setCryptoJS, prepareBytesForScalar, decapsulate, encapsulate, getEphemeralSecretAndPublicKey, productOfTwo, setHkdf, setIotaCrypto } from '../src';
import { ExtendedPoint, etc, modL_LE } from '../src/nobleEd';
import { Converter } from '@iota/util.js';
import { Bip39, Ed25519, Sha512, Bip32Path } from '@iota/crypto.js';
setIotaCrypto({
    Bip39,
    Ed25519,
    Sha512
})
import { Ed25519Seed, generateBip44Address, COIN_TYPE_SHIMMER } from '@iota/iota.js';
import CryptoJS from 'crypto-js';
import hkdf from 'js-crypto-hkdf';
setHkdf(async (secret:Uint8Array, length:number, salt:Uint8Array)=>{
    const res = await hkdf.compute(secret, 'SHA-256', length, '',salt)
    return res.key;
})
setCryptoJS(CryptoJS)
describe('basic test for ecies ed25519',()=>{
    let receiverInfo:{secret:Uint8Array,publicKey:Uint8Array}
    const tag = Converter.utf8ToBytes('DUMMYTAG')

    beforeEach(()=>{
        receiverInfo = getEphemeralSecretAndPublicKey()
    })

    test('iota and noble ed25519 interoperable publickey',async ()=>{
        const scalar = modL_LE(prepareBytesForScalar(receiverInfo.secret))
        const noblePublicKey =  ExtendedPoint.BASE.multiply(scalar).toRawBytes()
        expect(noblePublicKey).toEqual(receiverInfo.publicKey)
    })

    test('iota and noble ed25519 interoperable from mnemonic',async ()=>{
        const mnemonic = 'hard soap degree message stand update program hour false trigger series meat'
        const seed = Ed25519Seed.fromMnemonic(mnemonic)
        const accountState = {
            accountIndex: 0,
            addressIndex: 0,
            isInternal: false
        }
        let path = generateBip44Address(accountState)
        const addressSeed = seed.generateSeedFromPath(new Bip32Path(path))
        const addressKeyPair = addressSeed.keyPair()
        const publicKey = addressKeyPair.publicKey
        const privateKey = addressKeyPair.privateKey
        const scalar = modL_LE(prepareBytesForScalar(privateKey))
        const noblePublicKey =  ExtendedPoint.BASE.multiply(scalar).toRawBytes()
        expect(noblePublicKey).toEqual(publicKey)
    })
    test('test cross product of two pair is same',()=>{
        const {secret:secret1, publicKey:publicKey1} = getEphemeralSecretAndPublicKey()
        const {secret:secret2, publicKey:publicKey2} = getEphemeralSecretAndPublicKey()
        const product1 = productOfTwo(secret1,publicKey2)
        const product2 = productOfTwo(secret2,publicKey1)
        expect(product1).toEqual(product2)
    })

    test('test encap and decap should equal',()=>{
        const {secret:secret1, publicKey:publicKey1} = getEphemeralSecretAndPublicKey()
        
        const {secret:secret2, publicKey:publicKey2} = getEphemeralSecretAndPublicKey()
        const product1 = productOfTwo(secret1,publicKey2)
        const product2 = productOfTwo(secret2,publicKey1)
        expect(product1).toEqual(product2)
        const b1 = encapsulate(secret1,publicKey1,publicKey2,tag)
        const b2 = decapsulate(publicKey1,secret2,tag)
        expect(b1).toEqual(b2)

    })
    test('test publicKey hex length is 64',()=>{
        const hex = etc.bytesToHex(receiverInfo.publicKey)
        expect(hex.length).toEqual(64)
    })
    
    test('test public key from transaction',()=>{
        const mnemonic = 'hard soap degree message stand update program hour false trigger series meat'
        const seed = Ed25519Seed.fromMnemonic(mnemonic)
        const addressGeneratorAccountState = {
            accountIndex: 0,
            addressIndex: 0,
            isInternal: false
        };
        const path = generateBip44Address(addressGeneratorAccountState,COIN_TYPE_SHIMMER);

        console.log(`Wallet Index ${path}`);

        const addressSeed = seed.generateSeedFromPath(new Bip32Path(path));
        const addressKeyPair = addressSeed.keyPair();
        const publicKey = addressKeyPair.publicKey
        const publicKeyHex = Converter.bytesToHex(publicKey,true)
        const publicKeyFromTransaction = '0x5424b4c93053b649ea0dfb3a723171b10bb660f5a61eb6029bef015f324a8299'
        expect(publicKeyHex).toEqual(publicKeyFromTransaction)
        expect(publicKey).toEqual(Converter.hexToBytes(publicKeyFromTransaction))
        
    })

})