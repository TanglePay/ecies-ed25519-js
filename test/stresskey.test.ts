import { beforeEach, describe, expect, test } from '@jest/globals';
import { decrypt, encrypt, getEphemeralSecretAndPublicKey, setCryptoJS, setHkdf, setIotaCrypto, util, encryptPayloadList, decryptOneOfList} from '../src';
import { Bip39, Ed25519, Sha512, Bip32Path } from '@iota/crypto.js';
import { generateRandomStr, generatePublicKeyAndAddressPair, testList } from './shared';
setIotaCrypto({
    Bip39,
    Ed25519,
    Sha512
})
import CryptoJS from 'crypto-js';
import hkdf from 'js-crypto-hkdf';
import { Converter } from '@iota/util.js';
import { Ed25519Seed, generateBip44Address, COIN_TYPE_SHIMMER,Ed25519Address,Bech32Helper,ED25519_ADDRESS_TYPE } from '@iota/iota.js';
setHkdf(async (secret:Uint8Array, length:number, salt:Uint8Array)=>{
    const res = await hkdf.compute(secret, 'SHA-256', length, '',salt)
    return res.key;
})
setCryptoJS(CryptoJS)

describe('stress key content test for ecies ed25519',()=>{
    const pairs:{mkey:string, addr:string,privateKey:Uint8Array}[] = []
    const tag = Converter.utf8ToBytes('DUMMYTAG')
    beforeEach(async ()=>{
        pairs.length = 0;
        for(let i = 0;i<10;i++){
            pairs.push(generatePublicKeyAndAddressPair())
        }
    })

    test('test encrypt and decrypt once',async ()=>{
        const contentToBeEncrypted = generateRandomStr(32)
        const decrypted = await testList(contentToBeEncrypted,tag,pairs)
        expect(decrypted.payload).toEqual(contentToBeEncrypted)
    })

    test('test encrypt and decrypt 100 times',async ()=>{
        for(let i = 0;i<100;i++){
            const contentToBeEncrypted = generateRandomStr(32)
            const decrypted = await testList(contentToBeEncrypted,tag,pairs)
            expect(decrypted.payload).toEqual(contentToBeEncrypted)
        }
    })

})
