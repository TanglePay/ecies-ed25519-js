
import { beforeEach, describe, expect, test } from '@jest/globals';
import { decrypt, encrypt, getEphemeralSecretAndPublicKey, setCryptoJS, setHkdf, setIotaCrypto} from '../src';
import { Bip39, Ed25519, Sha512 } from '@iota/crypto.js';
setIotaCrypto({
    Bip39,
    Ed25519,
    Sha512
})
import CryptoJS from 'crypto-js';
import hkdf from 'js-crypto-hkdf';
import { Converter } from '@iota/util.js';
setHkdf(async (secret:Uint8Array, length:number, salt:Uint8Array)=>{
    const res = await hkdf.compute(secret, 'SHA-256', length, '',salt)
    return res.key;
})
setCryptoJS(CryptoJS)
describe('entrypt decrypt test for ecies ed25519',()=>{
    let receiverInfo:{secret:Uint8Array,publicKey:Uint8Array}
    let contentToBeEncrypted:string
    let encryptResult:{
        ephemeralPublicKey:Uint8Array,
        aesKey:string,
        encrypted:string,
        payload:string
    }
    let decryptResult:{
        ephemeralPublicKey:Uint8Array,
        aesKey:string,
        encrypted:string,
        payload:string
    }
    const tag = Converter.utf8ToBytes('DUMMYTAG')
    beforeEach(async ()=>{
        receiverInfo = getEphemeralSecretAndPublicKey()
        contentToBeEncrypted = 'hehe'//Bip39.randomMnemonic(128)
        encryptResult = await encrypt(receiverInfo.publicKey,contentToBeEncrypted,tag)
        decryptResult = await decrypt(receiverInfo.secret,encryptResult.payload,tag)
    })
    
    test('test ephemeralPublicKey equal',()=>{        
        expect(encryptResult.ephemeralPublicKey).toEqual(decryptResult.ephemeralPublicKey);
    })
    test('test aeskey equal',()=>{        
        expect(encryptResult.aesKey).toEqual(decryptResult.aesKey);
    })
    test('test encrypted',()=>{        
        expect(encryptResult.encrypted).toEqual(decryptResult.encrypted);
    })
    test('test content equal after encrypt then decrypt',()=>{        
        expect(contentToBeEncrypted).toEqual(decryptResult.payload);
    })
})