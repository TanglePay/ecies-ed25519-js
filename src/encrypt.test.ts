
import { beforeEach, describe, expect, test } from '@jest/globals';
import { decrypt, encrypt, getEphemeralSecretAndPublicKey } from '.';
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
    const tag = 'IOTACAT'
    beforeEach(()=>{
        receiverInfo = getEphemeralSecretAndPublicKey()
        contentToBeEncrypted = 'hehe'//Bip39.randomMnemonic(128)
        encryptResult = encrypt(receiverInfo.publicKey,contentToBeEncrypted,tag)
        decryptResult = decrypt(receiverInfo.secret,encryptResult.payload,tag)
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