
import { beforeEach, describe, expect, test } from '@jest/globals';
import { decrypt, encrypt, getEphemeralSecretAndPublicKey, setCryptoJS, setHkdf, setIotaCrypto, util, encryptPayloadList, decryptOneOfList} from '../src';
import { Bip39, Ed25519, Sha512, Bip32Path } from '@iota/crypto.js';
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
describe('entrypt decrypt test for ecies ed25519',()=>{
    let receiverInfo:{secret:Uint8Array,publicKey:Uint8Array}
    let contentToBeEncrypted:string
    let encryptResult:{
        ephemeralPublicKey:Uint8Array,
        aesKey:string,
        encrypted:string,
        payload:Uint8Array
    }
    let decryptResult:{
        ephemeralPublicKey:Uint8Array,
        aesKey:string,
        encrypted:Uint8Array,
        payload:string
    }
    const tag = Converter.utf8ToBytes('DUMMYTAG')
    const generatePublicKeyAndAddressPair = () => {
        const mnemonic = Bip39.randomMnemonic(128)
        const seed = Ed25519Seed.fromMnemonic(mnemonic)
        const accountState = {
            accountIndex: 0,
            addressIndex: 0,
            isInternal: false
        }
        let path = generateBip44Address(accountState,COIN_TYPE_SHIMMER)
        const addressSeed = seed.generateSeedFromPath(new Bip32Path(path))
        const addressKeyPair = addressSeed.keyPair()
        const publicKey = addressKeyPair.publicKey
        const publicKeyHex = Converter.bytesToHex(publicKey,true)
        const genesisEd25519Address = new Ed25519Address(publicKey);
        const genesisWalletAddress = genesisEd25519Address.toAddress();
        const accountBech32Address = Bech32Helper.toBech32(ED25519_ADDRESS_TYPE, genesisWalletAddress, 'smr');
        return {
            mkey:publicKeyHex,
            addr:accountBech32Address,
            privateKey: addressKeyPair.privateKey
        }
    }
    beforeEach(async ()=>{
        receiverInfo = getEphemeralSecretAndPublicKey()
        contentToBeEncrypted = 'hehe'//Bip39.randomMnemonic(128)
        encryptResult = await encrypt(receiverInfo.publicKey,contentToBeEncrypted,tag)
        decryptResult = await decrypt(receiverInfo.secret, encryptResult.payload,tag)
    })
    
    test('test ephemeralPublicKey equal',()=>{        
        expect(encryptResult.ephemeralPublicKey).toEqual(decryptResult.ephemeralPublicKey);
    })
    test('test aeskey equal',()=>{        
        expect(encryptResult.aesKey).toEqual(decryptResult.aesKey);
    })
    test('test encrypted',()=>{        
        expect(encryptResult.encrypted).toEqual(util.bytesToHex(decryptResult.encrypted));
    })
    test('test content equal after encrypt then decrypt',()=>{        
        expect(contentToBeEncrypted).toEqual(decryptResult.payload);
    })
    test('test encrypt a list then decrypt random one of it',async ()=>{
        // use generatePublicKeyAndAddressPair generate 100 pairs
        const pairs:{mkey:string, addr:string,privateKey:Uint8Array}[] = []
        for(let i = 0;i<100;i++){
            pairs.push(generatePublicKeyAndAddressPair())
        }
        const contentToBeEncrypted = Bip39.randomMnemonic(128)
        const encryptingPayloadList = pairs.map(pair=>({addr:pair.addr,publicKey:Converter.hexToBytes(pair.mkey),content:contentToBeEncrypted}))
        const encryptResult = await encryptPayloadList({payloadList:encryptingPayloadList,tag})
        const randomIndex = Math.floor(Math.random()*encryptingPayloadList.length)
        const randomPair = pairs[randomIndex]
        const decrypted = await decryptOneOfList({payloadList:encryptResult,receiverSecret:randomPair.privateKey,tag, idx:randomIndex})
        expect(decrypted.payload).toEqual(contentToBeEncrypted)
    })
    test('test encrypt a list then decrypt random one of it with fixed content and pair',async ()=>{
        const pairs:{mkey:string, addr:string,privateKey:Uint8Array}[] = [{
            mkey:"0x3ff5652902770c77d5fe8ff7bc6902c9c14646a73fa500f5e304e24c83db5c15",
            addr:"65e28f9b0090daa5bbf9cde6aa12b3a1c50d13f2",
            privateKey:Converter.hexToBytes("0x4782c4ec671736f1d649d5b5998e883e025b9b9aac5509c9250ceacd94c70fbbecfb4a3ebb662b8294b3a5d2da8cd4d4f6f9a2a87e979cedc0f2de24a607d3c3")
        }]
        const contentToBeEncrypted = 'ZK@%FH_SCw!IzxE6Mf%Xvjpu1@LboluI'
        const encryptingPayloadList = pairs.map(pair=>({addr:pair.addr,publicKey:Converter.hexToBytes(pair.mkey),content:contentToBeEncrypted}))
        const encryptResult = await encryptPayloadList({payloadList:encryptingPayloadList,tag})
        const randomIndex = Math.floor(Math.random()*encryptingPayloadList.length)
        const randomPair = pairs[randomIndex]
        const decrypted = await decryptOneOfList({payloadList:encryptResult,receiverSecret:randomPair.privateKey,tag, idx:randomIndex})
        expect(decrypted.payload).toEqual(contentToBeEncrypted)
    })
})