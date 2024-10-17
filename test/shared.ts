import { Bip39, Ed25519, Sha512, Bip32Path } from '@iota/crypto.js';
import { Ed25519Seed, generateBip44Address, COIN_TYPE_SHIMMER,Ed25519Address,Bech32Helper,ED25519_ADDRESS_TYPE } from '@iota/iota.js';
import { Converter } from '@iota/util.js';
import { decrypt, encrypt, getEphemeralSecretAndPublicKey, setCryptoJS, setHkdf, setIotaCrypto, util, encryptPayloadList, decryptOneOfList} from '../src';

export const generateRandomStr = (len:number) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    let result:string[] = []
    for (let i = 0; i < len; i++) {
        result.push(chars.charAt(Math.floor(Math.random() * chars.length)))
    }
    return result.join('')
}

export const generatePublicKeyAndAddressPair = () => {
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

export const testList = async (contentToBeEncrypted:string, tag:Uint8Array, pairs:{mkey:string, addr:string,privateKey:Uint8Array}[]) => {
    const encryptingPayloadList = pairs.map(pair=>({addr:pair.addr,publicKey:Converter.hexToBytes(pair.mkey),content:contentToBeEncrypted}))
    const encryptResult = await encryptPayloadList({payloadList:encryptingPayloadList,tag})
    const randomIndex = Math.floor(Math.random()*encryptingPayloadList.length)
    const randomPair = pairs[randomIndex]
    const decrypted = await decryptOneOfList({payloadList:encryptResult,receiverSecret:randomPair.privateKey,tag, idx:randomIndex})
    return decrypted
}