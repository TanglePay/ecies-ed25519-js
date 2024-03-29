
import type { Bip39, Ed25519, Sha512 } from "@iota/crypto.js";
import { ExtendedPoint, modL_LE, etc } from "./nobleEd";
import type CryptoJS from 'crypto-js'

let _CryptoJS:typeof CryptoJS
let _hkdf:(secret:Uint8Array, length:number, salt:Uint8Array)=>Promise<Uint8Array>
let IotaCrypto:{
    Bip39: typeof Bip39,
    Ed25519: typeof Ed25519,
    Sha512: typeof Sha512
}
const PUBLIC_KEY_LEN = 32
const SHARED_LEN = 32

export const util = etc
export const setCryptoJS = (instance:typeof CryptoJS) => {
    _CryptoJS = instance
}
export const setIotaCrypto = (instance:{
    Bip39: typeof Bip39,
    Ed25519: typeof Ed25519,
    Sha512: typeof Sha512
}) => {
    IotaCrypto = instance
}
export const setHkdf = (func:(secret:Uint8Array, length:number, salt:Uint8Array)=>Promise<Uint8Array>) => {
    _hkdf = func
}

export function prepareBytesForScalar(bytes:Uint8Array) {
    bytes = bytes.slice(0,IotaCrypto.Ed25519.SEED_SIZE)
    if (bytes.length !== IotaCrypto.Ed25519.SEED_SIZE) throw new Error('Invalid seed length')
    const sha512 = new IotaCrypto.Sha512();
    sha512.update(bytes);

    const digest = sha512.digest();
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;
    return digest.slice(0,32);
}

export const getEphemeralSecretAndPublicKey = () => {
    const mnemonic = IotaCrypto.Bip39.randomMnemonic(128)
    
    const ephemeralSecret = IotaCrypto.Bip39.mnemonicToSeed(mnemonic).slice(0, IotaCrypto.Ed25519.SEED_SIZE);
    
    const ephemeralPrivateKey = IotaCrypto.Ed25519.privateKeyFromSeed(ephemeralSecret);
    
    const ephemeralPublicKey = IotaCrypto.Ed25519.publicKeyFromPrivateKey(ephemeralPrivateKey);
    return {
        secret:ephemeralSecret,
        publicKey:ephemeralPublicKey
    }
}
export const encapsulate = async (ephemeralSecret:Uint8Array, ephemeralPublicKey:Uint8Array,receiverPublicKey:Uint8Array, tag:Uint8Array) => {

    if (receiverPublicKey.length !== PUBLIC_KEY_LEN) {
        throw new Error("Receiver public key must be 32 bytes.")
    }

    // get product of two scalars
    const sharedSecret = productOfTwo(ephemeralSecret, receiverPublicKey)
    const key = await _hkdf(etc.concatBytes(ephemeralPublicKey,sharedSecret), PUBLIC_KEY_LEN + SHARED_LEN, tag)
    return key
}
export const productOfTwo = (secret:Uint8Array,publicKey:Uint8Array) => {
    let point = ExtendedPoint.fromHex(etc.bytesToHex(publicKey))
    const scalar = modL_LE(prepareBytesForScalar(secret))
    point = point.multiply(scalar)
    return point.toRawBytes()
}
export const decapsulate = async (ephemeralPublicKey:Uint8Array, receiverSecret:Uint8Array,tag:Uint8Array) => {
    const sharedSecret = productOfTwo(receiverSecret, ephemeralPublicKey)
    const key = await _hkdf(etc.concatBytes(ephemeralPublicKey,sharedSecret), PUBLIC_KEY_LEN + SHARED_LEN, tag)
    return key
}

export const encrypt = async (receiverPublicKey:Uint8Array,content:string,tag:Uint8Array,ext?:{pair?:SecretAndPublicKeyPair,isPrefix?:boolean})=>{
    let {pair,isPrefix = true} = ext??{}
    if(!pair){
        pair = getEphemeralSecretAndPublicKey()
    }
    const {secret, publicKey} = pair!
    
    const aesKey = etc.bytesToHex(await encapsulate(secret,publicKey,receiverPublicKey,tag))
    const encrypted = aesEncrypt(content, aesKey)
    const encryptedBytes = etc.hexToBytes(encrypted)
    const payload = isPrefix ? etc.concatBytes(publicKey,encryptedBytes) : encryptedBytes
    return {
        ephemeralPublicKey:publicKey,
        aesKey,
        encrypted,
        payload
    }
}
export const aesEncrypt = (content:string,aesKey:string) => {
    const contentWord = _CryptoJS.enc.Utf8.parse(content)
    const {key,iv} = getKeyAndIv(aesKey)
    const encrypted = _CryptoJS.AES.encrypt(
        contentWord,
        key,
        { iv, mode: _CryptoJS.mode.CBC, padding: _CryptoJS.pad.Pkcs7 }
    ).ciphertext.toString(_CryptoJS.enc.Hex)
    return encrypted
}
export const decrypt = async (receiverSecret:Uint8Array, content:Uint8Array,tag:Uint8Array,ext?:{isPublicKeyPrefixed?:boolean,ephemeralPublicKey?:Uint8Array}) => {
    let {isPublicKeyPrefixed = true,ephemeralPublicKey} = ext ?? {}
    let encrypted = content
    if(isPublicKeyPrefixed){
        ephemeralPublicKey = content.slice(0,32)
        encrypted = content.slice(32)
    }
    const aesKey = etc.bytesToHex(await decapsulate(ephemeralPublicKey!,receiverSecret,tag))
    const decrypted = aesDecrypt(etc.bytesToHex(encrypted),aesKey)
    return {
        ephemeralPublicKey:ephemeralPublicKey!,
        encrypted,
        aesKey,
        payload: decrypted
    }
}
export const getKeyAndIv = (password:string)=>{
    const md5 = _CryptoJS.MD5(password).toString()
    const kdf1 = _CryptoJS.PBKDF2(md5, md5, { keySize: 16, iterations: 1000 })
    const kdf2 = _CryptoJS.PBKDF2(kdf1.toString(), kdf1.toString(), { keySize: 16, iterations: 1000 })
    return {key:kdf1,iv:kdf2}
}
export const aesDecrypt = (encrypted:string,aesKey:string) => {
    const {key,iv} = getKeyAndIv(aesKey)
    const encryptedWord = _CryptoJS.enc.Hex.parse(encrypted)
    const encryptedParam = _CryptoJS.lib.CipherParams.create({
        ciphertext: encryptedWord,
    })
    return _CryptoJS.AES.decrypt(encryptedParam,key,{ iv, mode: _CryptoJS.mode.CBC, padding: _CryptoJS.pad.Pkcs7 }).toString(_CryptoJS.enc.Utf8)
}

export type SecretAndPublicKeyPair = {
    secret:Uint8Array,
    publicKey:Uint8Array
}
export type EncryptingPayload = {
    publicKey:Uint8Array,
    content:string,
} & any
export type EncryptedContent = {
    content:string,
} & any;
export type EncryptedPayload = {
    payload:Uint8Array,
} & any;
export const encryptPayloadList = async ({payloadList,tag}:{payloadList:EncryptingPayload[],tag:Uint8Array}):Promise<EncryptedPayload[]> => {
    const pair = getEphemeralSecretAndPublicKey()
    const result:EncryptedPayload[] = []
    for (let i=0;i<payloadList.length;i++){
        const encryptPayload = payloadList[i]
        const {publicKey:receiverPublicKey,content} = encryptPayload
        const { payload } = await encrypt(receiverPublicKey,content,tag,{pair,isPrefix:i==0})
        encryptPayload.payload = payload
        result.push(encryptPayload)
    }
    return result
}

export const decryptOneOfList = async ({receiverSecret,payloadList,tag,idx}:{receiverSecret:Uint8Array, payloadList:EncryptedPayload[],tag:Uint8Array,idx:number}) => {
    const contentList:Uint8Array[] = []
    let ephemeralPublicKey:Uint8Array
    for (let i=0;i<payloadList.length;i++){
        let {payload} = payloadList[i];
        if (i == 0) {
            ephemeralPublicKey = payload.slice(0,32)
            payload = payload.slice(32)
        }
        contentList.push(payload)
    }
    const selectedPayload = contentList[idx]
    // call decrypt
    const result = await decrypt(receiverSecret,selectedPayload,tag,{isPublicKeyPrefixed:false,ephemeralPublicKey:ephemeralPublicKey!})
    return result
}