import type hkdf from "futoin-hkdf";
import { Bip39, Ed25519, Sha512 } from "@iota/crypto.js";
import { ExtendedPoint, modL_LE, etc } from "./nobleEd";
import type CryptoJS from 'crypto-js'

let _CryptoJS:typeof CryptoJS
let _hkdf:typeof hkdf

const PUBLIC_KEY_LEN = 32
const SHARED_LEN = 32

export const util = etc
export const setCryptoJS = (instance:typeof CryptoJS) => {
    _CryptoJS = instance
}
export const setHkdf = (instance:typeof hkdf) => {
    _hkdf = instance
}
export function prepareBytesForScalar(bytes:Uint8Array) {
    bytes = bytes.slice(0,Ed25519.SEED_SIZE)
    if (bytes.length !== Ed25519.SEED_SIZE) throw new Error('Invalid seed length')
    const sha512 = new Sha512();
    sha512.update(bytes);

    const digest = sha512.digest();
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;
    return digest.slice(0,32);
}

export const  getEphemeralSecretAndPublicKey = () => {
    const mnemonic = Bip39.randomMnemonic(128)
    
    const ephemeralSecret = Bip39.mnemonicToSeed(mnemonic).slice(0, Ed25519.SEED_SIZE);
    
    const ephemeralPrivateKey = Ed25519.privateKeyFromSeed(ephemeralSecret);
    
    const ephemeralPublicKey = Ed25519.publicKeyFromPrivateKey(ephemeralPrivateKey);
    return {
        secret:ephemeralSecret,
        publicKey:ephemeralPublicKey
    }
}
export const encapsulate = (ephemeralSecret:Uint8Array, ephemeralPublicKey:Uint8Array,receiverPublicKey:Uint8Array, tag:string = '') => {

    if (receiverPublicKey.length !== PUBLIC_KEY_LEN) {
        throw new Error("Receiver public key must be 32 bytes.")
    }

    // get product of two scalars
    const sharedSecret = productOfTwo(ephemeralSecret, receiverPublicKey)
    const key = _hkdf(Buffer.concat([Buffer.from(ephemeralPublicKey),Buffer.from(sharedSecret)]), PUBLIC_KEY_LEN + SHARED_LEN, {
        salt:tag
    })
    return key
}
export const productOfTwo = (secret:Uint8Array,publicKey:Uint8Array) => {
    let point = ExtendedPoint.fromHex(etc.bytesToHex(publicKey))
    const scalar = modL_LE(prepareBytesForScalar(secret))
    point = point.multiply(scalar)
    return point.toRawBytes()
}
export const decapsulate = (ephemeralPublicKey:Uint8Array, receiverSecret:Uint8Array,tag:string='') => {
    const sharedSecret = productOfTwo(receiverSecret, ephemeralPublicKey)
    const key = _hkdf(Buffer.concat([Buffer.from(ephemeralPublicKey),Buffer.from(sharedSecret)]), PUBLIC_KEY_LEN + SHARED_LEN, {
        salt:tag
    })
    return key
}

export const encrypt = (receiverPublicKey:Uint8Array,content:string,tag='')=>{
    const {secret, publicKey} = getEphemeralSecretAndPublicKey()
    
    const aesKey = etc.bytesToHex(encapsulate(secret,publicKey,receiverPublicKey,tag))
    const encrypted = aesEncrypt(content, aesKey)
    return {
        ephemeralPublicKey:publicKey,
        aesKey,
        encrypted,
        payload:etc.bytesToHex(publicKey) + encrypted
    }
}
export const aesEncrypt = (content:string,aesKey:string) => {
    const contentWord = _CryptoJS.enc.Utf8.parse(content)
    const {key,iv} = getKeyAndIv(aesKey)
    const encrypted = _CryptoJS.AES.encrypt(
        contentWord,
        key,
        { iv, mode: _CryptoJS.mode.CBC, padding: _CryptoJS.pad.Pkcs7 }
    ).ciphertext.toString(_CryptoJS.enc.Base64)
    return encrypted
}
export const decrypt = (receiverSecret:Uint8Array, content:string,tag='') => {
    const ephemeralPublicKeyHex = content.substring(0,64)
    const ephemeralPublicKey = etc.hexToBytes(ephemeralPublicKeyHex)
    const encrypted = content.substring(64)
    const aesKey = etc.bytesToHex(decapsulate(ephemeralPublicKey,receiverSecret,tag))
    const decrypted = aesDecrypt(encrypted,aesKey)
    return {
        ephemeralPublicKey,
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
    const encryptedWord = _CryptoJS.enc.Base64.parse(encrypted)
    const encryptedParam = _CryptoJS.lib.CipherParams.create({
        ciphertext: encryptedWord,
    })
    return _CryptoJS.AES.decrypt(encryptedParam,key,{ iv, mode: _CryptoJS.mode.CBC, padding: _CryptoJS.pad.Pkcs7 }).toString(_CryptoJS.enc.Utf8)
}

