
import { describe, expect, test } from '@jest/globals';
import { aesEncrypt, aesDecrypt, getKeyAndIv, setCryptoJS, setHkdf } from '../src';
import { Bip39 } from '@iota/crypto.js';
import CryptoJS from 'crypto-js';
import hkdf from 'futoin-hkdf';
setHkdf(hkdf)
setCryptoJS(CryptoJS)
describe('basic test for ecies ed25519',()=>{
    const basicContent = 'hehe'
    const basicAesKey = '12321321321321312'

    test('test raw case',()=>{
        const encrypted = CryptoJS.AES.encrypt(basicContent,basicAesKey).toString()
        const decrypted = CryptoJS.AES.decrypt(encrypted,basicAesKey).toString(CryptoJS.enc.Utf8)
        expect(decrypted).toEqual(basicContent)
    })
    test('test raw case with config',()=>{
        const {key, iv} = getKeyAndIv(basicAesKey)
        const encrypted = CryptoJS.AES.encrypt(basicContent,key,{ iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).ciphertext.toString(CryptoJS.enc.Base64)
        const encryptedWord = CryptoJS.enc.Base64.parse(encrypted)
        const encryptedParam = CryptoJS.lib.CipherParams.create({
            ciphertext:encryptedWord
        })
        const decrypted = CryptoJS.AES.decrypt(encryptedParam,key,{ iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString(CryptoJS.enc.Utf8)
        expect(decrypted).toEqual(basicContent)
    })
    
    test('test basic case',()=>{
        const encrypted = aesEncrypt(basicContent,basicAesKey)
        const decrypted = aesDecrypt(encrypted, basicAesKey)
        expect(decrypted).toEqual(basicContent)
    })
    
    test('test random content case',()=>{
        const content = Bip39.randomMnemonic(128)
        const key = Bip39.randomMnemonic(128)
        const encrypted = aesEncrypt(content,key)
        const decrypted = aesDecrypt(encrypted, key)
        expect(decrypted).toEqual(content)
    })
})