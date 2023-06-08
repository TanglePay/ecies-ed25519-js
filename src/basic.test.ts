
import { beforeEach, describe, expect, test } from '@jest/globals';
import { prepareBytesForScalar, decapsulate, decrypt, encapsulate, encrypt, getEphemeralSecretAndPublicKey, productOfTwo } from '.';
import { ExtendedPoint, etc, getPublicKeyAsync, modL_LE } from './nobleEd'
import { ExtendedGroupElement } from './edwards25519/extendedGroupElement';
describe('basic test for ecies ed25519',()=>{
    let receiverInfo:{secret:Uint8Array,publicKey:Uint8Array}
    const tag = 'IOTACAT'
    beforeEach(()=>{
        receiverInfo = getEphemeralSecretAndPublicKey()
    })
    test('iota and noble ed25519 interoperable multiply',()=>{
        const iotaBasePoint = new ExtendedGroupElement()
        const iotaBaseProduct = new Uint8Array(32);
        const prepared = prepareBytesForScalar(receiverInfo.secret)
        iotaBasePoint.scalarMultBase(prepared)
        iotaBasePoint.toBytes(iotaBaseProduct)
        const scalar = modL_LE(prepared)
        const nobleProduct =  ExtendedPoint.BASE.multiply(scalar).toRawBytes()
        expect(iotaBaseProduct).toEqual(nobleProduct)
    })
    test('iota and noble ed25519 interoperable publickey',async ()=>{
        const scalar = modL_LE(prepareBytesForScalar(receiverInfo.secret))
        const noblePublicKey =  ExtendedPoint.BASE.multiply(scalar).toRawBytes()
        expect(noblePublicKey).toEqual(receiverInfo.publicKey)
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

})