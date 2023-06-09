/// <reference types="node" />
import CryptoJS from 'crypto-js';
export declare function prepareBytesForScalar(bytes: Uint8Array): Uint8Array;
export declare const getEphemeralSecretAndPublicKey: () => {
    secret: Uint8Array;
    publicKey: Uint8Array;
};
export declare const encapsulate: (ephemeralSecret: Uint8Array, ephemeralPublicKey: Uint8Array, receiverPublicKey: Uint8Array, tag?: string) => Buffer;
export declare const productOfTwo: (secret: Uint8Array, publicKey: Uint8Array) => Uint8Array;
export declare const decapsulate: (ephemeralPublicKey: Uint8Array, receiverSecret: Uint8Array, tag?: string) => Buffer;
export declare const encrypt: (receiverPublicKey: Uint8Array, content: string, tag?: string) => {
    ephemeralPublicKey: Uint8Array;
    aesKey: string;
    encrypted: string;
    payload: string;
};
export declare const aesEncrypt: (content: string, aesKey: string) => string;
export declare const decrypt: (receiverSecret: Uint8Array, content: string, tag?: string) => {
    ephemeralPublicKey: Uint8Array;
    encrypted: string;
    aesKey: string;
    payload: string;
};
export declare const getKeyAndIv: (password: string) => {
    key: CryptoJS.lib.WordArray;
    iv: CryptoJS.lib.WordArray;
};
export declare const aesDecrypt: (encrypted: string, aesKey: string) => string;
//# sourceMappingURL=index.d.ts.map