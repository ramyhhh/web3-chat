import { TokenType } from "@angular/compiler"

const { subtle, getRandomValues } = crypto

export type Bytes = Uint8Array



export function decode(input: Bytes): string { return new TextDecoder().decode(input) }
export function encode(input: string): Bytes { return new TextEncoder().encode(input) }

export function randomBytes(length = 16) {
    const buffer = new Uint8Array(length)
    getRandomValues(buffer)
    return buffer
}
export function random(length = 16): string {
    return decode(randomBytes(length))
}




// export async function HKDF(inputKey: CryptoKey, salt: CryptoKey, infoStr: BufferSource) {

//     // Calculates HKDF outputs
//     // inputKey is a cryptoKey with derivedKeyAlgorithm HMAC
//     // salt is a second cryptoKey with derivedKeyAlgorithm HMAC
//     // infoStr is a string (can be an arbitrary constant e.g. "ratchet-str")
//     // returns an array of two HKDF outputs [HKDF_out1, HKDF_out2]

//     // since inputKey's derivedKeyAlgorithm is HMAC, we need to sign an arbitrary constant and
//     // then re-import as a a CryptoKey with derivedKeyAlgorithm HKDF
//     let inputKey_buff = await subtle.sign({ name: "HMAC" }, inputKey, encode("0"));
//     let inputKey_HKDF = await subtle.importKey("raw", inputKey_buff, "HKDF", false, ["deriveKey"]);

//     // Generate salts that will be needed for deriveKey calls later on
//     let salt1 = await subtle.sign({ name: "HMAC" }, salt, encode("salt1"));
//     let salt2 = await subtle.sign({ name: "HMAC" }, salt, encode("salt2"));

//     // calculate first HKDF output (with salt1)
//     const HKDF_out1 = await subtle.deriveKey(
//         { name: "HKDF", hash: "SHA-256", salt: salt1, info: infoStr },
//         inputKey_HKDF, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);

//     // calculate second HKDF output (with salt2)
//     const HKDF_out2 = await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: salt2, info: infoStr },
//         inputKey_HKDF, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);

//     return [HKDF_out1, HKDF_out2];
// }

export namespace HMAC {
    export async function deriveAesKey(key: CryptoKey, input: BufferSource, extractable = false): Promise<CryptoKey> {
        const buff = await subtle.sign({ name: "HMAC" }, key, input)
        return subtle.importKey("raw", buff, "AES-GCM", extractable, ["encrypt", "decrypt"])
    }
    export async function deriveHmacKey(key: CryptoKey, input: BufferSource): Promise<CryptoKey> {
        const buff = await subtle.sign({ name: "HMAC" }, key, input);
        return subtle.importKey("raw", buff, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
    }
}

export namespace AES {

    export function encrypt(key: CryptoKey, plaintext: BufferSource, iv: BufferSource, authenticatedData?: BufferSource) {
        return subtle.encrypt(
            { name: "AES-GCM", iv: iv, additionalData: authenticatedData }
            ,
            key,
            plaintext);
    }

    export function decrypt(key: CryptoKey, ciphertext: BufferSource, iv: BufferSource, authenticatedData?: BufferSource) {
        return subtle.decrypt(
            { name: "AES-GCM", iv: iv, additionalData: authenticatedData },
            key,
            ciphertext);
    }
}

export namespace ECDH {
    
    export const namedCurve = "P-384"

    export function generate(): Promise<CryptoKeyPair> {
        return subtle.generateKey({ name: "ECDH", namedCurve }, false, ["deriveKey"])
    }

    export function deriveHmacKey(myPrivateKey: CryptoKey, theirPublicKey: CryptoKey): Promise<CryptoKey> {
        return subtle.deriveKey({ name: "ECDH", public: theirPublicKey },
            myPrivateKey,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            false,
            ["sign", "verify"])
    }
}

export namespace ECDSA {

    export const namedCurve = "P-384"
    
    export function generate(): Promise<CryptoKeyPair> {
        return subtle.generateKey({ name: "ECDSA", namedCurve }, false, ["sign", "verify"])
    }

    export function sign(privateKey: CryptoKey, message: BufferSource): Promise<BufferSource> {
        return subtle.sign({ name: "ECDSA", hash: { name: "SHA-384" } }, privateKey, message)
    }

    export function verify(publicKey: CryptoKey, message: BufferSource, signature: BufferSource): Promise<boolean> {
        return subtle.verify({ name: "ECDSA", hash: { name: "SHA-384" } }, publicKey, signature, message)
    }
}