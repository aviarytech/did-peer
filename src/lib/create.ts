import { Numalgo2Prefixes, VARIANT_4_PREFIX, JSON_MULTICODEC_PREFIX, SHA256_MULTIHASH_PREFIX, SHA256_HASH_LENGTH, MULTIBASE_BASE58BTC_PREFIX } from "./constants.js";
import type { IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "./interfaces.js"
import { encodeService } from "./utils.js";
import { validateAuthentication, validateEncryption } from "./validators.js";
import { createHash } from 'crypto';

export const create = async (
    numalgo: number,
    authenticationKeys: IDIDDocumentVerificationMethod[],
    encryptionKeys?: IDIDDocumentVerificationMethod[],
    service?: IDIDDocumentServiceDescriptor | IDIDDocumentServiceDescriptor[]
): Promise<string> => {
    if (service && !Array.isArray(service)) {
        service = [service];
    }
    switch (numalgo) {
        case 0:
            return createNumAlgo0(authenticationKeys[0]);
        case 1:
            return createNumAlgo1();
        case 2:
            return createNumAlgo2(authenticationKeys, encryptionKeys, service);
        case 4:
            return createNumAlgo4(authenticationKeys, encryptionKeys, service);
        default:
            throw new Error(`numalgo ${numalgo} not recognized`);
    }
}

export const createNumAlgo0 = async (authenticationKey: IDIDDocumentVerificationMethod): Promise<string> => {
    validateAuthentication(authenticationKey)
    return `did:peer:0${authenticationKey.publicKeyMultibase}`
}

export const createNumAlgo1 = async (): Promise<string> => {
    throw new Error('NumAlgo1 not supported')
}

export const createNumAlgo2 = async (
    authenticationKeys: IDIDDocumentVerificationMethod[],
    encryptionKeys?: IDIDDocumentVerificationMethod[],
    service?: IDIDDocumentServiceDescriptor[]
): Promise<string> => {
    authenticationKeys.forEach(k => validateAuthentication(k));
    encryptionKeys?.forEach(k => validateEncryption(k));
    const auth = authenticationKeys.map(k => `.${Numalgo2Prefixes.Authentication}${k.publicKeyMultibase}`)
    const enc = encryptionKeys ? encryptionKeys.map(k => `.${Numalgo2Prefixes.KeyAgreement}${k.publicKeyMultibase}`) : '';
    const serv = service ? service?.map(s => encodeService(s)).join("") : '';
    return `did:peer:2${auth}${enc}${serv}`
}

export const createNumAlgo4 = async (
    authenticationKeys: IDIDDocumentVerificationMethod[],
    encryptionKeys?: IDIDDocumentVerificationMethod[],
    service?: IDIDDocumentServiceDescriptor[]
): Promise<string> => {
    // Create input document for variant 4
    const inputDoc: any = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]
    };

    // Add verification methods
    if (authenticationKeys.length > 0 || encryptionKeys?.length) {
        inputDoc.verificationMethod = [];
        
        let keyIndex = 0;
        authenticationKeys.forEach(key => {
            inputDoc.verificationMethod.push({
                id: `#key-${keyIndex++}`,
                type: key.type || "Multikey",
                publicKeyMultibase: key.publicKeyMultibase
            });
        });

        encryptionKeys?.forEach(key => {
            inputDoc.verificationMethod.push({
                id: `#key-${keyIndex++}`,
                type: key.type || "Multikey", 
                publicKeyMultibase: key.publicKeyMultibase
            });
        });
    }

    // Add verification relationships
    if (authenticationKeys.length > 0) {
        inputDoc.authentication = authenticationKeys.map((_, i) => `#key-${i}`);
    }

    if (encryptionKeys?.length) {
        inputDoc.keyAgreement = encryptionKeys.map((_, i) => `#key-${authenticationKeys.length + i}`);
    }

    // Add services
    if (service?.length) {
        inputDoc.service = service;
    }

    // Step 1: Encode the document
    const jsonString = JSON.stringify(inputDoc);
    const jsonBytes = new TextEncoder().encode(jsonString);
    
    // Add multicodec prefix for JSON
    // const jsonMulticodecBytes = encodeVarint(JSON_MULTICODEC_PREFIX);
    // const prefixedBytes = new Uint8Array(jsonMulticodecBytes.length + jsonBytes.length);
    // prefixedBytes.set(jsonMulticodecBytes);
    // prefixedBytes.set(jsonBytes, jsonMulticodecBytes.length);
    
    // Multibase encode as base58btc
    const encodedDocument = MULTIBASE_BASE58BTC_PREFIX + base58Encode(jsonBytes);

    // Step 2: Hash the document
    const hash = createHash('sha256').update(encodedDocument).digest();
    
    // Add multihash prefix
    const multihashPrefix = new Uint8Array([SHA256_MULTIHASH_PREFIX, SHA256_HASH_LENGTH]);
    const multihash = new Uint8Array(multihashPrefix.length + hash.length);
    multihash.set(multihashPrefix);
    multihash.set(hash, multihashPrefix.length);
    
    // Multibase encode the hash
    const hashString = MULTIBASE_BASE58BTC_PREFIX + base58Encode(multihash);

    // Step 3: Construct the DID
    return `did:peer:${VARIANT_4_PREFIX}${hashString}:${encodedDocument}`;
}

// Helper function to encode varint
function encodeVarint(value: number): Uint8Array {
    const bytes: number[] = [];
    while (value >= 0x80) {
        bytes.push((value & 0xFF) | 0x80);
        value >>>= 7;
    }
    bytes.push(value & 0xFF);
    return new Uint8Array(bytes);
}

// Helper function for base58 encoding
function base58Encode(bytes: Uint8Array): string {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    if (num === 0n) return alphabet[0];
    
    let result = '';
    while (num > 0n) {
        result = alphabet[Number(num % 58n)] + result;
        num = num / 58n;
    }
    
    // Add leading zeros
    for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
        result = alphabet[0] + result;
    }
    
    return result;
}
