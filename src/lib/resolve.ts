import { Numalgo2Prefixes, VARIANT_4_PREFIX, JSON_MULTICODEC_PREFIX, SHA256_MULTIHASH_PREFIX, SHA256_HASH_LENGTH, MULTIBASE_BASE58BTC_PREFIX } from "./constants.js";
import type { IDIDDocument, IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "./interfaces.js";
import { assert, createDIDDocument, decodeService, isPeerDID } from "./utils.js";
import { createHash } from 'crypto';

export const resolve = async (did: string): Promise<IDIDDocument> => {
    assert(isPeerDID(did), `${did} is not a valid did:peer`)
    switch(did.slice(9,10)) {
        case '0':
            return resolveNumAlgo0(did);
        case '1':
            return resolveNumAlgo1(did);
        case '2':
            return resolveNumAlgo2(did);
        case '4':
            return resolveNumAlgo4(did);
        default:
            throw new Error(`numalgo ${did.slice(9,10)} not recognized`);
    }
}

export const resolveNumAlgo0 = async (did: string): Promise<IDIDDocument> => {
    const multibaseKey = did.slice(10)
    const key = {
        id: `${did}#${multibaseKey.slice(1)}`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: multibaseKey
    }
    return createDIDDocument(did, [key], [], []);
}

export const resolveNumAlgo1 = async (did: string): Promise<IDIDDocument> => {
    throw new Error('NumAlgo1 not supported')
}

export const resolveNumAlgo2 = async (did: string): Promise<IDIDDocument> => {
    let authKeys: IDIDDocumentVerificationMethod[] = [];
    let encKeys: IDIDDocumentVerificationMethod[] = [];
    let services: IDIDDocumentServiceDescriptor[] = [];
    let keys = did.split('.')
    let serviceMetadata = {index: 0};
    let keyIndex = 1;
    delete keys[0];
    keys.forEach(k => {
        switch (k.slice(0,1)) {
            case Numalgo2Prefixes.Authentication:
                authKeys.push({
                    id: `#key-${keyIndex++}`,
                    controller: did,
                    type: 'Multikey',
                    publicKeyMultibase: k.slice(1)
                })
                break;
            case Numalgo2Prefixes.KeyAgreement:
                encKeys.push({
                    id: `#key-${keyIndex++}`,
                    controller: did,
                    type: 'Multikey',
                    publicKeyMultibase: k.slice(1)
                })
                break;
            case Numalgo2Prefixes.Service:
                services.push(decodeService(did, k.slice(1), serviceMetadata))
                break;
        }
    })
    return createDIDDocument(did, authKeys, encKeys, services)
}

export const resolveNumAlgo4 = async (did: string): Promise<IDIDDocument> => {
    // Check if this is a long form or short form DID
    const parts = did.split(':');
    if (parts.length < 3) {
        throw new Error('Invalid did:peer:4 format');
    }

    // Long form DID has format: did:peer:4zHash:zDocument
    // Short form DID has format: did:peer:4zHash
    const isLongForm = parts.length === 4 && parts[3] && parts[3].startsWith('z');
    
    if (isLongForm) {
        return resolveLongFormNumAlgo4(did);
    } else {
        return resolveShortFormNumAlgo4(did);
    }
}

export const resolveLongFormNumAlgo4 = async (did: string): Promise<IDIDDocument> => {
    // Extract hash and encoded document
    const parts = did.split(':');
    if (parts.length !== 4) {
        throw new Error('Invalid long form did:peer:4 format');
    }
    
    const hash = parts[2]; // includes the '4z' prefix
    const encodedDocument = parts[3];
    
    // Verify the hash
    const computedHash = createHash('sha256').update(encodedDocument).digest();
    const multihashPrefix = new Uint8Array([SHA256_MULTIHASH_PREFIX, SHA256_HASH_LENGTH]);
    const multihash = new Uint8Array(multihashPrefix.length + computedHash.length);
    multihash.set(multihashPrefix);
    multihash.set(computedHash, multihashPrefix.length);
    const expectedHash = VARIANT_4_PREFIX + MULTIBASE_BASE58BTC_PREFIX + base58Encode(multihash);
    
    if (hash !== expectedHash) {
        throw new Error('Hash verification failed for did:peer:4');
    }
    
    // Decode the document
    const decodedDocument = decodeVariant4Document(encodedDocument);
    
    // Create short form DID for alsoKnownAs
    const shortFormDid = `did:peer:${hash}`;
    
    // Contextualize the document for long form
    return contextualizeDocument(decodedDocument, did, shortFormDid);
}

export const resolveShortFormNumAlgo4 = async (did: string): Promise<IDIDDocument> => {
    // For short form resolution, we need the original long form document
    // This implementation assumes the document is stored/cached somewhere
    // In a real implementation, you would need to retrieve the document from storage
    throw new Error('Short form did:peer:4 resolution requires the original long form document to be known');
}

// Helper function to decode variant 4 document
function decodeVariant4Document(encodedDocument: string): any {
    // Remove multibase prefix
    if (!encodedDocument.startsWith(MULTIBASE_BASE58BTC_PREFIX)) {
        throw new Error('Invalid multibase encoding');
    }
    
    const base58Data = encodedDocument.slice(1);
    const bytes = base58Decode(base58Data);
    
    // Remove multicodec prefix
    const { value: multicodec, bytes: remaining } = decodeVarint(bytes);
    if (multicodec !== JSON_MULTICODEC_PREFIX) {
        throw new Error('Invalid multicodec prefix');
    }
    
    // Decode JSON
    const jsonString = new TextDecoder().decode(remaining);
    return JSON.parse(jsonString);
}

// Helper function to contextualize document
function contextualizeDocument(decodedDoc: any, fullDid: string, shortFormDid: string): IDIDDocument {
    const doc = { ...decodedDoc };
    
    // Add id
    doc.id = fullDid;
    
    // Add alsoKnownAs
    if (!doc.alsoKnownAs) {
        doc.alsoKnownAs = [];
    }
    if (!doc.alsoKnownAs.includes(shortFormDid)) {
        doc.alsoKnownAs.push(shortFormDid);
    }
    
    // Set controller for verification methods if not already set
    if (doc.verificationMethod) {
        doc.verificationMethod.forEach((vm: any) => {
            if (!vm.controller) {
                vm.controller = fullDid;
            }
        });
    }
    
    // Handle embedded verification methods in relationships
    ['authentication', 'keyAgreement', 'assertionMethod', 'capabilityInvocation', 'capabilityDelegation'].forEach(rel => {
        if (doc[rel]) {
            doc[rel] = doc[rel].map((item: any) => {
                if (typeof item === 'object' && !item.controller) {
                    return { ...item, controller: fullDid };
                }
                return item;
            });
        }
    });
    
    return doc as IDIDDocument;
}

// Helper function for base58 decoding
function base58Decode(str: string): Uint8Array {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = 0n;
    
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        const index = alphabet.indexOf(char);
        if (index === -1) throw new Error('Invalid base58 character');
        num = num * 58n + BigInt(index);
    }
    
    const hex = num.toString(16);
    const bytes = new Uint8Array(hex.length / 2 + (hex.length % 2));
    
    let byteIndex = 0;
    if (hex.length % 2) {
        bytes[byteIndex++] = parseInt(hex[0], 16);
    }
    
    for (let i = hex.length % 2; i < hex.length; i += 2) {
        bytes[byteIndex++] = parseInt(hex.slice(i, i + 2), 16);
    }
    
    // Handle leading zeros
    let leadingZeros = 0;
    for (let i = 0; i < str.length && str[i] === alphabet[0]; i++) {
        leadingZeros++;
    }
    
    const result = new Uint8Array(leadingZeros + bytes.length);
    result.set(bytes, leadingZeros);
    
    return result;
}

// Helper function to decode varint
function decodeVarint(bytes: Uint8Array): { value: number; bytes: Uint8Array } {
    let value = 0;
    let shift = 0;
    let index = 0;
    
    while (index < bytes.length) {
        const byte = bytes[index++];
        value |= (byte & 0x7F) << shift;
        shift += 7;
        
        if ((byte & 0x80) === 0) {
            break;
        }
    }
    
    return {
        value,
        bytes: bytes.slice(index)
    };
}

// Helper function for base58 encoding (reused from create.ts)
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
