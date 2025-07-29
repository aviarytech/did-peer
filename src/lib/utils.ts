import { Buffer } from 'buffer/index.js';
import { Numalgo2Prefixes, ServiceReplacements } from "./constants.js";
import type { IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "./interfaces.js";

export const assert = (exp: boolean, message: string) => {
    if(!exp) throw new Error(message || 'unknown assertion error');
}

export const base64 = {
	encode: (unencoded: any): string => {
		return Buffer.from(unencoded || '').toString('base64');
	},
	decode: (encoded: any): Uint8Array => {
		return new Uint8Array(Buffer.from(encoded || '', 'base64').buffer);
	}
};

export const utf8 = {
	encode: (unencoded: string): Uint8Array => {
		return new TextEncoder().encode(unencoded)
	},
	decode: (encoded: Uint8Array): string => {
		return new TextDecoder().decode(encoded);
	} 
}

export const base64url = {
	encode: (unencoded: any): string => {
		const encoded = base64.encode(unencoded);
		return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
	},
	decode: (encoded: any): Uint8Array => {
		encoded = encoded.replace(/-/g, '+').replace(/_/g, '/');
		while (encoded.length % 4) encoded += '=';
		return base64.decode(encoded);
	}
};

export const encodeService = (service: IDIDDocumentServiceDescriptor): string => {
    let encoded = JSON.stringify(service)
    Object.values(ServiceReplacements).forEach((v: string, idx: number) => {
        encoded = encoded.replace(Object.keys(ServiceReplacements)[idx], v)
    })
    return `.${Numalgo2Prefixes.Service}${base64url.encode(encoded)}`
}

export const decodeService = (did: string, service: string, metadata: Record<string, any>): IDIDDocumentServiceDescriptor => {
    const val = JSON.parse(utf8.decode(base64url.decode(service)))
    if (val.s) {
        val['serviceEndpoint'] = val.s;
        delete val['s']
    }
    if (typeof val.serviceEndpoint === 'object') {
        if (val.serviceEndpoint.r) {
            val.serviceEndpoint['routingKeys'] = val.serviceEndpoint.r;
            delete val.serviceEndpoint.r
        }
        if (val.serviceEndpoint.a) {
            val.serviceEndpoint['accept'] = val.serviceEndpoint.a;
            delete val.serviceEndpoint.a;
        }
    } else {
        if (val.r) {
            val['routingKeys'] = val.r;
            delete val['r']
        }
        if (val.a) {
            val['accept'] = val.a;
            delete val['a'];
        }
    }
    
    if (val.t) {
        if (val.t === 'dm') {
            val.type = 'DIDCommMessaging'
        } else {
            val.type = val.t;
        }
        delete val['t']
    }
    if (!val.id) {
        if (metadata.index === 0) {
            val.id = `#service`;
        } else {
            val.id = `#service-${metadata.index}`;
        }
        metadata.index++;
    }
    return val;
}

export const isPeerDID = (did: string) => {
    // Updated regex to support variant 4 long form DIDs
    // Original patterns for variants 0, 1, 2
    const variant012Pattern = '^did:peer:(([01](z)([1-9a-km-zA-HJ-NP-Z]*))|(2((.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]*))+(.(S)[0-9a-zA-Z=]*)*)))$';
    
    // Variant 4 pattern - can be short form (did:peer:4z...) or long form (did:peer:4z...:z...)
    const variant4Pattern = '^did:peer:4z[1-9a-km-zA-HJ-NP-Z]*(:[a-zA-Z0-9]+)*$';
    
    return new RegExp(variant012Pattern).test(did) || new RegExp(variant4Pattern).test(did);
}

export const createDIDDocument = (
    did: string,
    authKeys: IDIDDocumentVerificationMethod[],
    encKeys: IDIDDocumentVerificationMethod[],
    services: IDIDDocumentServiceDescriptor[]
) => {
    let contexts = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", {"@base": did}]
    const prefix = "did:peer:";
    const didPeerNumalgo = parseInt(did.slice(prefix.length, prefix.length+1))
    if (didPeerNumalgo < 2) {
        contexts = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
    }
    const auth = authKeys.map(k => k.id);
    const enc = encKeys.map(k => k.id);
    const ver = [...authKeys, ...encKeys].map(k => ({
        id: k.id,
        type: k.type,
        controller: k.controller,
        publicKeyMultibase: k.publicKeyMultibase
    }))
    const doc: any = {
        "id": did,
        assertionMethod: auth,
        authentication: auth,
        verificationMethod: ver,
    }
    if (didPeerNumalgo < 2) {
        doc["capabilityDelegation"] = auth
        doc["capabilityInvocation"] = auth
    }
    if (enc.length > 0) {
        doc['keyAgreement'] = enc;
        if (didPeerNumalgo < 2) {
            contexts.push("https://w3id.org/security/suites/x25519-2020/v1");
        }
    }
    if (services.length > 0) {
        doc['service'] = services
    }
    return {"@context": contexts, ...doc};
}

// Helper function to encode varint
export const encodeVarint = (value: number): Uint8Array => {
    const bytes: number[] = [];
    while (value >= 0x80) {
        bytes.push((value & 0xFF) | 0x80);
        value >>>= 7;
    }
    bytes.push(value & 0xFF);
    return new Uint8Array(bytes);
}

// Helper to decode unsigned varints (LEB128)
export const decodeVarint = (
    bytes: Uint8Array
): { value: number; bytes: Uint8Array } => {
    let value = 0;
    let shift = 0;
    let index = 0;

    while (index < bytes.length) {
        const byte = bytes[index++];
        value |= (byte & 0x7F) << shift;
        shift += 7;

        // If the continuation bit is not set, we're done
        if ((byte & 0x80) === 0) {
            break;
        }
    }

    return {
        value,
        bytes: bytes.slice(index)
    };
};

export const base58Encode = (bytes: Uint8Array): string => {
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
