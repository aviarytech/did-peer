import { Buffer } from 'buffer/index.js';
import { Numalgo2Prefixes, ServiceReplacements } from "./constants.js";
import type { IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "./interfaces.js";

export const assert = (exp: boolean, message: string) => {
    if(!Boolean(exp)) throw new Error(message || 'unknown assertion error');
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
    return new RegExp('^did:peer:(([01](z)([1-9a-km-zA-HJ-NP-Z]*))|(2((\.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]*))+(\.(S)[0-9a-zA-Z=]*)*)))$').test(did)
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
    let doc: any = {
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
