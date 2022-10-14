import { Ed25519VerificationKey2020, X25519KeyAgreementKey2020 } from "@aviarytech/crypto";
import { assert } from "vitest";
import { Numalgo2Prefixes } from "./constants";
import type { IDIDDocument, IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "./interfaces";
import { createDIDDocument, decodeService } from "./utils";

export const resolve = async (did: string): Promise<IDIDDocument> => {
    assert(did.slice(0,9) === 'did:peer:', `${did} is not a valid did:peer`)
    switch(did.slice(9,10)) {
        case '0':
            return resolveNumAlgo0(did);
        case '1':
            return resolveNumAlgo1(did);
        case '2':
            return resolveNumAlgo2(did);
        default:
            throw new Error(`numalgo ${did.slice(9,10)} not recognized`);
    }
}

export const resolveNumAlgo0 = async (did: string): Promise<IDIDDocument> => {
    const multibaseKey = did.slice(10)
    const key = new Ed25519VerificationKey2020(`${did}#${multibaseKey}`, did, multibaseKey)
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
    let serviceIndex = 0;
    delete keys[0];
    keys.forEach(k => {
        switch (k.slice(0,1)) {
            case Numalgo2Prefixes.Authentication:
                authKeys.push(new Ed25519VerificationKey2020(`${did}#${k.slice(1)}`, did, k.slice(1)))
                break;
            case Numalgo2Prefixes.KeyAgreement:
                encKeys.push(new X25519KeyAgreementKey2020(`${did}#${k.slice(1)}`, did, k.slice(1)))
                break;
            case Numalgo2Prefixes.Service:
                services.push(decodeService(did, k.slice(1), serviceIndex))
                serviceIndex++;
                break;
        }
    })
    return createDIDDocument(did, authKeys, encKeys, services)
}