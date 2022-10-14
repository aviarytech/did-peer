import { base64url, utf8 } from "@aviarytech/crypto";
import { Numalgo2Prefixes, ServiceReplacements } from "./constants";
import type { IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "./interfaces";

export const encodeService = (service: IDIDDocumentServiceDescriptor): string => {
    let encoded = JSON.stringify(service)
    Object.values(ServiceReplacements).forEach((v: string, idx: number) => {
        encoded = encoded.replace(Object.keys(ServiceReplacements)[idx], v)
    })
    return `.${Numalgo2Prefixes.Service}${base64url.encode(encoded)}`
}

export const decodeService = (did: string, service: string, index: number): IDIDDocumentServiceDescriptor => {
    let val = JSON.parse(utf8.decode(base64url.decode(service)))
    if (val.r) {
        val['routingKeys'] = val.r;
        delete val['r']
    }
    if (val.a) {
        val['accept'] = val.a;
        delete val['a'];
    }
    if (val.t) {
        if (val.t === 'dm') {
            val.type = 'DIDCommMessaging'
            val.id = `${did}#didcomm-${index}`
        } else {
            val.type = val.t;
            val.id = `${did}#service-${index}`
        }
        delete val['t']
    }
    if (val.s) {
        val['serviceEndpoint'] = val.s;
        delete val['s']
    }
    return val;
}

export const createDIDDocument = (
    did: string,
    authKeys: IDIDDocumentVerificationMethod[],
    encKeys: IDIDDocumentVerificationMethod[],
    services: IDIDDocumentServiceDescriptor[]
) => {
    const auth = authKeys.map(k => k.id);
    const enc = encKeys.map(k => k.id);
    const ver = [...authKeys, ...encKeys].map(k => ({
        id: k.id,
        type: k.type,
        controller: k.controller,
        publicKeyMultibase: k.publicKeyMultibase
    }))
    return {
        "@context": "https://w3id.org/did/v1",
        "id": did,
        authentication: auth,
        keyAgreement: enc,
        verificationMethod: ver,
        service: services
    }
}