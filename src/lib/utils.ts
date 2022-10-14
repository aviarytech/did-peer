import { base64 } from "@aviarytech/crypto";
import { Numalgo2Prefixes, ServiceReplacements } from "./constants";
import type { IDIDDocumentServiceDescriptor } from "./interfaces";

export const encodeService = (service: IDIDDocumentServiceDescriptor): string => {
    let encoded = JSON.stringify(service)
    Object.values(ServiceReplacements).forEach((v: string, idx: number) => {
        encoded = encoded.replace(Object.keys(ServiceReplacements)[idx], v)
    })
    return `.${Numalgo2Prefixes.Service}${base64.encode(encoded)}`
}