import { base64 } from "@aviarytech/crypto";
import { Numalgo2Prefixes, ServiceReplacements } from "./constants";
import type { IDIDDocumentServiceDescriptor } from "./interfaces";

export const encodeService = (service: IDIDDocumentServiceDescriptor): string => {
    let encoded = JSON.stringify(service)
    Object.keys(ServiceReplacements).forEach((k: string) => encoded.replace(k, ServiceReplacements[k]] ))
    return `.${Numalgo2Prefixes.Service}${base64.encode(encoded)}`
}