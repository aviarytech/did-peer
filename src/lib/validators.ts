import type { IDIDDocumentVerificationMethod } from "./interfaces.js";
import { assert } from "./utils.js";

export const validateAuthentication = (verificationMethod: IDIDDocumentVerificationMethod) => {
    assert(['Ed25519VerificationKey2020', 'Multikey'].includes(verificationMethod.type), 'verificationMethod type must be Ed25519VerificationKey2020 or Multikey')
    assert(verificationMethod.publicKeyMultibase, 'verificationMethod must have publicKeyMultibase property')
}

export const validateEncryption = (verificationMethod: IDIDDocumentVerificationMethod) => {
    assert(['X25519KeyAgreementKey2020', 'Multikey'].includes(verificationMethod.type), 'verificationMethod type must be X25519KeyAgreementKey2020 or Multikey')
    assert(verificationMethod.publicKeyMultibase, 'verificationMethod must have publicKeyMultibase property')
}