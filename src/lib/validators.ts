import { assert } from "vitest";
import type { IDIDDocumentVerificationMethod } from "./interfaces";

export const validateAuthentication = (verificationMethod: IDIDDocumentVerificationMethod) => {
    assert(verificationMethod.type === 'Ed25519VerificationKey2020', 'verificationMethod type must be Ed25519VerificationKey2020')
    assert(verificationMethod.publicKeyMultibase, 'verificationMethod must have publicKeyMultibase property')
}

export const validateEncryption = (verificationMethod: IDIDDocumentVerificationMethod) => {
    assert(verificationMethod.type === 'X25519KeyAgreementKey2020', 'verificationMethod type must be X25519KeyAgreementKey2020')
    assert(verificationMethod.publicKeyMultibase, 'verificationMethod must have publicKeyMultibase property')
}