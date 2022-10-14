import { create, createNumAlgo0, createNumAlgo2 } from '$lib';
import { Ed25519VerificationKey2020, X25519KeyAgreementKey2020 } from '@aviarytech/crypto';
import { describe, expect, it } from 'vitest';

describe('create', () => {
    it('should create peer:did w/ numalgo0', async () => {
        const signingKey = await Ed25519VerificationKey2020.generate();
        const did = await create(0, [signingKey])
        expect(did).toBeTruthy()
    })
    it('should create peer:did w/ numalgo1', async () => {
        const signingKey = await Ed25519VerificationKey2020.generate();
        const did = await create(1, [signingKey])
        expect(did).toBeTruthy()
    })

    it('should create peer:did w/ numalgo2', async () => {
        const signingKey = await Ed25519VerificationKey2020.generate();
        const did = await create(2, [signingKey])
        expect(did).toBeTruthy()
    })
})

describe('createNumAlgo0', () => {
    it('should create valid peer:did with NumAlgo0', async () => {
        const key = await Ed25519VerificationKey2020.generate();
        const did = await createNumAlgo0(key);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('0')
        expect(did[10]).toBe('z')
    })
    it('should require Ed25519VerificationKey2020', async () => {
        const key = await X25519KeyAgreementKey2020.generate();
        try {
            const did = await createNumAlgo0(key);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be Ed25519VerificationKey2020')
        }
    })
    it('should require publicKeyMultibase property', async () => {
        let key = await Ed25519VerificationKey2020.generate();
        try {
            const { publicKeyMultibase, ...rest } = key;
            const did = await createNumAlgo0(rest);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod must have publicKeyMultibase property')
        }
    })
})

describe('createNumAlgo2', () => {
    it('should create valid peer:did with NumAlgo2 no encryption', async () => {
        const authKey = await Ed25519VerificationKey2020.generate();
        const did = await createNumAlgo2([authKey]);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('2')
        expect(did[10]).toBe('.')
        expect(did[11]).toBe('V')
    })
    it('should require auth key type Ed25519VerificationKey2020', async () => {
        const key = await X25519KeyAgreementKey2020.generate();
        try {
            const did = await createNumAlgo2([key]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be Ed25519VerificationKey2020')
        }
    })
    it('should require auth key publicKeyMultibase property', async () => {
        let key = await Ed25519VerificationKey2020.generate();
        try {
            const { publicKeyMultibase, ...rest } = key;
            const did = await createNumAlgo2([rest]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod must have publicKeyMultibase property')
        }
    })
    it('should create valid peer:did with NumAlgo2 with encryption', async () => {
        const authKey = await Ed25519VerificationKey2020.generate();
        const encKey = await X25519KeyAgreementKey2020.generate();
        const did = await createNumAlgo2([authKey], [encKey]);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('2')
        expect(did[10]).toBe('.')
        expect(did[11]).toBe('V')
        expect(did).toContain(authKey.publicKeyMultibase)
        const encKeyLocation = did.indexOf('.E')
        expect(did[encKeyLocation]).toBe('.')
        expect(did[encKeyLocation + 1]).toBe('E')
        expect(did).toContain(encKey.publicKeyMultibase)
    })
    it('should require encryption key type X25519KeyAgreementKey2020', async () => {
        const key = await Ed25519VerificationKey2020.generate();
        try {
            const did = await createNumAlgo2([key], [key]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be X25519KeyAgreementKey2020')
        }
    })
    it('should require encryption key publicKeyMultibase property', async () => {
        let authKey = await Ed25519VerificationKey2020.generate();
        let encKey = await X25519KeyAgreementKey2020.generate();
        try {
            const { publicKeyMultibase, ...rest } = encKey;
            const did = await createNumAlgo2([authKey], [rest]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod must have publicKeyMultibase property')
        }
    })
    it('should create valid peer:did with NumAlgo2 with service', async () => {
        const authKey = await Ed25519VerificationKey2020.generate();
        const service = {
            'id': '#didcomm',
            'type': 'DIDCommMessaging',
            'serviceEndpoint' :'http://example.com'
        }
        const did = await createNumAlgo2([authKey], undefined, service);
        expect(did).toBeTruthy()
        const serviceLocation = did.indexOf('.S')
        expect(did[serviceLocation]).toBe('.')
        expect(did[serviceLocation + 1]).toBe('S')
        console.log(did.slice(serviceLocation))
    })
    it('should require encryption key type X25519KeyAgreementKey2020', async () => {
        const key = await Ed25519VerificationKey2020.generate();
        try {
            const did = await createNumAlgo2([key], [key]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be X25519KeyAgreementKey2020')
        }
    })
    it('should require encryption key publicKeyMultibase property', async () => {
        let authKey = await Ed25519VerificationKey2020.generate();
        let encKey = await X25519KeyAgreementKey2020.generate();
        try {
            const { publicKeyMultibase, ...rest } = encKey;
            const did = await createNumAlgo2([authKey], [rest]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod must have publicKeyMultibase property')
        }
    })
})