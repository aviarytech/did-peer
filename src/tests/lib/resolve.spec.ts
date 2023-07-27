import { resolve, resolveNumAlgo0, resolveNumAlgo2 } from "../../lib";
import { describe, it, expect } from "vitest";
import type { IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "$lib/interfaces";
import { expectArrayEquivalence } from "./test-utils";

describe('resolve', () => {
    it('should resolve numalgo0 peer:did from test vectors', async () => {
        const inputDID = require('../fixtures/peerdid-python/numalgo0-did.json')
        const doc = require('../fixtures/peerdid-python/numalgo0-diddoc.json')
        const did = await resolve(inputDID.did)
        expect(did).toStrictEqual(doc)
    })
    it('should resolve numalgo2 peer:did from test vectors', async () => {
        const inputDID = require('../fixtures/peerdid-python/numalgo2-did.json')
        const inputDoc = require('../fixtures/peerdid-python/numalgo2-diddoc.json')
        const resolvedDoc = await resolve(inputDID.did)
        expect(resolvedDoc.id).toEqual(inputDoc.id)
        expectArrayEquivalence(resolvedDoc['@context'] as string[], inputDoc['@context']);
        expectArrayEquivalence(resolvedDoc.verificationMethod!, inputDoc.verificationMethod);
        expectArrayEquivalence(resolvedDoc.keyAgreement as IDIDDocumentVerificationMethod[], inputDoc.keyAgreement);
        expectArrayEquivalence(resolvedDoc.authentication as IDIDDocumentVerificationMethod[], inputDoc.authentication);
        expectArrayEquivalence(resolvedDoc.assertionMethod as IDIDDocumentVerificationMethod[], inputDoc.assertionMethod);
        expectArrayEquivalence(resolvedDoc.capabilityInvocation as IDIDDocumentVerificationMethod[], inputDoc.capabilityInvocation);
        expectArrayEquivalence(resolvedDoc.capabilityDelegation as IDIDDocumentVerificationMethod[], inputDoc.capabilityDelegation);
        expectArrayEquivalence(resolvedDoc.service as IDIDDocumentServiceDescriptor[], inputDoc.service);
    })
    it('should resolve peer:did w/ numalgo0', async () => {
        const doc = await resolve('did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH')
        expect(doc).toBeTruthy()
    })
    it('should resolve peer:did w/ numalgo1', async () => {
        try {
            const doc = await resolve('did:peer:1zQmZMygzYqNwU6Uhmewx5Xepf2VLp5S4HLSwwgf2aiKZuwa')
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('NumAlgo1 not supported')
        }
    })

    it('should create peer:did w/ numalgo2', async () => {
        const doc = await resolve('did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0')
        expect(doc).toBeTruthy()
    })

    it('should resolve peer:did w/ serviceEndpoint object', async () => {
        const doc = await resolve('did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.SeyJpZCI6ICIjZGlkY29tbSIsICJ0IjogImRtIiwgInMiOiB7InVyaSI6ICJodHRwOi8vZXhhbXBsZS5jb20iLCAiciI6IFsiZGlkOmV4YW1wbGU6MTIzIzQ1NiJdLCAiYSI6IFsiZGlkY29tbS92MiJdfX0')
        // @ts-ignore
        expect(doc.service[0].serviceEndpoint.routingKeys).toStrictEqual(["did:example:123#456"]);
        expect(doc).toBeTruthy();
    })

    it('should fail if not peer:did', async () => {
        try {
            const doc = await resolve('did:example:123')
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('did:example:123 is not a valid did:peer')
        }
    })
})

describe('resolveNumAlgo0', () => {
    it('should resolve', async () => {
        const did = 'did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
        const doc = await resolveNumAlgo0(did)
        expect(doc).toBeTruthy()
        expect(doc.id).toBe(did)
        expect(doc.verificationMethod!.length).toBe(1)
        expect(doc.verificationMethod![0].type).toBe('Ed25519VerificationKey2020')
        expect(doc.verificationMethod![0].publicKeyMultibase).toBe('z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH')
        expect(doc.authentication!.length).toBe(1)
        expect(doc.authentication![0]).toBe(`${did}#6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH`)
    })
})

describe('resolveNumAlgo2', () => {
    it('should resolve', async () => {
        const did = 'did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0';
        const doc = await resolveNumAlgo2(did)
        expect(doc).toBeTruthy()
        expect(doc.id).toBe(did)
        expect(doc.verificationMethod!.length).toBe(3)
        expect(doc.authentication!.length).toBe(2)
        expect(doc.keyAgreement!.length).toBe(1)
        expect(doc.service!.length).toBe(1)        
    })
})