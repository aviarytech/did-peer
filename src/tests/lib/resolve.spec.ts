import { resolve, resolveNumAlgo0, resolveNumAlgo2 } from "../../lib";
import { describe, it, expect } from "vitest";

describe('resolve', () => {
    it('should resolve peer:did w/ numalgo0', async () => {
        const doc = await resolve('did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH')
        expect(doc).toBeTruthy()
    })
    it('should create peer:did w/ numalgo1', async () => {
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
        expect(doc.authentication![0]).toBe(`${did}#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH`)
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