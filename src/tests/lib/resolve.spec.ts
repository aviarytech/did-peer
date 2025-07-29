import { resolve, resolveNumAlgo0, resolveNumAlgo2, resolveNumAlgo4, resolveLongFormNumAlgo4 } from "../../lib";
import { describe, it, expect } from "vitest";
import type { IDIDDocumentServiceDescriptor, IDIDDocumentVerificationMethod } from "$lib/interfaces";
import { expectArrayEquivalence } from "./test-utils";
import { createNumAlgo4 } from "../../lib";

// Test keys for variant 4
const multikeyEd25519 = {
    type: 'Multikey',
    publicKeyMultibase: 'z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
}

const multikeyX25519 = {
    type: 'Multikey', 
    publicKeyMultibase: 'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
}

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
        expect(resolvedDoc.capabilityInvocation).toEqual(undefined);
        expect(resolvedDoc.capabilityDelegation).toEqual(undefined);
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

    it('should resolve peer:did w/ numalgo4 long form', async () => {
        // Create a variant 4 DID and then resolve it
        const did = await createNumAlgo4([multikeyEd25519])
        const doc = await resolve(did)
        expect(doc).toBeTruthy()
        expect(doc.id).toBe(did)
        expect(doc.verificationMethod).toBeTruthy()
        expect(doc.verificationMethod!.length).toBe(1)
        expect(doc.authentication).toBeTruthy()
    })

    it('should resolve peer:did w/ numalgo4 with encryption key', async () => {
        const did = await createNumAlgo4([multikeyEd25519], [multikeyX25519])
        const doc = await resolve(did)
        expect(doc).toBeTruthy()
        expect(doc.id).toBe(did)
        expect(doc.verificationMethod!.length).toBe(2)
        expect(doc.authentication).toBeTruthy()
        expect(doc.keyAgreement).toBeTruthy()
    })

    it('should resolve peer:did w/ numalgo4 with service', async () => {
        const service = [{
            'id': '#didcomm',
            'type': 'DIDCommMessaging',
            'serviceEndpoint': 'http://example.com'
        }]
        const did = await createNumAlgo4([multikeyEd25519], undefined, service)
        const doc = await resolve(did)
        expect(doc).toBeTruthy()
        expect(doc.service).toBeTruthy()
        expect(doc.service!.length).toBe(1)
        expect(doc.service![0].type).toBe('DIDCommMessaging')
    })

    it('should resolve the example long form numalgo4 DID from the spec', async () => {
        // Example DID from the Peer DID spec (variant 4 – long-form)
        const exampleDid = 'did:peer:4zQmd8CpeFPci817KDsbSAKWcXAE2mjvCQSasRewvbSF54Bd:z2M1k7h4psgp4CmJcnQn2Ljp7Pz7ktsd7oBhMU3dWY5s4fhFNj17qcRTQ427C7QHNT6cQ7T3XfRh35Q2GhaNFZmWHVFq4vL7F8nm36PA9Y96DvdrUiRUaiCuXnBFrn1o7mxFZAx14JL4t8vUWpuDPwQuddVo1T8myRiVH7wdxuoYbsva5x6idEpCQydJdFjiHGCpNc2UtjzPQ8awSXkctGCnBmgkhrj5gto3D4i3EREXYq4Z8r2cWGBr2UzbSmnxW2BuYddFo9Yfm6mKjtJyLpF74ytqrF5xtf84MnGFg1hMBmh1xVx1JwjZ2BeMJs7mNS8DTZhKC7KH38EgqDtUZzfjhpjmmUfkXg2KFEA3EGbbVm1DPqQXayPYKAsYPS9AyKkcQ3fzWafLPP93UfNhtUPL8JW5pMcSV3P8v6j3vPXqnnGknNyBprD6YGUVtgLiAqDBDUF3LSxFQJCVYYtghMTv8WuSw9h1a1SRFrDQLGHE4UrkgoRvwaGWr64aM87T1eVGkP5Dt4L1AbboeK2ceLArPScrdYGTpi3BpTkLwZCdjdiFSfTy9okL1YNRARqUf2wm8DvkVGUU7u5nQA3ZMaXWJAewk6k1YUxKd7LvofGUK4YEDtoxN5vb6r1Q2godrGqaPkjfL3RoYPpDYymf9XhcgG8Kx3DZaA6cyTs24t45KxYAfeCw4wqUpCH9HbpD78TbEUr9PPAsJgXBvBj2VVsxnr7FKbK4KykGcg1W8M1JPz21Z4Y72LWgGQCmixovrkHktcTX1uNHjAvKBqVD5C7XmVfHgXCHj7djCh3vzLNuVLtEED8J1hhqsB1oCBGiuh3xXr7fZ9wUjJCQ1HYHqxLJKdYKtoCiPmgKM7etVftXkmTFETZmpM19aRyih3bao76LdpQtbw636r7a3qt8v4WfxsXJetSL8c7t24SqQBcAY89FBsbEnFNrQCMK3JEseKHVaU388ctvRD45uQfe5GndFxthj4iSDomk4uRFd1uRbywoP1tRuabHTDX42UxPjz';

        const doc = await resolve(exampleDid);

        expect(doc).toBeTruthy();
        expect(doc.id).toBe(exampleDid);
        // Should have at least one verification method and authentication entry
        expect(doc.verificationMethod && doc.verificationMethod.length).toBeGreaterThan(0);
        expect(doc.authentication && doc.authentication.length).toBeGreaterThan(0);
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

describe('resolveNumAlgo4', () => {
    it('should resolve long form variant 4 DID', async () => {
        const did = await createNumAlgo4([multikeyEd25519]);
        const doc = await resolveNumAlgo4(did)
        expect(doc).toBeTruthy()
        expect(doc.id).toBe(did)
        expect(doc.verificationMethod!.length).toBe(1)
        expect(doc.authentication!.length).toBe(1)
    })

    it('should resolve variant 4 DID with encryption key', async () => {
        const did = await createNumAlgo4([multikeyEd25519], [multikeyX25519]);
        const doc = await resolveNumAlgo4(did)
        expect(doc).toBeTruthy()
        expect(doc.verificationMethod!.length).toBe(2)
        expect(doc.authentication!.length).toBe(1)
        expect(doc.keyAgreement!.length).toBe(1)
    })

    it('should include alsoKnownAs with short form', async () => {
        const did = await createNumAlgo4([multikeyEd25519]);
        const doc = await resolveNumAlgo4(did)
        expect(doc.alsoKnownAs).toBeTruthy()
        expect(doc.alsoKnownAs!.length).toBeGreaterThan(0)
        // Should contain the short form DID
        const shortForm = doc.alsoKnownAs!.find(aka => aka.startsWith('did:peer:4z'))
        expect(shortForm).toBeTruthy()
    })

    it('should throw error for short form DID without repository', async () => {
        try {
            // Create a short form DID by extracting hash part
            const longFormDid = await createNumAlgo4([multikeyEd25519]);
            const parts = longFormDid.split(':')
            const hashPart = parts[2] // The hash part includes the '4z' prefix
            const shortFormDid = `did:peer:${hashPart}`
            
            await resolveNumAlgo4(shortFormDid)
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toContain('Short form did:peer:4 resolution requires a DID repository')
        }
    })
})

describe('resolveLongFormNumAlgo4', () => {
    it('should resolve long form variant 4 DID', async () => {
        const did = await createNumAlgo4([multikeyEd25519]);
        const doc = await resolveLongFormNumAlgo4(did)
        expect(doc).toBeTruthy()
        expect(doc.id).toBe(did)
    })

    it('should verify hash correctly', async () => {
        const did = await createNumAlgo4([multikeyEd25519]);
        const doc = await resolveLongFormNumAlgo4(did)
        expect(doc).toBeTruthy()
        // If no error is thrown, hash verification passed
    })

    it('should throw error for invalid format', async () => {
        try {
            await resolveLongFormNumAlgo4('did:peer:4invalidformat')
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toContain('Invalid')
        }
    })
})
