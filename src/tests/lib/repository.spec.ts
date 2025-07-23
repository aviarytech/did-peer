import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryDIDRepository, extractShortFormDid, storeLongFormDid } from '../../lib/repository.js'
import { createNumAlgo4 } from '../../lib/create.js'
import { resolve } from '../../lib/resolve.js'

const multikeyEd25519 = {
    id: '#key-1',
    type: 'Multikey',
    controller: '',
    publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
}

describe('InMemoryDIDRepository', () => {
    let repository: InMemoryDIDRepository

    beforeEach(() => {
        repository = new InMemoryDIDRepository()
    })

    it('should store and retrieve a DID', async () => {
        const shortForm = 'did:peer:4z123'
        const longForm = 'did:peer:4z123:zDocument'
        
        await repository.store(shortForm, longForm)
        const retrieved = await repository.retrieve(shortForm)
        
        expect(retrieved).toBe(longForm)
    })

    it('should return null for non-existent DID', async () => {
        const retrieved = await repository.retrieve('did:peer:4z999')
        expect(retrieved).toBeNull()
    })

    it('should check if DID exists', async () => {
        const shortForm = 'did:peer:4z123'
        const longForm = 'did:peer:4z123:zDocument'
        
        expect(await repository.exists(shortForm)).toBe(false)
        
        await repository.store(shortForm, longForm)
        expect(await repository.exists(shortForm)).toBe(true)
    })

    it('should clear all stored DIDs', async () => {
        await repository.store('did:peer:4z123', 'did:peer:4z123:zDoc1')
        await repository.store('did:peer:4z456', 'did:peer:4z456:zDoc2')
        
        expect(repository.size()).toBe(2)
        repository.clear()
        expect(repository.size()).toBe(0)
    })
})

describe('extractShortFormDid', () => {
    it('should extract short form from long form DID', async () => {
        const longFormDid = await createNumAlgo4([multikeyEd25519])
        const shortFormDid = extractShortFormDid(longFormDid)
        
        const parts = longFormDid.split(':')
        const expectedShortForm = `did:peer:${parts[2]}`
        
        expect(shortFormDid).toBe(expectedShortForm)
    })

    it('should throw error for invalid DID format', () => {
        expect(() => extractShortFormDid('invalid:did')).toThrow('Invalid long form did:peer:4 format')
        expect(() => extractShortFormDid('did:peer:2z123')).toThrow('Invalid long form did:peer:4 format')
        expect(() => extractShortFormDid('did:peer:4z123')).toThrow('Invalid long form did:peer:4 format')
    })
})

describe('storeLongFormDid', () => {
    let repository: InMemoryDIDRepository

    beforeEach(() => {
        repository = new InMemoryDIDRepository()
    })

    it('should store long form DID and return short form', async () => {
        const longFormDid = await createNumAlgo4([multikeyEd25519])
        const shortFormDid = await storeLongFormDid(longFormDid, repository)
        
        expect(shortFormDid).toBeTruthy()
        expect(shortFormDid.startsWith('did:peer:4z')).toBe(true)
        
        const retrieved = await repository.retrieve(shortFormDid)
        expect(retrieved).toBe(longFormDid)
    })
})

describe('Integration: Repository with resolve', () => {
    let repository: InMemoryDIDRepository

    beforeEach(() => {
        repository = new InMemoryDIDRepository()
    })

    it('should resolve short form DID using repository', async () => {
        // Create and store a long form DID
        const longFormDid = await createNumAlgo4([multikeyEd25519])
        const shortFormDid = await storeLongFormDid(longFormDid, repository)
        
        // Resolve the short form DID
        const doc = await resolve(shortFormDid, repository)
        
        expect(doc).toBeTruthy()
        expect(doc.id).toBe(shortFormDid)
        expect(doc.alsoKnownAs).toContain(longFormDid)
        expect(doc.verificationMethod).toBeTruthy()
        expect(doc.authentication).toBeTruthy()
    })

    it('should throw error when resolving short form without repository', async () => {
        const longFormDid = await createNumAlgo4([multikeyEd25519])
        const shortFormDid = extractShortFormDid(longFormDid)
        
        try {
            await resolve(shortFormDid)
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toContain('Short form did:peer:4 resolution requires a DID repository')
        }
    })

    it('should throw error when DID not found in repository', async () => {
        // Use a valid format but unknown DID
        const longFormDid = await createNumAlgo4([multikeyEd25519])
        const shortFormDid = extractShortFormDid(longFormDid)
        // Don't store it in the repository
        
        try {
            await resolve(shortFormDid, repository)
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toContain('not found in repository')
        }
    })
})
