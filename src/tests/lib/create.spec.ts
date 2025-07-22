import { create, createNumAlgo0, createNumAlgo2, createNumAlgo4 } from '../../lib';
import { describe, expect, it } from 'vitest';
import { expectArrayEquivalence } from './test-utils';
import { base64, utf8 } from '$lib/utils';

const ed25519Key = require('../fixtures/peerdid-python/ed25519-key.json')
const x25519Key = require('../fixtures/peerdid-python/x25519-key.json')

// Test key for variant 4
const multikeyEd25519 = {
    type: 'Multikey',
    publicKeyMultibase: 'z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
}

const multikeyX25519 = {
    type: 'Multikey', 
    publicKeyMultibase: 'z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
}

describe('create', () => {
    it('should create numalgo0 peer:did from test vectors', async () => {
        const inputs = require('../fixtures/peerdid-python/numalgo0-inputs.json')
        const inputDID = require('../fixtures/peerdid-python/numalgo0-did.json')
        const did = await create(0, inputs.signing_keys)
        expect(did).toBe(inputDID.did)
    })

    it('should create numalgo2 peer:did from test vectors', async () => {
        const inputs = require('../fixtures/peerdid-python/numalgo2-inputs.json')
        const inputDID = require('../fixtures/peerdid-python/numalgo2-did.json')
        const did = await create(2, inputs.signing_keys, inputs.encryption_keys, inputs.service)
        expectArrayEquivalence(did.split('.'), inputDID.did.split('.'))
    })
    it('should create peer:did w/ numalgo0', async () => {
        const did = await create(0, [ed25519Key])
        expect(did).toBeTruthy()
    })
    it('should create peer:did w/ numalgo1', async () => {
        try {
            const did = await create(1, [ed25519Key])
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('NumAlgo1 not supported')
        }
    })

    it('should create peer:did w/ numalgo2', async () => {
        const did = await create(2, [ed25519Key])
        expect(did).toBeTruthy()
    })

    it('should create peer:did w/ numalgo4', async () => {
        const did = await create(4, [multikeyEd25519])
        expect(did).toBeTruthy()
        expect(did.startsWith('did:peer:4')).toBe(true)
        // Variant 4 long form DID has exactly 4 parts (did:peer:hash:document)
        const parts = did.split(':')
        expect(parts.length).toBe(4)
        expect(parts[2].startsWith('4z')).toBe(true) // hash part starts with 4z
        expect(parts[3].startsWith('z')).toBe(true) // document part starts with z
    })

    it('should create peer:did w/ numalgo4 with encryption key', async () => {
        const did = await create(4, [multikeyEd25519], [multikeyX25519])
        expect(did).toBeTruthy()
        expect(did.startsWith('did:peer:4')).toBe(true)
    })

    it('should create peer:did w/ numalgo4 with service', async () => {
        const service = [{
            'id': '#didcomm',
            'type': 'DIDCommMessaging',
            'serviceEndpoint': 'http://example.com',
            'routingKeys': ['did:example:123#456'],
            'accept': ['didcomm/v2']
        }]
        const did = await create(4, [multikeyEd25519], undefined, service)
        expect(did).toBeTruthy()
        expect(did.startsWith('did:peer:4')).toBe(true)
    })
})

describe('createNumAlgo0', () => {
    it('should create valid peer:did with NumAlgo0', async () => {
        const did = await createNumAlgo0(ed25519Key);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('0')
        expect(did[10]).toBe('z')
    })
    it('should require Ed25519VerificationKey2020', async () => {
        try {
            const did = await createNumAlgo0(x25519Key);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be Ed25519VerificationKey2020 or Multikey')
        }
    })
})

describe('createNumAlgo2', () => {
    it('should create valid peer:did with NumAlgo2 no encryption', async () => {
        const did = await createNumAlgo2([ed25519Key]);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('2')
        expect(did[10]).toBe('.')
        expect(did[11]).toBe('V')
    })
    it('should require auth key type Ed25519VerificationKey2020', async () => {
        try {
            const did = await createNumAlgo2([x25519Key]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be Ed25519VerificationKey2020 or Multikey')
        }
    })
    it('should create valid peer:did with NumAlgo2 with encryption', async () => {
        const did = await createNumAlgo2([ed25519Key], [x25519Key]);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('2')
        expect(did[10]).toBe('.')
        expect(did[11]).toBe('V')
        expect(did).toContain(ed25519Key.publicKeyMultibase)
        const encKeyLocation = did.indexOf('.E')
        expect(did[encKeyLocation]).toBe('.')
        expect(did[encKeyLocation + 1]).toBe('E')
        expect(did).toContain(x25519Key.publicKeyMultibase)
    })
    it('should require encryption key type X25519KeyAgreementKey2020', async () => {
        try {
            const did = await createNumAlgo2([ed25519Key], [ed25519Key]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be X25519KeyAgreementKey2020 or Multikey')
        }
    })
    it('should require encryption key publicKeyMultibase property', async () => {
        try {
            const { publicKeyMultibase, ...rest } = x25519Key;
            const did = await createNumAlgo2([ed25519Key], [rest]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod must have publicKeyMultibase property')
        }
    })
    it('should create valid peer:did with NumAlgo2 with service', async () => {
        const service = [{
            'id': '#didcomm',
            'type': 'DIDCommMessaging',
            'serviceEndpoint' :'http://example.com',
            'routingKeys': ['did:example:123#456'],
            'accept': ['didcomm/v2']
        }]
        const did = await createNumAlgo2([ed25519Key], undefined, service);
        expect(did).toBeTruthy()
        const segments = did.split('.');
        const idx = segments.findIndex((s) => s.length > 1 && s[0] === 'S')
        expect(segments[idx][0]).toBe('S')
        const basedService = segments[idx].slice(1)
        const serv = JSON.parse(utf8.decode(base64.decode(basedService)))
        expect(serv['id']).toBe('#didcomm')
        expect(serv['t']).toBe('dm')
        expect(serv['s']).toBe('http://example.com')
        expect(serv['r']).toStrictEqual(['did:example:123#456'])
        expect(serv['a']).toStrictEqual(['didcomm/v2'])
    })

    it('should create valid peer:did with NumAlgo2 with service with serviceEndpoint object', async () => {
        const service = [{
            'id': '#didcomm',
            'type': 'DIDCommMessaging',
            'serviceEndpoint': {
                'uri': 'http://example.com',
                'routingKeys': ['did:example:123#456'],
                'accept': ['didcomm/v2']
            }
        }]
        const did = await createNumAlgo2([ed25519Key], undefined, service);
        expect(did).toBeTruthy()
        const segments = did.split('.');
        const idx = segments.findIndex((s) => s.length > 1 && s[0] === 'S')
        expect(segments[idx][0]).toBe('S')
        const basedService = segments[idx].slice(1)
        const serv = JSON.parse(utf8.decode(base64.decode(basedService)))
        expect(serv['id']).toBe('#didcomm')
        expect(serv['t']).toBe('dm')
        expect(serv['s']).toStrictEqual({'uri':'http://example.com', 'r': ['did:example:123#456'], 'a': ['didcomm/v2']})
    })
    
    it('should require encryption key type X25519KeyAgreementKey2020', async () => {
        try {
            const did = await createNumAlgo2([ed25519Key], [ed25519Key]);
            expect(true).toBeFalsy()
        } catch (e: any) {
            expect(e.message).toBe('verificationMethod type must be X25519KeyAgreementKey2020 or Multikey')
        }
    })
})

describe('createNumAlgo4', () => {
    it('should create valid peer:did with NumAlgo4', async () => {
        const did = await createNumAlgo4([multikeyEd25519]);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('4')
        expect(did.startsWith('did:peer:4z')).toBe(true)
        // Verify it's a long form DID with hash and document (4 parts total)
        const parts = did.split(':')
        expect(parts.length).toBe(4)
        expect(parts[2].startsWith('4z')).toBe(true)
        expect(parts[3].startsWith('z')).toBe(true)
    })

    it('should create valid peer:did with NumAlgo4 with encryption key', async () => {
        const did = await createNumAlgo4([multikeyEd25519], [multikeyX25519]);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('4')
        // Should contain encoded document
        expect(did).toContain(':z')
    })

    it('should create consistent DIDs for same input', async () => {
        const did1 = await createNumAlgo4([multikeyEd25519]);
        const did2 = await createNumAlgo4([multikeyEd25519]);
        expect(did1).toBe(did2)
    })

    it('should create valid peer:did with NumAlgo4 with service', async () => {
        const service = [{
            'id': '#didcomm',
            'type': 'DIDCommMessaging',
            'serviceEndpoint': 'http://example.com'
        }]
        const did = await createNumAlgo4([multikeyEd25519], undefined, service);
        expect(did).toBeTruthy()
        expect(did[9]).toBe('4')
    })

    it('should accept Multikey type for authentication', async () => {
        const did = await createNumAlgo4([multikeyEd25519]);
        expect(did).toBeTruthy()
    })

    it('should accept Multikey type for encryption', async () => {
        const did = await createNumAlgo4([multikeyEd25519], [multikeyX25519]);
        expect(did).toBeTruthy()
    })
})
