import type { IDIDRepository } from "./interfaces.js";

/**
 * Simple in-memory implementation of IDIDRepository.
 * Suitable for testing and development, but data is lost when the process exits.
 */
export class InMemoryDIDRepository implements IDIDRepository {
    private storage: Map<string, string> = new Map();

    async store(shortFormDid: string, longFormDid: string): Promise<void> {
        this.storage.set(shortFormDid, longFormDid);
    }

    async retrieve(shortFormDid: string): Promise<string | null> {
        return this.storage.get(shortFormDid) || null;
    }

    async exists(shortFormDid: string): Promise<boolean> {
        return this.storage.has(shortFormDid);
    }

    /**
     * Clear all stored DIDs (useful for testing)
     */
    clear(): void {
        this.storage.clear();
    }

    /**
     * Get the number of stored DIDs
     */
    size(): number {
        return this.storage.size;
    }
}

/**
 * Helper function to extract the short form DID from a long form variant 4 DID
 * @param longFormDid The long form DID (did:peer:4zHash:zDocument)
 * @returns The short form DID (did:peer:4zHash)
 */
export function extractShortFormDid(longFormDid: string): string {
    const parts = longFormDid.split(':');
    if (parts.length !== 4 || parts[0] !== 'did' || parts[1] !== 'peer' || !parts[2].startsWith('4z')) {
        throw new Error('Invalid long form did:peer:4 format');
    }
    return `did:peer:${parts[2]}`;
}

/**
 * Convenience function to store a long form DID in a repository using its short form as the key
 * @param longFormDid The long form DID to store
 * @param repository The repository to store it in
 */
export async function storeLongFormDid(longFormDid: string, repository: IDIDRepository): Promise<string> {
    const shortFormDid = extractShortFormDid(longFormDid);
    await repository.store(shortFormDid, longFormDid);
    return shortFormDid;
}
