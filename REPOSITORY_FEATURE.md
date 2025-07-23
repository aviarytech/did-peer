# DID Repository Feature for Short Form Resolution

## Overview

This feature adds abstract repository support for resolving short form peer DID variant 4 identifiers. Short form DIDs are compact representations that require the original long form DID document to be stored and retrievable for resolution.

## Key Components

### 1. IDIDRepository Interface

An abstract interface that can be implemented with different storage backends:

```typescript
interface IDIDRepository {
  store(shortFormDid: string, longFormDid: string): Promise<void>;
  retrieve(shortFormDid: string): Promise<string | null>;
  exists(shortFormDid: string): Promise<boolean>;
}
```

### 2. InMemoryDIDRepository

A concrete implementation using in-memory storage:

```typescript
const repository = new InMemoryDIDRepository();
```

### 3. Updated Resolve Functions

The `resolve` function now accepts an optional repository parameter:

```typescript
const doc = await resolve(shortFormDid, repository);
```

## Usage Examples

### Basic Usage

```typescript
import { 
  createNumAlgo4, 
  resolve, 
  InMemoryDIDRepository, 
  storeLongFormDid 
} from '@aviarytech/did-peer';

// 1. Create repository
const repository = new InMemoryDIDRepository();

// 2. Create a DID
const longFormDid = await createNumAlgo4([authKey], [encKey]);

// 3. Store in repository
const shortFormDid = await storeLongFormDid(longFormDid, repository);

// 4. Resolve short form (requires repository)
const doc = await resolve(shortFormDid, repository);

// 5. Resolve long form (no repository needed)
const doc2 = await resolve(longFormDid);
```

### Custom Repository Implementation

```typescript
class DatabaseDIDRepository implements IDIDRepository {
  async store(shortFormDid: string, longFormDid: string): Promise<void> {
    // Store in your database
    await db.collection('dids').insertOne({ 
      shortForm: shortFormDid, 
      longForm: longFormDid 
    });
  }

  async retrieve(shortFormDid: string): Promise<string | null> {
    // Retrieve from your database
    const result = await db.collection('dids').findOne({ 
      shortForm: shortFormDid 
    });
    return result?.longForm || null;
  }

  async exists(shortFormDid: string): Promise<boolean> {
    const count = await db.collection('dids').countDocuments({ 
      shortForm: shortFormDid 
    });
    return count > 0;
  }
}
```

## Key Features

1. **Backward Compatibility**: Existing code continues to work without changes
2. **Flexible Storage**: Repository interface can be implemented with any storage backend
3. **Proper Error Handling**: Clear error messages for missing repositories or DIDs
4. **Utility Functions**: Helper functions for extracting short forms and storing DIDs
5. **Type Safety**: Full TypeScript support with proper interfaces

## DID Format Differences

- **Long Form**: `did:peer:4zHash:zDocument` (self-contained, no repository needed)
- **Short Form**: `did:peer:4zHash` (requires repository lookup)

When resolving:
- Long form documents have `alsoKnownAs: [shortFormDid]`
- Short form documents have `alsoKnownAs: [longFormDid]`

## Error Scenarios

1. **No Repository Provided**: Throws error when trying to resolve short form without repository
2. **DID Not Found**: Throws error when short form DID doesn't exist in repository
3. **Invalid Format**: Throws error for malformed DID strings

## Testing

Comprehensive test suite covers:
- Repository storage and retrieval
- Short form extraction utilities
- Integration with resolve functions
- Error conditions and edge cases

Run tests with:
```bash
npm test src/tests/lib/repository.spec.ts
```
