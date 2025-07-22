# Peer DID Method Variant 4 Implementation

## Overview
This library has been updated to support **Peer DID Method Variant 4** according to the latest specification from the Identity Foundation. Variant 4 introduces a statically resolvable DID method that supports both short form and long form representations.

## What's New

### Variant 4 Features
- **Long Form DIDs**: Self-contained DIDs that include the entire DID document encoded in the DID itself
- **Short Form DIDs**: Compact representation using only the hash of the document
- **Static Resolution**: No need for external resolution methods or registries
- **Multikey Support**: Uses the modern `Multikey` verification method type
- **Transform Processing**: Implements proper multicodec and multihash encoding

### DID Format
Variant 4 DIDs follow this structure:
- **Long Form**: `did:peer:4{hash}:{document}`
- **Short Form**: `did:peer:4{hash}`

Where:
- `{hash}` is a SHA-256 multihash (multibase-encoded with base58btc) of the encoded document
- `{document}` is the JSON-LD DID document (multicodec + multibase encoded)

## Implementation Details

### Files Modified
1. **`src/lib/constants.ts`** - Added variant 4 constants (multicodec prefixes, etc.)
2. **`src/lib/create.ts`** - Added `createNumAlgo4()` function
3. **`src/lib/resolve.ts`** - Added `resolveNumAlgo4()` and `resolveLongFormNumAlgo4()` functions
4. **`src/lib/validators.ts`** - Updated to support `Multikey` type
5. **`src/lib/utils.ts`** - Updated `isPeerDID()` to recognize variant 4 format
6. **`src/lib/interfaces.ts`** - Updated `alsoKnownAs` to be an array
7. **`src/lib/index.ts`** - Added exports for new functions

### New Functions
- `createNumAlgo4(authKeys, encKeys?, services?)` - Creates variant 4 DIDs
- `resolveNumAlgo4(did)` - Resolves variant 4 DIDs
- `resolveLongFormNumAlgo4(did)` - Specifically resolves long form variant 4 DIDs

## Example Usage

```javascript
import { createNumAlgo4, resolveNumAlgo4 } from '@aviarytech/did-peer';

// Create a simple variant 4 DID
const authKey = {
    type: 'Multikey',
    publicKeyMultibase: 'z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
};

const did = await createNumAlgo4([authKey]);
console.log(did);

// Resolve the DID
const didDocument = await resolveNumAlgo4(did);
console.log(didDocument);
```

## Backward Compatibility
- All existing functionality for variants 0, 1, and 2 remains unchanged
- Updated validators accept both legacy types and new `Multikey` type
- Existing test vectors continue to pass

## Testing
- Added 12 new test cases covering variant 4 functionality
- Tests cover creation, resolution, error handling, and edge cases
- All 43 tests pass (24 for create, 19 for resolve)

## Compliance
This implementation follows the latest Peer DID Method specification and supports the transform algorithm for variant 4 with proper multicodec and multihash encoding.
