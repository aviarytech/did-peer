export enum Numalgo2Prefixes {
    "Authentication" = 'V',
    "KeyAgreement" = 'E',
    "Service" = 'S'
}

export const ServiceReplacements = {
    'type': 't',
    'DIDCommMessaging': 'dm',
    'serviceEndpoint': 's',
    'routingKeys': 'r',
    'accept': 'a'
}

// Variant 4 Transform Constants
export const VARIANT_4_PREFIX = '4';
export const JSON_MULTICODEC_PREFIX = 0x0200; // JSON multicodec prefix
export const SHA256_MULTIHASH_PREFIX = 0x12; // SHA2-256 multihash prefix
export const SHA256_HASH_LENGTH = 0x20; // 32 bytes for SHA2-256
export const MULTIBASE_BASE58BTC_PREFIX = 'z'; // Base58BTC multibase prefix