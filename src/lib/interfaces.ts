export interface IJWK {
	alg?: string;
	crv: string;
	d?: string;
	dp?: string;
	dq?: string;
	e?: string;
	ext?: boolean;
	k?: string;
	key_ops?: string[];
	kid?: string;
	kty: string;
	n?: string;
	oth?: Array<{
		d?: string;
		r?: string;
		t?: string;
	}>;
	p?: string;
	q?: string;
	qi?: string;
	use?: string;
	x?: string;
	y?: string;
	x5c?: string[];
	x5t?: string;
	'x5t#S256'?: string;
	x5u?: string;
	[propName: string]: unknown
}

/**
 * A verification method definition entry in a DID Document.
 */
 export interface IDIDDocumentVerificationMethod {
    /** Fully qualified identifier of this public key, e.g. did:example:123#key-1 */
    id: string;
  
    /** The type of this public key, as defined in: https://w3c-ccg.github.io/ld-cryptosuite-registry/ */
    type: string;
  
    /** The DID of the controller of this key. */
    controller: string;
  
    /** The value of the public key in PEM format. Only one value field will be present. */
    publicKeyPem?: string;
  
    /** The value of the public key in JWK format. Only one value field will be present. */
    publicKeyJwk?: IJWK;
  
    /** The value of the public key in hex format. Only one value field will be present. */
    publicKeyHex?: string;
  
    /** The value of the public key in Base64 format. Only one value field will be present. */
    publicKeyBase64?: string;
  
    /** The value of the public key in Base58 format. Only one value field will be present. */
    publicKeyBase58?: string;
  
    /** The value of the public key in Multibase format. Only one value field will be present. */
    publicKeyMultibase?: string;
  }
  
  export interface IDIDDocumentServiceEndpoint {
    /** uri of the service endpoint */
    uri?: string;
  
    /** array of media types in order of preference for sending a message to the endpoint */
    accept?: string[];
  
    /** ordered array of keys to be used for preparing the message for transmission */
    routingKeys?: string[];
  }
  
  /**
   * Defines a service descriptor entry present in a DID Document.
   */
  export interface IDIDDocumentServiceDescriptor {
    /** id of this service, e.g. `did:example:123#id`. */
    id: string;
  
    /** The type of this service. */
    type: string;
  
    /** The endpoint of this service, as a URI. */
    serviceEndpoint: string | IDIDDocumentServiceEndpoint | IDIDDocumentServiceEndpoint[];

    /** The routing keys to be used */
    routingKeys?: string[],
    
    /** The types of messages the service accepts */
    accepts?: string[]
    /**
     * Allow additional custom properties on service descriptors. This is required
     * for interoperability with services whose specification extends the base
     * definition with extra fields not (yet) known to this library.
     */
    [propName: string]: unknown;
  }
  
  /**
   * Decentralized Identity Document.
   */
  export interface IDIDDocument {
    /** The JSON-LD context of the DID Documents. */
    "@context": string[] | string;
  
    /** The DID to which this DID Document pertains. */
    id: string;
  
    /** The controller of the DID */
    controller?: string;
  
    /** This DID is also known as - array of alternative identifiers */
    alsoKnownAs?: string[];
  
    /** Array of verification methods associated with the DID. */
    verificationMethod?: IDIDDocumentVerificationMethod[];
  
    /** Array of services associated with the DID. */
    service?: IDIDDocumentServiceDescriptor[] | string[];
  
    /** Array of authentication methods. */
    authentication?: IDIDDocumentVerificationMethod[] | string[];
  
    /** Array of assertion methods. */
    assertionMethod?: IDIDDocumentVerificationMethod[] | string[];
  
    /** Array of key agreement methods */
    keyAgreement?: IDIDDocumentVerificationMethod[] | string[];
  
    /** Array of capability invocation methods */
    capabilityInvocation?: IDIDDocumentVerificationMethod[] | string[];
  
      /** Array of capability delegation methods */
  capabilityDelegation?: IDIDDocumentVerificationMethod[] | string[];
}

/**
 * Repository interface for storing and retrieving DID documents.
 * Implementations can use different storage backends (memory, database, filesystem, etc.)
 */
export interface IDIDRepository {
  /** 
   * Store a long form DID document by its short form DID 
   * @param shortFormDid The short form DID to use as key
   * @param longFormDid The long form DID containing the full document
   */
  store(shortFormDid: string, longFormDid: string): Promise<void>;
  
  /** 
   * Retrieve a long form DID document by its short form DID
   * @param shortFormDid The short form DID to look up
   * @returns The corresponding long form DID, or null if not found
   */
  retrieve(shortFormDid: string): Promise<string | null>;
  
  /** 
   * Check if a short form DID exists in the repository
   * @param shortFormDid The short form DID to check
   * @returns True if the DID exists, false otherwise
   */
  exists(shortFormDid: string): Promise<boolean>;
}