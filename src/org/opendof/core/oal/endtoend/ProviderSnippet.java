package org.opendof.core.oal.endtoend;

// Educational snippet - not production code

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class ProviderSnippet {

    // 11/10/2015 Beginning of Diffie-Hellman Implementation by Saad
    //
    // Phase 0: DH parameter creation
    // Provider gets an encoded public key from which it extracts the DH parameters used
    // Now provider must create his keys using these extracted DH parameters
    //
    // Phase 1: Key Pair Generation, Key-Agree initialization and encoding public keys to be sent
    //   - Now DH Params have been obtained, generate keys
    //
    // Phase 2: Do Phase, final phase of key agreement
    //
    // Phase 3: Shared secret generation
    //   At this stage, both requestor and provider have completed the DH key agreement protocol.
    //   Both generate the (same) shared secret.

    /**
     * Demonstrates the DH key exchange algorithm from the provider side.
     * Given the requestor's encoded public key, derives the shared secret.
     */
    private void dhKeyExchangeExample() throws Exception {
        byte[] requestorPubKeyEnc = null; // Assuming the encoded key received here

        // Set up for DH Parameter extraction
        KeyFactory providerKeyFac = KeyFactory.getInstance("DH"); // Get Key specifications from key
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(requestorPubKeyEnc); // Create Key
        PublicKey requestorPubKey = providerKeyFac.generatePublic(x509KeySpec); // Get public key

        DHParameterSpec dhParamSpec = ((DHPublicKey) requestorPubKey).getParams(); // Get DH Param from public key

        // Generate keys using the extracted DH parameters
        KeyPairGenerator providerKpairGen = KeyPairGenerator.getInstance("DH"); // Generate a pair of keys of the specified algorithm
        providerKpairGen.initialize(dhParamSpec); // Initialize the keypair to the DH parameter generated before
        KeyPair providerKpair = providerKpairGen.generateKeyPair(); // Create a key and assign it to the generator above

        // Key-Pair Agreement Initialization
        KeyAgreement providerKeyAgree = KeyAgreement.getInstance("DH"); // Create a key exchange Agreement of the "DH" parameter
        providerKeyAgree.init(providerKpair.getPrivate()); // Initialize this key Agreement to the private part of provider's keypair

        // Provider encodes his public key, and sends it over to requestor.
        byte[] providerPubKeyEnc = providerKpair.getPublic().getEncoded(); // encode the public part of provider's key as a byte stream

        // Do Phase - final phase of key agreement
        providerKeyAgree.doPhase(requestorPubKey, true);

        // Shared secret generation
        byte[] providerSharedSecret = providerKeyAgree.generateSecret();
    }

    // 11/10/2015 End of Diffie-Hellman Implementation by Saad

    // This is the implementation of the Provider snippet
    // (Session-based providing shown below — see Provider.java for the actual implementation)
    public void generateSharedKey() {
        // placeholder - see handleSendEncodedPubKey in Provider.java
    }

    public void generateEncodedPublicKey() {
        // placeholder - see handleSendEncodedPubKey in Provider.java
    }
}
