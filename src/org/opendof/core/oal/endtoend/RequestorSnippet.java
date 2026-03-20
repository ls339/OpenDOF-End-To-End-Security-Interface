package org.opendof.core.oal.endtoend;

// Educational snippet - not production code

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import org.opendof.core.oal.DOFException;
import org.opendof.core.oal.DOFOperation;
import org.opendof.core.oal.DOFProviderInfo;
import org.opendof.core.oal.DOFObject;

public class RequestorSnippet {

    // Example method showing how the requestor generates DH parameters and sends its public key
    public void SEND_ENCODED_PUB_KEY(KeyAgreement X) throws Exception {
        // Phase 0: DH parameter creation
        DHParameterSpec dhSkipParamSpec;
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH"); // Initialize(empty) parameters for the given algorithm
        paramGen.init(1024); // Initializes this parameter generator for a size of 1024 bits.
        AlgorithmParameters params = paramGen.generateParameters(); // Generate the parameters
        dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class); // Generate the parameters

        // Phase 1: Key Pair Generation, Key-Agree initialization and encoding public keys to be sent
        KeyPairGenerator requestorKpairGen = KeyPairGenerator.getInstance("DH"); // Generate a pair of keys of the specified algorithm
        requestorKpairGen.initialize(dhSkipParamSpec); // Initialize the keypair to the DH parameter generated before
        KeyPair requestorKpair = requestorKpairGen.generateKeyPair(); // Create a key and assign it to the generator above

        X.init(requestorKpair.getPrivate()); // Initialize this key Agreement to the private part of requestor's keypair

        // Key-Pair Generation Complete, now send part
        byte[] requestorPubKeyEnc = requestorKpair.getPublic().getEncoded(); // encode the public part of requestor's key as a byte stream
        // send.requestorPubKeyEnc; sending to provider
    }

    // 11/10/2015 Beginning of Diffie-Hellman Implementation by Saad

    /**
     * Demonstrates the full DH key exchange flow from the requestor side.
     */
    private void dhKeyExchangeExample() throws Exception {
        // Phase 0: DH parameter creation
        DHParameterSpec dhSkipParamSpec;
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH"); // Initialize(empty) parameters for the given algorithm
        paramGen.init(1024); // Initializes this parameter generator for a size of 1024 bits.
        AlgorithmParameters params = paramGen.generateParameters(); // Generate the parameters
        dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class); // Generate the parameters

        // Phase 1: Key Pair Generation, Key-Agree initialization and encoding public keys to be sent
        KeyPairGenerator requestorKpairGen = KeyPairGenerator.getInstance("DH"); // Generate a pair of keys of the specified algorithm
        requestorKpairGen.initialize(dhSkipParamSpec); // Initialize the keypair to the DH parameter generated before
        KeyPair requestorKpair = requestorKpairGen.generateKeyPair(); // Create a key and assign it to the generator above

        KeyAgreement requestorKeyAgree = KeyAgreement.getInstance("DH"); // Create a key exchange Agreement of the "DH" parameter
        requestorKeyAgree.init(requestorKpair.getPrivate()); // Initialize this key Agreement to the private part of requestor's keypair

        // Key-Pair Generation Complete, now send part
        byte[] requestorPubKeyEnc = requestorKpair.getPublic().getEncoded(); // encode the public part of requestor's key as a byte stream
        // send.requestorPubKeyEnc; sending to provider

        // The Requestor would wait for Provider's response at this point.
        // Response would be provider's encoded public key
        // This key needs to be saved for future use

        byte[] providerPubKeyEnc = null; // Assuming the encoded key received here

        KeyFactory requestorKeyFac = KeyFactory.getInstance("DH"); // Get Key specifications from key
        X509EncodedKeySpec x509KeySpec1 = new X509EncodedKeySpec(providerPubKeyEnc); // Create Key
        PublicKey providerPubKey = requestorKeyFac.generatePublic(x509KeySpec1); // Get public key

        // Phase 2: Do Phase, final phase of key agreement
        requestorKeyAgree.doPhase(providerPubKey, true);

        // Phase 3: Shared secret generation
        // At this stage, both requestor and provider have completed the DH key agreement protocol.
        // Both generate the (same) shared secret.
        byte[] requestorSharedSecret = requestorKeyAgree.generateSecret(); // Shared secret stored in a byte array
    }

    // 11/10/2015 End of Diffie-Hellman Implementation by Saad

    // This is the Requestor snippet - session operation listener example
    public class CustomSessionOperationListener implements DOFObject.SessionOperationListener {
        @Override
        public void sessionOpen(DOFOperation.Session operation, DOFProviderInfo providerInfo,
                                DOFObject session, DOFException exception) {
            // Save the session Object
            // Once this is called the session is ready for use
        }

        @Override
        public void complete(DOFOperation operation, DOFException exception) {
            if (operation != null) {
                if (exception != null) {
                    // The sessionObject is not available any more.
                }
            }
        }
    }

    public void generateSharedKey() {
        // placeholder - see SEND_ENCODED_PUB_KEY in Requestor.java
    }

    public void generateEncodedPublicKey() {
        // placeholder - see SEND_ENCODED_PUB_KEY in Requestor.java
    }
}
