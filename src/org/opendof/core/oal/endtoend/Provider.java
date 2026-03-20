package org.opendof.core.oal.endtoend;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.opendof.core.oal.DOF;
import org.opendof.core.oal.DOFErrorException;
import org.opendof.core.oal.DOFException;
import org.opendof.core.oal.DOFInterface;
import org.opendof.core.oal.DOFInterfaceID;
import org.opendof.core.oal.DOFObject;
import org.opendof.core.oal.DOFObjectID;
import org.opendof.core.oal.DOFOperation;
import org.opendof.core.oal.DOFRequest;
import org.opendof.core.oal.DOFSystem;
import org.opendof.core.oal.DOFType;
import org.opendof.core.oal.DOFValue;
import org.opendof.core.oal.value.DOFBlob;
import org.opendof.core.oal.value.DOFBoolean;
import org.opendof.core.oal.value.DOFDateTime;

public class Provider {

    private DOFSystem mySystem;
    private DOFObject myObject;
    private boolean alarmActive = false;
    private DOFDateTime alarmTime = new DOFDateTime(new Date());
    private int delay = 1000;

    // ETE fields
    private SecretKey secKey;
    private IvParameterSpec initializationVector;
    private Cipher savedEncryptCipher;
    private Cipher savedDecryptCipher;

    public Provider(DOFSystem system, String oidString) {
        this.mySystem = system;
        myObject = mySystem.createObject(DOFObjectID.create(oidString));
        myObject.beginProvide(TBAInterface.DEF, DOF.TIMEOUT_NEVER, new TBAOperationListener(), null);
        myObject.beginProvide(ETEInterface.DEF, DOF.TIMEOUT_NEVER, new ETEOperationListener(), null);
    }

    public void setDelay(int delay) {
        this.delay = delay;
    }

    public void setActive(boolean active) {
        this.alarmActive = active;
    }

    public boolean getActive() {
        return alarmActive;
    }

    /**
     * Handles the SEND_ENCODED_PUB_KEY invoke from the requestor.
     * Extracts the IV and requestor's public key, performs DH key agreement,
     * derives the shared AES key, and initializes encrypt/decrypt ciphers.
     */
    private void handleSendEncodedPubKey(DOFRequest.Invoke request, List<DOFValue> parameters) {
        try {
            byte[] ivBytes = DOFType.asBytes(parameters.get(0));
            byte[] requestorPubKeyEnc = DOFType.asBytes(parameters.get(1));
            initializationVector = new IvParameterSpec(ivBytes);

            // Decode requestor's pub key and extract DH params
            KeyFactory keyFac = KeyFactory.getInstance("DH");
            PublicKey requestorPubKey = keyFac.generatePublic(new X509EncodedKeySpec(requestorPubKeyEnc));
            DHParameterSpec dhParamSpec = ((DHPublicKey) requestorPubKey).getParams();

            // Generate provider's own DH key pair using same params
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhParamSpec);
            KeyPair providerKpair = kpg.generateKeyPair();

            // Key agreement
            KeyAgreement providerKeyAgree = KeyAgreement.getInstance("DH");
            providerKeyAgree.init(providerKpair.getPrivate());
            providerKeyAgree.doPhase(requestorPubKey, true);

            // Derive shared AES key and initialize ciphers
            byte[] sharedSecretBytes = providerKeyAgree.generateSecret();
            secKey = new SecretKeySpec(sharedSecretBytes, 0, 16, "AES");
            savedEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            savedEncryptCipher.init(Cipher.ENCRYPT_MODE, secKey, initializationVector);
            savedDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            savedDecryptCipher.init(Cipher.DECRYPT_MODE, secKey, initializationVector);

            // Return provider's encoded pub key
            request.respond(new DOFBlob(providerKpair.getPublic().getEncoded()));
        } catch (Exception e) {
            request.respond(new DOFErrorException(DOFErrorException.INTERNAL));
        }
    }

    private class TBAOperationListener extends DOFObject.DefaultProvider {

        @Override
        public void get(DOFOperation.Provide operation, DOFRequest.Get request,
                        DOFObject object, DOFInterface.Property property) {
            try {
                if (property.equals(TBAInterface.PROPERTY_ALARM_ACTIVE)) {
                    request.respond(new DOFBoolean(alarmActive));
                } else if (property.equals(TBAInterface.PROPERTY_ALARM_TIME_VALUE)) {
                    request.respond(alarmTime);
                } else {
                    request.respond(new DOFErrorException(DOFErrorException.NOT_SUPPORTED));
                }
            } catch (Exception e) {
                request.respond(new DOFErrorException(DOFErrorException.INTERNAL));
            }
        }

        @Override
        public void set(DOFOperation.Provide operation, DOFRequest.Set request,
                        DOFObject object, DOFInterface.Property property, DOFValue newValue) {
            try {
                if (property.equals(TBAInterface.PROPERTY_ALARM_ACTIVE)) {
                    alarmActive = DOFType.asBoolean(newValue);
                    request.respond();
                } else {
                    request.respond(new DOFErrorException(DOFErrorException.NOT_SUPPORTED));
                }
            } catch (Exception e) {
                request.respond(new DOFErrorException(DOFErrorException.INTERNAL));
            }
        }

        @Override
        public void invoke(DOFOperation.Provide operation, DOFRequest.Invoke request,
                           DOFObject object, DOFInterface.Method method, List<DOFValue> parameters) {
            try {
                if (method.equals(TBAInterface.METHOD_SET_NEW_TIME)) {
                    alarmTime = (DOFDateTime) parameters.get(0);
                    request.respond(new DOFBoolean(true));
                } else {
                    request.respond(new DOFErrorException(DOFErrorException.NOT_SUPPORTED));
                }
            } catch (Exception e) {
                request.respond(new DOFErrorException(DOFErrorException.INTERNAL));
            }
        }

        @Override
        public void complete(DOFOperation operation, DOFException exception) {
        }
    }

    private class ETEOperationListener extends DOFObject.DefaultProvider {

        @Override
        public void get(DOFOperation.Provide operation, DOFRequest.Get request,
                        DOFObject object, DOFInterface.Property property) {
            request.respond(new DOFErrorException(DOFErrorException.NOT_SUPPORTED));
        }

        @Override
        public void set(DOFOperation.Provide operation, DOFRequest.Set request,
                        DOFObject object, DOFInterface.Property property, DOFValue newValue) {
            request.respond(new DOFErrorException(DOFErrorException.NOT_SUPPORTED));
        }

        @Override
        public void invoke(DOFOperation.Provide operation, DOFRequest.Invoke request,
                           DOFObject object, DOFInterface.Method method, List<DOFValue> parameters) {
            if (method.equals(ETEInterface.SEND_ENCODED_PUB_KEY)) {
                handleSendEncodedPubKey(request, parameters);
            } else {
                request.respond(new DOFErrorException(DOFErrorException.NOT_SUPPORTED));
            }
        }

        @Override
        public void complete(DOFOperation operation, DOFException exception) {
        }
    }
}
