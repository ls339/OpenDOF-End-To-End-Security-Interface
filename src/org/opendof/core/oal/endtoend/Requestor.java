package org.opendof.core.oal.endtoend;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.opendof.core.oal.DOFErrorException;
import org.opendof.core.oal.DOFException;
import org.opendof.core.oal.DOFInterestLevel;
import org.opendof.core.oal.DOFInterfaceID;
import org.opendof.core.oal.DOFObject;
import org.opendof.core.oal.DOFObjectID;
import org.opendof.core.oal.DOFOperation;
import org.opendof.core.oal.DOFProviderException;
import org.opendof.core.oal.DOFProviderInfo;
import org.opendof.core.oal.DOFQuery;
import org.opendof.core.oal.DOFResult;
import org.opendof.core.oal.DOFSystem;
import org.opendof.core.oal.DOFType;
import org.opendof.core.oal.DOFValue;
import org.opendof.core.oal.DOFOperation.Query;
import org.opendof.core.oal.security.DOFSecurityException;
import org.opendof.core.oal.value.DOFBlob;
import org.opendof.core.oal.value.DOFBoolean;
import org.opendof.core.oal.value.DOFDateTime;

public class Requestor {

    TrainingUI parent; // <-- comment this out when turning off the gui
    DOFSystem mySystem;
    Map<String, DOFObject> objectMap = new HashMap<String, DOFObject>(2);
    DOFObject broadcastObject = null;
    DOFQuery query;
    DOFObject currentProvider = null;
    // For end-to-end
    DOFOperation.Session SessionObject = null;
    DOFObject.SessionOperationListener operationListener = new DOFObject.SessionOperationListener() {
        @Override
        public void sessionOpen(DOFOperation.Session operation, DOFProviderInfo providerInfo,
                                DOFObject session, DOFException exception) {}
        @Override
        public void complete(DOFOperation operation, DOFException exception) {}
    };

    DOFOperation.Get activeGetOperation = null;
    DOFOperation.Set activeSetOperation = null;
    DOFOperation.Invoke activeInvokeOperation = null;

    int TIMEOUT = 5000;

    // ETE fields
    private DataTransform dataTransform;
    private SecretKey secKey;
    private IvParameterSpec initializationVector;
    public static DefaultDataTransform ETE_DATA_TRANSFORM = null; // set by init_data_transform()

    public Requestor(DOFSystem _system, TrainingUI _parent) { // <-- comment this out when turning off the gui
    //public Requestor(DOFSystem _system){
        mySystem = _system;
        this.parent = _parent; // <-- comment this out when turning off the gui
        init();
    }

    private void init() {
        broadcastObject = mySystem.createObject(DOFObjectID.BROADCAST);
        mySystem.beginInterest(TBAInterface.IID, DOFInterestLevel.WATCH);
        query = new DOFQuery.Builder()
            .addFilter(TBAInterface.IID)
            .build();
        mySystem.beginQuery(query, new QueryListener());
    }

    public void setCurrentRequestor(String _oidString) {
        currentProvider = objectMap.get(_oidString);
    }

    public boolean sendSetRequest(boolean _active) {
        try {
            DOFBoolean setValue = new DOFBoolean(_active);
            if (currentProvider != null) {
                currentProvider.set(TBAInterface.PROPERTY_ALARM_ACTIVE, setValue, TIMEOUT);
                return true;
            }
            return false;
        } catch (DOFProviderException e) {
            return false;
        } catch (DOFErrorException e) {
            return false;
        } catch (DOFException e) {
            return false;
        }
    }

    public Boolean sendGetRequest() {
        /*
         * Begin Secure end-to-end session
         * SessionObject = currentProvider.beginSession(iface, sessionType)
         * public DOFOperation.Session beginSession(DOFInterface iface, DOFInterfaceID sessionType, int timeout, SessionOperationListener operationListener)
         * { return oalObject.beginSession(iface, sessionType, timeout, operationListener); }
         */
        try {
            DOFResult<DOFValue> myResult;
            if (currentProvider != null) {
                // end-to-end
                SessionObject = currentProvider.beginSession(TBAInterface.DEF, ETEInterface.IID, operationListener);

                myResult = currentProvider.get(TBAInterface.PROPERTY_ALARM_ACTIVE, TIMEOUT);
                return myResult.asBoolean();
            }
            return null;
        } catch (DOFProviderException e) {
            return null;
        } catch (DOFErrorException e) {
            return null;
        } catch (DOFException e) {
            return null;
        }
    }

    public Boolean sentInvokeRequest(Date _alarmTime) {
        try {
            DOFDateTime alarmTimeParameter = new DOFDateTime(_alarmTime);
            if (currentProvider != null) {
                DOFResult<List<DOFValue>> myResults = currentProvider.invoke(TBAInterface.METHOD_SET_NEW_TIME, TIMEOUT, alarmTimeParameter);
                List<DOFValue> myValueList = myResults.get();
                return DOFType.asBoolean(myValueList.get(0));
            }
            return null;
        } catch (DOFProviderException e) {
            return null;
        } catch (DOFErrorException e) {
            return null;
        } catch (DOFException e) {
            return null;
        }
    }

    // ETE SEND_ENCODED_PUB_KEY Method
    public void SEND_ENCODED_PUB_KEY(KeyAgreement myKeyAgreement)
            throws NoSuchAlgorithmException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException, InvalidKeyException {
        try {
            DHParameterSpec dhSkipParamSpec;
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(2048);
            AlgorithmParameters params = paramGen.generateParameters();
            dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
            KeyPairGenerator requestorKpairGen = KeyPairGenerator.getInstance("DH");
            requestorKpairGen.initialize(dhSkipParamSpec);
            KeyPair requestorKpair = requestorKpairGen.generateKeyPair();
            myKeyAgreement.init(requestorKpair.getPrivate());

            // Create the 16 byte IV
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            initializationVector = ivParameterSpec;

            DOFBlob BlobPubKey = new DOFBlob(requestorKpair.getPublic().getEncoded());
            DOFBlob InitVector = new DOFBlob(iv);

            if (currentProvider != null) {
                DOFResult<List<DOFValue>> myResults = currentProvider.invoke(ETEInterface.SEND_ENCODED_PUB_KEY, TIMEOUT, InitVector, BlobPubKey);
                List<DOFValue> myValueList = myResults.get();
                byte[] providerPubKeyBytes = DOFType.asBytes(myValueList.get(0));
                PublicKey providerPubKey = decodeproviderPubKey(providerPubKeyBytes);
                myKeyAgreement.doPhase(providerPubKey, true);
                byte[] sharedSecretBytes = myKeyAgreement.generateSecret();
                secKey = new SecretKeySpec(sharedSecretBytes, 0, 16, "AES");
                init_data_transform();
            }
        } catch (DOFProviderException e) {
            // handle
        } catch (DOFErrorException e) {
            // handle
        } catch (DOFException e) {
            // handle
        } catch (InvalidKeySpecException e) {
            // handle
        }
    }

    public void setDataTransform(DataTransform dataTransform) {
        this.dataTransform = dataTransform;
    }

    public static final class DefaultDataTransform implements DataTransform {
        private final Cipher savedEncryptCipher;
        private final Cipher savedDecryptCipher;

        public DefaultDataTransform(Cipher encCipher, Cipher decCipher) {
            this.savedEncryptCipher = encCipher;
            this.savedDecryptCipher = decCipher;
        }

        public static Cipher createDecryptCipher(SecretKey sharedSecret, IvParameterSpec iv) {
            try {
                Cipher aesDecryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // MUST specify an IV and distribute to both sides
                aesDecryptCipher.init(Cipher.DECRYPT_MODE, sharedSecret, iv); // iv is the saved IV from encoded public key method
                return aesDecryptCipher;
            } catch (Exception e) {
                return null;
            }
        }

        // create ciphers in initialized method or constructor - class level private variables
        public static Cipher createEncryptCipher(SecretKey sharedSecret, IvParameterSpec iv) {
            try {
                Cipher aesEncryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesEncryptCipher.init(Cipher.ENCRYPT_MODE, sharedSecret, iv); // iv is the saved IV from encoded public key method
                return aesEncryptCipher;
            } catch (Exception e) {
                return null;
            }
        }

        @Override
        public byte[] transformSendData(DOFInterfaceID interfaceID, byte[] data) {
            try {
                return savedEncryptCipher.doFinal(data);
            } catch (Exception e) {
                return data;
            }
        }

        @Override
        public byte[] transformReceiveData(DOFInterfaceID interfaceID, byte[] data) {
            try {
                return savedDecryptCipher.doFinal(data);
            } catch (Exception e) {
                return data;
            }
        }
    } // End of Data Transform

    public void init_data_transform() {
        Cipher encCipher = DefaultDataTransform.createEncryptCipher(secKey, initializationVector);
        Cipher decCipher = DefaultDataTransform.createDecryptCipher(secKey, initializationVector);
        ETE_DATA_TRANSFORM = new DefaultDataTransform(encCipher, decCipher);
        this.dataTransform = ETE_DATA_TRANSFORM;
    }

    // By Saad,
    // Once you receive a response Blob from provider, we need to extract the public key from it for key agreement
    // Input: Provider's EncodedPubkey as a byte[]
    // Output: provider's PubKey
    public PublicKey decodeproviderPubKey(byte[] providerPubKeyEnc)
            throws java.security.NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory requestorKeyFac = KeyFactory.getInstance("DH"); // Get Key specifications from key
        X509EncodedKeySpec x509KeySpec1 = new X509EncodedKeySpec(providerPubKeyEnc); // Create Key
        PublicKey providerPubKey = requestorKeyFac.generatePublic(x509KeySpec1); // Get public key
        return providerPubKey;
    }

    /**
     * To generate a shared secret once the key agreement between parties has concluded.
     * @param requestorKeyAgree A KeyAgreement that has successfully initiated the do-phase of agreement.
     * @return a byte array containing the shared key.
     */
    public byte[] gen_shared_secret(KeyAgreement requestorKeyAgree) throws Exception {
        byte[] requestorSharedSecret = requestorKeyAgree.generateSecret();
        return requestorSharedSecret;
    }

    public void sendBeginGetRequest() {
        activeGetOperation = broadcastObject.beginGet(TBAInterface.PROPERTY_ALARM_ACTIVE, TIMEOUT, new GetListener());
    }

    public void sendBeginSetRequest(boolean _active) {
        DOFBoolean setValue = new DOFBoolean(_active);
        activeSetOperation = broadcastObject.beginSet(TBAInterface.PROPERTY_ALARM_ACTIVE, setValue, TIMEOUT, new SetListener());
    }

    public void sendBeginInvokeRequest(Date _alarmTime) {
        List<DOFValue> parameters = new ArrayList<DOFValue>();
        DOFDateTime alarmTimeParameter = new DOFDateTime(_alarmTime);
        parameters.add(alarmTimeParameter);
        activeInvokeOperation = broadcastObject.beginInvoke(TBAInterface.METHOD_SET_NEW_TIME, parameters, TIMEOUT, new InvokeListener());
    }

    private class QueryListener implements DOFSystem.QueryOperationListener {

        @Override
        public void interfaceAdded(Query operation, DOFObjectID oid, DOFInterfaceID iid) {
            DOFObject providerObject = mySystem.createObject(oid);
            objectMap.put(oid.toStandardString(), providerObject);
        }

        @Override
        public void interfaceRemoved(Query operation, DOFObjectID oid, DOFInterfaceID iid) {
            /* This is called when the provider cancels any provide operation detected by the query. */
        }

        @Override
        public void providerRemoved(Query operation, DOFObjectID oid) {
            /* This is called when, due to the canceling of a provide operation, the provider no longer matches the query. */
            DOFObject providerObject = objectMap.get(oid.toStandardString());
            if (providerObject != null)
                providerObject.destroy();
            objectMap.remove(oid.toStandardString());
        }

        @Override
        public void complete(DOFOperation operation, DOFException exception) {
        }
    }

    private class SetListener implements DOFObject.SetOperationListener {
        @Override
        public void setResult(DOFOperation.Set operation, DOFProviderInfo providerInfo, DOFException exception) {
            if (exception == null) {
                DOFObjectID providerID = providerInfo.getProviderID();
                String providerIDString = providerID.toStandardString();
                parent.displaySetResults(providerIDString); // <-- *
            } else {
                // Handle the error.
            }
        }

        @Override
        public void complete(DOFOperation operation, DOFException ex) {
        }
    }

    private class GetListener implements DOFObject.GetOperationListener {

        @Override
        public void getResult(DOFOperation.Get operation, DOFProviderInfo providerInfo, DOFValue result, DOFException exception) {
            if (exception == null) {
                DOFObjectID providerID = providerInfo.getProviderID();
                String providerIDString = providerID.toStandardString();
                Boolean unwrappedResult = DOFType.asBoolean(result);
                parent.displayGetResults(providerIDString, unwrappedResult); // <-- *
            } else {
                // Handle the error.
            }
        }

        @Override
        public void complete(DOFOperation operation, DOFException ex) {
        }
    }

    private class InvokeListener implements DOFObject.InvokeOperationListener {

        @Override
        public void invokeResult(DOFOperation.Invoke operation, DOFProviderInfo providerInfo, List<DOFValue> result, DOFException exception) {
            if (exception == null) {
                DOFObjectID providerID = providerInfo.getProviderID();
                String providerIDString = providerID.toStandardString();
                Boolean unwrappedResult = DOFType.asBoolean(result.get(0));
                parent.displayInvokeResults(providerIDString, unwrappedResult); // <-- comment this out when turning off the gui
            } else {
                if (exception.getClass().equals(DOFProviderException.class)) {
                    DOFProviderException ex = (DOFProviderException) exception;
                    int itemID = ex.getInterfaceException().getItemID();
                    System.out.println("Received provider exception: " + itemID);
                } else if (exception instanceof DOFSecurityException) {
                    // handle
                } else if (exception.getClass().equals(DOFErrorException.class)) {
                    DOFErrorException ex = (DOFErrorException) exception;
                    int errorCode = ex.getErrorCode();
                    System.out.println("Received error exception: " + errorCode);
                } else {
                    int errorCode = exception.getErrorCode();
                    System.out.println("Received exception: " + errorCode);
                }
            }
        }

        @Override
        public void complete(DOFOperation operation, DOFException ex) {
        }
    }
}
