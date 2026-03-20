package org.opendof.core.oal.endtoend;

// Educational snippets — shows how DataTransform is wired together. Not intended for direct use.

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.opendof.core.oal.DOFInterfaceID;

public class DataTransformSnippets {

    // These three must be created before the key exchange
    private DataTransform dataTransform = null; // set after key exchange via init_data_transform()
    private SecretKey secKey = null;
    private IvParameterSpec initializationVector = null;
    // These three must be created before the key exchange

    // ETE_DATA_TRANSFORM is null until init_data_transform() is called after key exchange
    private Cipher savedEncryptCipher = null; // = DefaultDataTransform.createEncryptCipher(secKey, initializationVector) after init
    private Cipher savedDecryptCipher = null; // = DefaultDataTransform.createDecryptCipher(secKey, initializationVector) after init

    // Now call transformSendData and transformReceiveData via the dataTransform field

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
    }
}
