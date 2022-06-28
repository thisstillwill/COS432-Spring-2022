import java.util.Arrays;

/**********************************************************************************/
/* AuthDecrytor.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated decryption of data encrypted using         */
/*              AuthEncryptor.java.                                               */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Decrypt data encrypted by your implementation of AuthEncryptor.java */
/*            if provided with the appropriate key and nonce.  If the data has    */
/*            been tampered with, return null.                                    */
/*                                                                                */
/**********************************************************************************/
public class AuthDecryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = AuthEncryptor.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = AuthEncryptor.NONCE_SIZE_BYTES;

    // Instance variables.
    // IMPLEMENT THIS

    private final byte[] encryptionKey;
    private final byte[] macKey;

    public AuthDecryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;
        // IMPLEMENT THIS

         // Generate two unique keys for encryption and MAC using the given key
        PRGen prGen = new PRGen(key);
        this.encryptionKey = new byte[KEY_SIZE_BYTES];
        prGen.nextBytes(encryptionKey);
        this.macKey = new byte[KEY_SIZE_BYTES];
        prGen.nextBytes(macKey);
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce has been included in <in>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in) {

        // IMPLEMENT THIS

        // Separate authenticated encryption into constituent parts
        byte[] encryptedMessage = Arrays.copyOfRange(in, 0, in.length - NONCE_SIZE_BYTES - PRF.OUTPUT_SIZE_BYTES);
        byte[] mac = Arrays.copyOfRange(in, in.length - NONCE_SIZE_BYTES - PRF.OUTPUT_SIZE_BYTES, in.length - NONCE_SIZE_BYTES);
        byte[] nonce = Arrays.copyOfRange(in, in.length - NONCE_SIZE_BYTES, in.length);

        // Verify MAC
        PRF prf = new PRF(macKey);
        byte[] macComputed = prf.eval(encryptedMessage);
        if (!Arrays.equals(macComputed, mac)) return null;

        // If MAC verified, decrypt ciphertext and return
        StreamCipher streamCipher = new StreamCipher(encryptionKey, nonce);
        byte[] decryptedMessage = new byte[encryptedMessage.length];
        streamCipher.cryptBytes(encryptedMessage, 0, decryptedMessage, 0, encryptedMessage.length);
        return decryptedMessage;
    }

    // Decrypts and authenticates the contents of <in>.  <in> should have been encrypted
    // using your implementation of AuthEncryptor.
    // The nonce used to encrypt the data is provided in <nonce>.
    // If the integrity of <in> cannot be verified, then returns null.  Otherwise,
    // returns a newly allocated byte[] containing the plaintext value that was
    // originally encrypted.
    public byte[] authDecrypt(byte[] in, byte[] nonce) {
        assert nonce != null && nonce.length == NONCE_SIZE_BYTES;

        // IMPLEMENT THIS

         // Separate authenticated encryption into constituent parts
        byte[] encryptedMessage = Arrays.copyOfRange(in, 0, in.length - PRF.OUTPUT_SIZE_BYTES);
        byte[] mac = Arrays.copyOfRange(in, in.length - PRF.OUTPUT_SIZE_BYTES, in.length);

        // Verify MAC
        PRF prf = new PRF(macKey);
        byte[] macComputed = prf.eval(encryptedMessage);
        if (!Arrays.equals(macComputed, mac)) return null;

        // If MAC verified, decrypt ciphertext and return
        StreamCipher streamCipher = new StreamCipher(encryptionKey, nonce);
        byte[] decryptedMessage = new byte[encryptedMessage.length];
        streamCipher.cryptBytes(encryptedMessage, 0, decryptedMessage, 0, encryptedMessage.length);
        return decryptedMessage;
    }
}
