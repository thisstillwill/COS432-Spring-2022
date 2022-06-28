/**********************************************************************************/
/* AuthEncryptor.java                                                             */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: Performs authenticated encryption of data.                        */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement authenticated encryption, ensuring:                       */
/*            (1) Confidentiality: the only way to recover encrypted data is to   */
/*                perform authenticated decryption with the same key and nonce    */
/*                used to encrypt the data.                                       */
/*            (2) Integrity: A party decrypting the data using the same key and   */
/*                nonce that were used to encrypt it can verify that the data has */
/*                not been modified since it was encrypted.                       */
/*                                                                                */
/**********************************************************************************/
public class AuthEncryptor {
    // Class constants.
    public static final int KEY_SIZE_BYTES = StreamCipher.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = StreamCipher.NONCE_SIZE_BYTES;

    // Instance variables.
    // IMPLEMENT THIS

    private final byte[] encryptionKey;
    private final byte[] macKey;

    public AuthEncryptor(byte[] key) {
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS

        // Generate two unique keys for encryption and MAC using the given key
        PRGen prGen = new PRGen(key);
        this.encryptionKey = new byte[KEY_SIZE_BYTES];
        prGen.nextBytes(encryptionKey);
        this.macKey = new byte[KEY_SIZE_BYTES];
        prGen.nextBytes(macKey);
    }

    // Encrypts the contents of <in> so that its confidentiality and integrity are protected against those who do not
    //     know the key and nonce.
    // If <nonceIncluded> is true, then the nonce is included in plaintext with the output.
    // Returns a newly allocated byte[] containing the authenticated encryption of the input.
    public byte[] authEncrypt(byte[] in, byte[] nonce, boolean includeNonce) {

        // IMPLEMENT THIS

        // Encrypt message
        StreamCipher streamCipher = new StreamCipher(encryptionKey, nonce);
        byte[] encryptedMessage = new byte[in.length];
        streamCipher.cryptBytes(in, 0, encryptedMessage, 0, in.length);

        // Compute MAC on ciphertext
        PRF prf = new PRF(macKey);
        byte[] mac = prf.eval(encryptedMessage);

        // Return ciphertext concatenated with MAC and (if applicable) nonce
        byte[] authenticatedEncryption;
        if (includeNonce) {
            authenticatedEncryption = new byte[encryptedMessage.length + mac.length + nonce.length];
            System.arraycopy(encryptedMessage, 0, authenticatedEncryption, 0, encryptedMessage.length);
            System.arraycopy(mac, 0, authenticatedEncryption, encryptedMessage.length, mac.length);
            System.arraycopy(nonce, 0, authenticatedEncryption, encryptedMessage.length + mac.length, nonce.length);
        } else {
            authenticatedEncryption = new byte[encryptedMessage.length + mac.length];
            System.arraycopy(encryptedMessage, 0, authenticatedEncryption, 0, encryptedMessage.length);
            System.arraycopy(mac, 0, authenticatedEncryption, encryptedMessage.length, mac.length);
        }
        return authenticatedEncryption;
    }
}
