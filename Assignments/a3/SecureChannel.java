import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class SecureChannel extends InsecureChannel {
    // This is just like an InsecureChannel, except that it provides 
    //    authenticated encryption for the messages that pass
    //    over the channel.   It also guarantees that messages are delivered 
    //    on the receiving end in the same order they were sent (returning
    //    null otherwise).  Also, when the channel is first set up,
    //    the client authenticates the server's identity, and the necessary
    //    steps are taken to detect any man-in-the-middle (and to close the
    //    connection if a MITM is detected).
    //
    // The code provided here is not secure --- all it does is pass through
    //    calls to the underlying InsecureChannel.

    // Instance variables
    private long sendSequenceNumber;
    private long receiveSequenceNumber;
    private AuthEncryptor authEncryptor;
    private AuthDecryptor authDecryptor;

    public SecureChannel(InputStream inStr, OutputStream outStr,
                         PRGen rand, boolean iAmServer,
                         RSAKey serverKey) throws IOException {
        // if iAmServer==false, then serverKey is the server's *public* key
        // if iAmServer==true, then serverKey is the server's *private* key

        super(inStr, outStr);
        // IMPLEMENT THIS

        // Start the sequence numbers at 0
        this.sendSequenceNumber = 0;
        this.receiveSequenceNumber = 0;

        // Perform DHKE over plaintext
        KeyExchange keyExchange = new KeyExchange(rand, iAmServer);
        super.sendMessage(keyExchange.prepareOutMessage());
        byte[] symmetricKey = keyExchange.processInMessage(super.receiveMessage());

        // Create two different keys for the AuthEncryptor and AuthDecryptor
        PRGen keyMaker = new PRGen(symmetricKey);
        byte[] authEncryptorKey = new byte[AuthDecryptor.KEY_SIZE_BYTES];
        byte[] authDecryptorKey = new byte[AuthDecryptor.KEY_SIZE_BYTES];
        
        // Ensure keys line up between client/server
        if (iAmServer) {
            keyMaker.nextBytes(authEncryptorKey);
            keyMaker.nextBytes(authDecryptorKey);
        } else {
            keyMaker.nextBytes(authDecryptorKey);
            keyMaker.nextBytes(authEncryptorKey);
        }
        this.authEncryptor = new AuthEncryptor(authEncryptorKey);
        this.authDecryptor = new AuthDecryptor(authDecryptorKey);

        // If server, sign shared secret and send to client for verification
        if (iAmServer) {
            byte[] symmetricKeySignature = serverKey.sign(symmetricKey, rand);

            // Create nonce using appropriate sequence number
            byte[] nonce = ByteBuffer.allocate(AuthEncryptor.NONCE_SIZE_BYTES).putLong(sendSequenceNumber).array();
            byte[] authenticatedEncryption = authEncryptor.authEncrypt(symmetricKeySignature, nonce, true);
            sendSequenceNumber++; // Update sequence number
            super.sendMessage(authenticatedEncryption);
        }
        // If client, use RSA signature verification to confirm the identity of the server
        else {
            byte[] authenticatedEncryption = super.receiveMessage();
            byte[] symmetricKeySignature = authDecryptor.authDecrypt(authenticatedEncryption);

            // If server can't be verified, close the channel and delete any secret values
            if (!serverKey.verifySignature(symmetricKey, symmetricKeySignature)) {
                authEncryptor = null;
                authDecryptor = null;
                super.close();
            }
            receiveSequenceNumber++; // Update sequence number
        }
    }

    public void sendMessage(byte[] message) throws IOException {
         // Create nonce using appropriate sequence number
        byte[] nonce = ByteBuffer.allocate(AuthEncryptor.NONCE_SIZE_BYTES).putLong(sendSequenceNumber).array();
        byte[] authenticatedEncryption = authEncryptor.authEncrypt(message, nonce, false);
        sendSequenceNumber++; // Update sequence number

        super.sendMessage(authenticatedEncryption);
    }

    public byte[] receiveMessage() throws IOException {
        byte[] authenticatedEncryption = super.receiveMessage();

         // Create nonce using appropriate sequence number
        byte[] nonce = ByteBuffer.allocate(AuthEncryptor.NONCE_SIZE_BYTES).putLong(receiveSequenceNumber).array();
        byte[] recoveredPlaintext = authDecryptor.authDecrypt(authenticatedEncryption, nonce);

        // Return null if message integrity cannot be verified (message changed, received out of order etc.)
        if (recoveredPlaintext == null) return null;

        receiveSequenceNumber++; // Update sequence number
        return recoveredPlaintext;
    }

    // TESTING
    public static void main(String[] args) {
        byte[] key = {-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51,89,-79,100,-106,121,68,79,81,-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51};
        AuthEncryptor authEncryptor = new AuthEncryptor(key);
        AuthDecryptor authDecryptor = new AuthDecryptor(key);
        byte[] nonce = {89,-79,100,-106,121,68,79,81};
        byte[] plaintext = "Can you hear me?".getBytes();
        byte[] authenticatedEncryption = authEncryptor.authEncrypt(plaintext, nonce, true);
        byte[] recoveredPlaintext = authDecryptor.authDecrypt(authenticatedEncryption);
        System.out.println(recoveredPlaintext == null);
        System.out.println(new String(recoveredPlaintext));
    }
}
