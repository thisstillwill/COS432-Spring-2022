import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**********************************************************************************/
/* StreamCipher.java                                                              */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a stream cipher, which encrypts or decrypts */
/*              a stream of bytes (the two operations are identical).             */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: Implement a stream cipher.                                          */
/* ------------------------------------------------------------------------------ */
/* USAGE: Create a new StreamCipher with key k of length <KEY_SIZE_BYTES> and     */
/*        nonce n of length NONCE_SIZE_BYTES:                                     */
/*            StreamCipher enc = new StreamCipher(k, n);                          */
/*                                                                                */
/*        Encrypt two bytes b1 and b2:                                            */
/*            byte e1 = enc.cryptByte(b1);                                        */
/*            byte e2 = enc.cryptByte(b2);                                        */
/*                                                                                */
/*        Decrypt two bytes e1 and e2.  First, create a StreamCipher with the     */
/*        same key and nonce, and then call cryptByte() on the encrypted bytes in */
/*        the same order.                                                         */
/*            StreamCipher dec = new StreamCipher(k, n);                          */
/*            byte d1 = dec.cryptByte(e1);                                        */
/*            byte d2 = dec.cryptByte(e2);                                        */
/*            assert (d1 == b1 && d2 == b2);                                      */
/**********************************************************************************/
public class StreamCipher {
    // Class constants.
    public static final int KEY_SIZE_BYTES   = PRGen.KEY_SIZE_BYTES;
    public static final int NONCE_SIZE_BYTES = 8;

    // Instance variables.
    // IMPLEMENT THIS

    // Note: The session key and PRF are only needed during instantiation.
    //       Therefore, only the PRGen is an instance variable.
    private final PRGen prGen;

    // Creates a new StreamCipher with key <key> and nonce composed of
    // nonceArr[nonceOffset] through nonceArr[nonceOffset + NONCE_SIZE_BYTES - 1].
    public StreamCipher(byte[] key, byte[] nonceArr, int nonceOffset) {
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS

        // Create a new PRF using the given key
        PRF prf = new PRF(key);
        // Generate a session key by evaluating the PRF with the given nonce
        byte[] sessionKey = prf.eval(nonceArr, nonceOffset, NONCE_SIZE_BYTES);
        // Seed a PRGen using the generated session key
        this.prGen = new PRGen(sessionKey);
    }

    public StreamCipher(byte[] key, byte[] nonce) {
        this(key, nonce, 0); // Call the other constructor.
    }

    // Encrypts or decrypts the next byte in the stream.
    public byte cryptByte(byte in) {

        // IMPLEMENT THIS

        // Generate a pseudorandom byte 
        //
        // NOTE: Random.nextBytes() acts on an array of bytes. To work with just a 
        //       single byte, we use a byte array of size 1 as the argument to the function.
        byte[] rBytes = new byte[1];
        prGen.nextBytes(rBytes);

        return (byte) (in ^ rBytes[0]);
         
    }

    // Encrypts or decrypts multiple bytes.
    // Encrypts or decrypts inBuf[inOffset] through inBuf[inOffset + numBytes - 1],
    // storing the result in outBuf[outOffset] through outBuf[outOffset + numBytes - 1].
    public void cryptBytes(byte[]  inBuf, int  inOffset, 
                           byte[] outBuf, int outOffset, int numBytes) {

        // IMPLEMENT THIS

        // Call cryptByte() for each byte in inBuf, accounting for inOffset
        int j = outOffset;
        for (int i = inOffset; i < inOffset + numBytes; i++) {
            byte b = cryptByte(inBuf[i]);
            // Store result in outBuf, accounting for outOffset
            outBuf[j] = b;
            j++;
        }
    }

    // TESTING
    public static void main(String[] args) {
        System.out.println("BEGIN TESTS");

        // Test basic encryption/decryption
        System.out.println("Encrypting a message...");
        String stringtext = "All your base are belong to us!";
        System.out.println(String.format("Message: %s", stringtext));
        byte[] plaintext = stringtext.getBytes();
        System.out.println(String.format("Bytes: %s", stringtext.getBytes()));
        byte[] key = {-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51,89,-79,100,-106,121,68,79,81,-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51};
        System.out.println(String.format("Key: %s", key));
        byte[] nonce = "thisisanonce".getBytes();
        System.out.println(String.format("Nonce: %s", nonce));
        StreamCipher encSC = new StreamCipher(key, nonce);
        byte[] ciphertext = new byte[plaintext.length];
        encSC.cryptBytes(plaintext, 0, ciphertext, 0, ciphertext.length);
        System.out.println(String.format("Encrypted message: %s", ciphertext));
        StreamCipher decSC = new StreamCipher(key, nonce);
        byte[] recovered = new byte[plaintext.length];
        decSC.cryptBytes(ciphertext, 0, recovered, 0, recovered.length);
        System.out.println(String.format("Decrypted message: %s", new String(recovered, StandardCharsets.UTF_8)));
        assert Arrays.equals(plaintext, recovered);
        System.out.println("Test Complete!");

        // Test that different nonce (with the same key and message) produces different encrypted message
        System.out.println("Encrypting message with different nonce...");
        byte[] nonce2 = "abc123xyz".getBytes();
        System.out.println(String.format("New nonce: %s", nonce2));
        assert !Arrays.equals(nonce, nonce2);
        StreamCipher encSC2 = new StreamCipher(key, nonce2);
        byte[] ciphertext2 = new byte[plaintext.length];
        encSC2.cryptBytes(plaintext, 0, ciphertext2, 0, ciphertext2.length);
        System.out.println(String.format("New encrypted message: %s", ciphertext2));
        assert !Arrays.equals(ciphertext, ciphertext2);
        System.out.println("Test Complete!");

        // Test that new encrypted message still decrypts to same message
        System.out.println("Decrypting new encryption to plaintext...");
        StreamCipher decSC2 = new StreamCipher(key, nonce2);
        byte[] recovered2 = new byte[plaintext.length];
        decSC2.cryptBytes(ciphertext2, 0, recovered2, 0, recovered2.length);
        System.out.println(String.format("New decrypted message: %s", new String(recovered2, StandardCharsets.UTF_8)));
        assert Arrays.equals(recovered, recovered2);
        System.out.println("Test Complete!");
        encSC = decSC = encSC2 = decSC2 = null;

        System.out.println("END TESTS");
    }
}
