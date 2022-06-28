import java.math.BigInteger;
import java.util.Arrays;

/***
 * This class represents a single RSA key that can perform the RSA encryption and signing algorithms discussed in
 * class. Note that some of the public methods would normally not be part of a production API, but we leave them
 * public for the sake of grading.
 */
public class RSAKey {
    
    // Class constants
    public static final int BITS_PER_BYTE = 8;
    public static final int R_BYTE_LENGTH = 16;
    public static final int Z_BYTE_LENGTH = 16;
    public static final byte PADDING_BYTE = (byte) 0xff;

    private BigInteger exponent;
    private BigInteger modulus;

    /***
     * Constructor. Create an RSA key with the given exponent and modulus.
     * 
     * @param theExponent exponent to use for this key's RSA math
     * @param theModulus modulus to use for this key's RSA math
     */
    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    /***
     * Get the exponent used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's exponent
     */
    public BigInteger getExponent() {
        return exponent;
    }

    /***
     * Get the modulus used for this key's encryption/decryption.
     *
     * @return BigInteger containing this key's modulus
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /***
     * Pad plaintext input if it is too short for OAEP. Do not call this from {@link #encodeOaep(byte[], PRGen)}.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to pad
     * @return padded plaintext of appropriate length for OAEP
     */
    public byte[] addPadding(byte[] input) {
        
        // IMPLEMENT THIS
        
        // Input needs to be padded so it has length n-k0-k1
        int paddedLength = maxPlaintextLength() + 1;
        byte[] paddedInput = new byte[paddedLength];
        System.arraycopy(input, 0, paddedInput, 0, input.length);
        // Set the first padded byte to be unique for identification later
        paddedInput[input.length] = PADDING_BYTE;
        return paddedInput;
    }

    /***
     * Remove padding applied by {@link #addPadding(byte[])} method. Do not call this from {@link #decodeOaep(byte[])}.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input padded plaintext from which we extract plaintext
     * @return plaintext in {@code input} without padding
     */
    public byte[] removePadding(byte[] input) {
        
        // IMPLEMENT THIS
        
        // Iterate through input array backwards until first padding byte is found
        int paddingBeginsIndex = input.length - 1;
        for (int i = input.length - 1; i >= 0; i--) {
            if (input[i] == PADDING_BYTE) {
                paddingBeginsIndex = i;
                break;
            }
        }

        // Return unpadded message
        byte[] unpaddedInput = Arrays.copyOfRange(input, 0, paddingBeginsIndex);
        return unpaddedInput;
    }

    /***
     * Encode a plaintext input with OAEP method. May require basic padding before calling. Do not call
     * {@link #addPadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input plaintext to encode
     * @param prgen pseudo-random generator to use in encoding algorithm
     * @return OAEP encoded plaintext
     */
    public byte[] encodeOaep(byte[] input, PRGen prgen) {
        
        // IMPLEMENT THIS

        byte[] mAndZ = new byte[input.length + Z_BYTE_LENGTH];
        System.arraycopy(input, 0, mAndZ, 0, input.length);

        // Generate 128-bit random r using PRGen passed in as an argument
        byte[] r = new byte[R_BYTE_LENGTH];
        prgen.nextBytes(r);
        byte[] gKey = Arrays.copyOf(r, 32);

        // Run r through new PRGen G
        PRGen G = new PRGen(gKey);
       
        // XOR with message (assumed to have already been padded with 128 bits of 0s)
        byte[] GOutput = new byte[mAndZ.length];
        G.nextBytes(GOutput);
        byte[] X = new byte[mAndZ.length];
        for (int i = 0; i < mAndZ.length; i++) {
            X[i] = (byte) (GOutput[i] ^ mAndZ[i]);
        }

        // Run X through hash function
        byte[] HOutput = HashFunction.computeHash(X);

        // XOR result with r
        byte[] Y = new byte[r.length];
        for (int i = 0; i < Y.length; i++) {
            Y[i] = (byte) (HOutput[i] ^ r[i]);
        }

        // Concatenate to X
        byte[] output = new byte[X.length + Y.length];
        System.arraycopy(X, 0, output, 0, X.length);
        System.arraycopy(Y, 0, output, X.length, Y.length);
        return output;
    }

    /***
     * Decode an OAEP encoded message back into its plaintext representation. May require padding removal after calling.
     * Do not call {@link #removePadding(byte[])} from this method.
     *
     * In a "real world" application, this would be a private helper function, but for grading purposes we will make it
     * public.
     *
     * Encoding looks like this:
     * <pre>{@code
     *  byte[] plaintext = 'Hello World'.getBytes();
     *  byte[] paddedPlaintext = addPadding(plaintext)
     *  byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);
     * }</pre>
     *
     * Decoding looks like this:
     * <pre>{@code
     *  byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
     *  byte[] recoveredPlaintext = removePadding(unOAEP);
     * }</pre>
     *
     * @param input OEAP encoded message
     * @return decoded plaintext message
     */
    public byte[] decodeOaep(byte[] input) {
        
        // IMPLEMENT THIS

        byte[] Y = Arrays.copyOfRange(input, input.length - R_BYTE_LENGTH, input.length);
        byte[] X = Arrays.copyOfRange(input, 0, input.length - R_BYTE_LENGTH);
        byte[] HOutput = HashFunction.computeHash(X);

        // Recover r as H(X) XOR Y
        byte[] r = new byte[Y.length];
        for (int i = 0; i < r.length; i++) {
            r[i] = (byte) (Y[i] ^ HOutput[i]);
        }

        // Recover m as X XOR G(r)
        byte[] gKey = Arrays.copyOf(r, 32);
        PRGen G = new PRGen(gKey);
        byte[] GOutput = new byte[X.length];
        G.nextBytes(GOutput);
        byte[] mAndZ = new byte[X.length];
        for (int i = 0; i < X.length; i++) {
            mAndZ[i] = (byte) (X[i] ^ GOutput[i]);
        }
        
        // Integrity check
        byte[] z = Arrays.copyOfRange(mAndZ, mAndZ.length - Z_BYTE_LENGTH, mAndZ.length);
        boolean isValid = Arrays.equals(z, new byte[Z_BYTE_LENGTH]);
        if (isValid) {
            byte[] m = Arrays.copyOfRange(mAndZ, 0, mAndZ.length - Z_BYTE_LENGTH);
            return m;
        } else {
            return null;
        }
    }

    /***
     * Get the largest N such that any plaintext of size N bytes can be encrypted with this key and padding/encoding.
     *
     * @return upper bound of plaintext length applicable for this key
     */
    public int maxPlaintextLength() {
        
        // IMPLEMENT THIS
        
        // Account for there always being at least one byte of padding
        int maxLength = ((modulus.bitLength() - 1) / BITS_PER_BYTE) - Z_BYTE_LENGTH - R_BYTE_LENGTH - 1; // Integer division rounds down
        return maxLength;
    }

    /***
     * Encrypt the given plaintext message using RSA algorithm with this key.
     *
     * @param plaintext message to encrypt
     * @param prgen pseudorandom generator to be used for encoding/encryption
     * @return ciphertext result of RSA encryption on this plaintext/key
     */
    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null) throw new NullPointerException();

        // IMPLEMENT THIS

        // Fail if message is longer than maximum length
        if (plaintext.length > maxPlaintextLength()) throw new RuntimeException("Message is longer than maximum allowed length!");
        
        byte[] paddedPlaintext = addPadding(plaintext);
        byte[] paddedPlaintextOAEP = encodeOaep(paddedPlaintext, prgen);

        // m^e (mod n)
        BigInteger m = HW2Util.bytesToBigInteger(paddedPlaintextOAEP);
        BigInteger encryptedMessage = m.modPow(exponent, modulus);
        int length = (int) Math.ceil(encryptedMessage.bitLength() / (double) BITS_PER_BYTE);
        return HW2Util.bigIntegerToBytes(encryptedMessage, length);
    }

    /***
     * Decrypt the given ciphertext message using RSA algorithm with this key. Effectively the inverse of our
     * {@link #encrypt(byte[], PRGen)} method.
     *
     * @param ciphertext encrypted message to decrypt
     * @return plaintext message
     */
    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null) throw new NullPointerException();

        // IMPLEMENT THIS
        
        // c^d (mod n)
        BigInteger c = HW2Util.bytesToBigInteger(ciphertext);
        BigInteger decryptedMessage = c.modPow(exponent, modulus);
        
        int length = (int) Math.ceil(decryptedMessage.bitLength() / (double) BITS_PER_BYTE);
        byte[] paddedPlaintextOAEP = HW2Util.bigIntegerToBytes(decryptedMessage, length);
        byte[] unOAEP = decodeOaep(paddedPlaintextOAEP);
        byte[] recoveredPlaintext = removePadding(unOAEP);
        return recoveredPlaintext;
    }

    /***
     * Create a digital signature on {@code message}. The signature need not contain the contents of {@code message}; we
     * will assume that a party who wants to verify the signature will already know with which message this signature is
     * meant to be associated.
     *
     * @param message message to sign
     * @param prgen pseudorandom generator used for signing
     * @return RSA signature of the message using this key
     */
    public byte[] sign(byte[] message, PRGen prgen) {
        if (message == null) throw new NullPointerException();

        // IMPLEMENT THIS
        
        // m^d (mod n)
        byte[] hashedMessage = HashFunction.computeHash(message);
        BigInteger hashedMessageBigInt = HW2Util.bytesToBigInteger(hashedMessage);
        BigInteger signature = hashedMessageBigInt.modPow(exponent, modulus);
        int length = (int) Math.ceil(signature.bitLength() / (double) BITS_PER_BYTE);
        return HW2Util.bigIntegerToBytes(signature, length);
    }

    /***
     * Verify a digital signature against this key. Returns true if and only if {@code signature} is a valid RSA
     * signature on {@code message}; returns false otherwise. A "valid" RSA signature is one that was created by calling
     * {@link #sign(byte[], PRGen)} with the same message on the other RSAKey that belongs to the same RSAKeyPair as
     * this RSAKey object.
     *
     * @param message message that has been signed
     * @param signature signature to validate against this key
     * @return true iff this RSAKey object's counterpart in a keypair signed the given message and produced the given
     * signature
     */
    public boolean verifySignature(byte[] message, byte[] signature) {
        if ((message == null) || (signature == null)) throw new NullPointerException();

        // IMPLEMENT THIS
        
        // m == S^e (mod n)
        byte[] hashedMessage = HashFunction.computeHash(message);
        BigInteger signatureBigInt = HW2Util.bytesToBigInteger(signature);
        BigInteger rsaOutput = signatureBigInt.modPow(exponent, modulus);
        int length = (int) Math.ceil(rsaOutput.bitLength() / (double) BITS_PER_BYTE);
        return Arrays.equals(hashedMessage, HW2Util.bigIntegerToBytes(rsaOutput, length));
    }

    // TESTING
    public static void main(String[] args) {
        System.out.println("BEGIN TESTS");

        // Test instantiating a KeyPair object and retrieving its keys
        System.out.println("Test instantiation...");
        byte[] key = {-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51,89,-79,100,-106,121,68,79,81,-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51};
        PRGen prGen = new PRGen(key);
        RSAKeyPair keyPair = new RSAKeyPair(prGen, 1024);
        RSAKey publicKey = keyPair.getPublicKey();
        RSAKey privateKey = keyPair.getPrivateKey();
        System.out.println("Test complete!");

        // Test padding and OAEP encoding/decoding
        System.out.println("Test padding and OAEP functions...");
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] paddedPlaintext = publicKey.addPadding(plaintext);
        byte[] paddedPlaintextOAEP = publicKey.encodeOaep(paddedPlaintext, prGen);
        byte[] unOAEP = publicKey.decodeOaep(paddedPlaintextOAEP);
        byte[] recoveredPlaintext = publicKey.removePadding(unOAEP);
        assert Arrays.equals(plaintext, recoveredPlaintext);
        System.out.println("Test complete!");

        // Test encrypted and decrypting text
        System.out.println("Test encryption/decryption...");
        plaintext = "Realmente me encanta esta clase, ¿me entiendes?".getBytes();
        byte[] ciphertext = publicKey.encrypt(plaintext, prGen);
        recoveredPlaintext = privateKey.decrypt(ciphertext);
        assert Arrays.equals(plaintext, recoveredPlaintext);
        System.out.println("Test complete!");

        // Test signing/verification
        System.out.println("Test signing/verification...");
        String message = "Dear Sir: "
        + "I have been requested by the Nigerian National Petroleum Company to contact you for assistance in resolving a matter. "
        + "The Nigerian National Petroleum Company has recently concluded a large number of contracts for oil exploration in the sub-Sahara region. "
        + "The contracts have immediately produced moneys equaling US$40,000,000. "
        + "The Nigerian National Petroleum Company is desirous of oil exploration in other parts of the world, however, "
        + "because of certain regulations of the Nigerian Government, "
        + "it is unable to move these funds to another region.";
        byte[] messageBytes = message.getBytes();
        byte[] signature = privateKey.sign(messageBytes, prGen);
        String fakeMessage = message.replace("Sir", "Ma'am");
        byte[] fakeMessageBytes = fakeMessage.getBytes();
        assert publicKey.verifySignature(messageBytes, signature);
        assert !publicKey.verifySignature(fakeMessageBytes, signature);
        System.out.println("Test complete!");

        System.out.println("END TESTS");
    }
}
