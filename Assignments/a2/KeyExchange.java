import java.math.BigInteger;
import java.util.Arrays;

/***
 * This class facilitates a key exchange.
 *
 * Once two {@code KeyExchange} participants (objects) are created, two things have to happen for the key exchange to be
 * complete:
 *  1.  Call {@code prepareOutMessage} on the first participant, and send the result to the other participant.
 *  2.  Receive the result of the second participant's {@code prepareOutMessage}, and pass it into the first
 *      participant's {@code processInMessage} method.
 * The process can happen in an arbitrary order of participants (i.e., it doesn't matter which participant is first).
 * They could even happen concurrently in two separate threads. However, your code must work regardless of the order of
 * participants.
 */
public class KeyExchange {
    public static final int OUTPUT_SIZE_BYTES = PRF.OUTPUT_SIZE_BYTES;
    public static final int OUTPUT_SIZE_BITS = 8 * OUTPUT_SIZE_BYTES;

    public static final int BITS_PER_BYTE = 8;

    // instance variables
    // IMPLEMENT THIS

    private final PRGen prGen;

    private BigInteger myPrivateKey;
    private BigInteger sharedSecret;

    /***
     * Prepares to do a key exchange. {@code rand} is a secure pseudorandom generator that can be used by the
     * implementation. {@code iAmServer} is true if and only if this instantiation is playing the server role in the
     * exchange. Each exchange has exactly two participants: one plays the role of client and the other plays the role
     * of server.
     *
     * @param rand secure pseudorandom generator
     * @param iAmServer true iff we are playing the server role in this exchange
     */
    public KeyExchange(PRGen rand, boolean iAmServer) {

        // IMPLEMENT THIS
        
        // Pick random private key with bit length p - 1
        // https://edstem.org/us/courses/18504/discussion/1134731
        this.prGen = rand;
        this.myPrivateKey = new BigInteger(DHConstants.p.bitLength() - 1, rand);
    }

    /***
     * Create a message to send to the other key exchange participant for digest.
     *
     * @return digestible message for sending to the other key exchange participant
     */
    public byte[] prepareOutMessage() {

        // IMPLEMENT THIS

        // Compute g^A mod p, where A is our secret key
        BigInteger publicKey = DHConstants.g.modPow(myPrivateKey, DHConstants.p);

        // If public key is problematic (1 or p - 1), regenerate as necessary
        while (publicKey.compareTo(BigInteger.ONE) == 0 || publicKey.compareTo(DHConstants.p.subtract(BigInteger.ONE)) == 0) {
            this.myPrivateKey = new BigInteger(DHConstants.p.bitLength() - 1, prGen);
            publicKey = DHConstants.g.modPow(myPrivateKey, DHConstants.p);
        }
        int length = (int) Math.ceil(publicKey.bitLength() / (double) BITS_PER_BYTE);
        return HW2Util.bigIntegerToBytes(publicKey, length);
    }

    /***
     * Creates a digest from the specified {@code inMessage} from the other key exchange participant.
     *
     * If passed a null value, then throw a {@code NullPointerException}.
     * Otherwise, if passed a value that could not possibly have been generated
     *    by {@code prepareOutMessage}, then return null.
     * Otherwise, return a "digest" (hash) with the property described below.
     *
     * This code must provide the following security guarantee: If the two
     *    participants end up with the same non-null digest value, then this digest value
     *    is not known to anyone else. This must be true even if third parties
     *    can observe and modify the messages sent between the participants.
     * This code is NOT required to check whether the two participants end up with
     *    the same digest value; the code calling this must verify that property.
     *
     * @param inMessage exchange message from the other key exchange participant
     * @return digest of {@code inMessage} with cryptographic properties as described (the size of the returned array
     * must be {@code OUTPUT_SIZE_BYTES}.
     */
    public byte[] processInMessage(byte[] inMessage) {

        // IMPLEMENT THIS

        // Compute shared secret
        BigInteger theirPublicKey = HW2Util.bytesToBigInteger(inMessage);

        // Reject problematic values (1 or p - 1)
        if (theirPublicKey.compareTo(BigInteger.ONE) == 0 || theirPublicKey.compareTo(DHConstants.p.subtract(BigInteger.ONE)) == 0) return null;

        this.sharedSecret = theirPublicKey.modPow(myPrivateKey, DHConstants.p);
        
        // Return digest of message using hash function
        int length = (int) Math.ceil(sharedSecret.bitLength() / (double) BITS_PER_BYTE);
        byte[] messageToHash = HW2Util.bigIntegerToBytes(sharedSecret, length);
        return HashFunction.computeHash(messageToHash);
    }

    public static void main(String[] args) {
        System.out.println("BEGIN TESTS");

        // Test instantiating two KeyExchange objects (acting as Alice and Bob)
        System.out.println("Test instantiation...");
        byte[] key = {-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51,89,-79,100,-106,121,68,79,81,-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51};
        PRGen prGen = new PRGen(key);
        KeyExchange alice = new KeyExchange(prGen, false);
        KeyExchange bob = new KeyExchange(prGen, false);
        System.out.println("Test complete!");

        // Perform key exchange
        System.out.println("Test exchanging keys...");
        byte[] keyAlice = alice.prepareOutMessage();
        byte[] keyBob = bob.prepareOutMessage();
        byte[] sharedDigestAlice = alice.processInMessage(keyBob);
        byte[] sharedDigestBob = bob.processInMessage(keyAlice);
        System.out.println("Alice's digest from Bob:");
        System.out.println(Arrays.toString(sharedDigestAlice));
        System.out.println("Bob's digest from Alice:");
        System.out.println(Arrays.toString(sharedDigestBob));
        assert Arrays.equals(sharedDigestAlice, sharedDigestBob);
        System.out.println("Test complete!");

        // Test handling problematic public keys
        System.out.println("Test problematic public keys...");
        byte[] badDigest = bob.processInMessage(DHConstants.p.subtract(BigInteger.ONE).toByteArray());
        assert badDigest == null;
        badDigest = bob.processInMessage(BigInteger.ONE.toByteArray());
        assert badDigest == null;
        System.out.println("Test complete!");

        System.out.println("END TESTS");
    }
}
