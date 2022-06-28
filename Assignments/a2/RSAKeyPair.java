import java.math.BigInteger;

/***
 * This class represents a pair of RSA keys to be used for asymmetric encryption.
 */
public class RSAKeyPair {

    private RSAKey publicKey;
    private RSAKey privateKey;

    // Primes used to generate key pair
    private final BigInteger p;
    private final BigInteger q;

    /***
     * Create an RSA key pair.
     *
     * @param rand PRGen that this class can use to get pseudorandom bits
     * @param numBits size in bits of each of the primes that will be used
     */
    public RSAKeyPair(PRGen rand, int numBits) {

        // IMPLEMENT THIS

        // Pick primes p and q
        this.p = BigInteger.probablePrime(numBits, rand);
        this.q = BigInteger.probablePrime(numBits, rand);

        // Compute n = pq
        BigInteger n = p.multiply(q);

        // Compute 𝜑(n) = (p - 1)(q - 1)
        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        
        // Choose any e where 1 < e < 𝜑(n)^gcd(𝜑(n),e) = 1, that is e, 𝜑(n) are coprime
        //
        // NOTE: We start with e = 3, but increment as necessary until the GCD constraint is 1
        BigInteger e = BigInteger.valueOf(3);
        while (!e.gcd(phi_n).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.ONE);
        }

        // Compute d = e^-1(mod 𝜑(n))
        BigInteger d = e.modInverse(phi_n);

        // SK = (d,n)
        this.privateKey = new RSAKey(d, n);

        // PK = (e,n)
        this.publicKey = new RSAKey(e, n);
    }

    /***
     * Get the public key from this keypair.
     *
     * @return public RSAKey corresponding to this pair
     */
    public RSAKey getPublicKey() {
        return publicKey;
    }

    /***
     * Get the private key from this keypair.
     *
     * @return private RSAKey corresponding to this pair
     */
    public RSAKey getPrivateKey() {
        return privateKey;
    }

    /***
     * Get an array containing the two primes that were used in this KeyPair's generation. In real life, this wouldn't
     * usually be necessary (we don't always keep track of the primes used for generation). Including this function here
     * is for grading purposes.
     *
     * @return two-element array of BigIntegers containing both of the primes used to generate this KeyPair
     */
    public BigInteger[] getPrimes() {
        BigInteger[] primes = new BigInteger[2];

        // IMPLEMENT THIS

        primes[0] = p;
        primes[1] = q;

        return primes;
    }
}
