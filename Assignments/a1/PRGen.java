import java.util.BitSet;

/**********************************************************************************/
/* PRGen.java                                                                     */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a forward secure pseudo-random generator.   */
/*              It should produce a sequence of pseudo-random bits specified by a */
/*              key of length <KEY_SIZE_BYTES>.                                   */
/* ------------------------------------------------------------------------------ */
/* YOUR TASK: You must write a generator with the following properties:           */
/*            (1) It must be pseudo-random, meaning that there is no way to       */
/*                distinguish its output from that of a truly random generator    */
/*                unless you know the key.                                        */
/*            (2) It must be deterministic, meaning that, if two programs create  */
/*                generators with the same seed and make the same sequence of     */
/*                calls, they should receive the same sequence of bytes.          */
/*            (3) It must be forward secure, meaning that, even if an adversary   */
/*                observes the full state of the generator at time t, the         */
/*                adversary will not be able to determine the output of the       */
/*                generator at any time prior to t.                               */
/* ------------------------------------------------------------------------------ */
/* NOTE: This class extends java.util.Random, which means that, once implemented, */
/*       you have access to a number of useful utility methods for free.  We      */
/*       highly recommend that you look up the java.util.Random documentation to  */
/*       understand the full API of this class. For example, you can write        */
/*           prg.nextBytes(outArray);                                             */
/*       instead of                                                               */
/*           for (int i = 0; i < outArray.length; i++) outArray[i] = prg.next();  */
/* ------------------------------------------------------------------------------ */
/* USAGE: Create a generator with a key k by calling the constructor:             */
/*            PRGen prg = new PRGen(k);                                           */
/*                                                                                */
/*        Retrieve pseudo-random bits from the sequence corresponding to key k by */
/*        calling next() (or any related method in the java.util.Random API):     */
/*            int r1 = prg.next(8);  // 8  pseudo-random bits                     */
/*            int r2 = prg.next(32); // 32 pseudo-random bits                     */
/*                                                                                */
/**********************************************************************************/

public class PRGen extends java.util.Random {
    // Class constants.
    public static final int KEY_SIZE_BYTES = PRF.KEY_SIZE_BYTES;
    public static final int OUTPUT_SIZE_BYTES = PRF.OUTPUT_SIZE_BYTES;

    // Instance variables.
    // IMPLEMENT THIS

    private final PRF prf;
    private byte[] state;

    public PRGen(byte[] key) {
        super(); // Calls the parent class's constructor. Leave this here.
        assert key.length == KEY_SIZE_BYTES;

        // IMPLEMENT THIS

        // Create a pseudo-random function with the given key of length KEY_SIZE_BYTES
        this.prf = new PRF(key);
        this.state = key; // Initial value of state is the seed
    }

    // Returns an integer whose low-order <bits> bits are set pseudo-randomly. The
    // higher-order bits should be set to 0.
    protected int next(int bits) {
        assert 0 < bits && bits <= 32;

        // IMPLEMENT THIS.
        
        // Call pseudo-random function to output a byte array of length OUTPUT_SIZE_BYTES
        byte[] out = prf.eval(state);
        assert out.length == OUTPUT_SIZE_BYTES;
        state = out; // Update state
        
        // Produce a correctly-sized bitstream by setting higher-order bits as 0.
        //
        // NOTE: We convert the output byte array from the PRF to a BitSet in order to iterate
        //       over each bit individually.
        BitSet bitSet = BitSet.valueOf(out); // BitSets treat bit order as little-endian

        // Convert bitset to integer representation and return
        // 
        // NOTE: We iterate up to the number of desired pseudo-random bits and then stop. 
        //       This effectively leaves the remaining higher-order bits in the return value 
        //       as 0.
        int value = 0;
        for (int i = 0; i < bits; i++) {
            // If equal to 1, shift return value appropriate number of bits for current index
            value += bitSet.get(i) ? (1 << i) : 0;
        }
        return value;
    }

    // TESTING
    public static void main(String[] args) {
        System.out.println("BEGIN TESTS");

        // Test instantiation with a "random" key of 32 bytes
        byte[] k1 = {-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51,89,-79,100,-106,121,68,79,81,-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51};
        System.out.println(String.format("Using key k1 = %s", k1.toString()));
        System.out.println("Instantiating generator prg1...");
        PRGen prg1 = new PRGen(k1);
        System.out.println("Test complete!");

        // Test pseudo-random number generation
        System.out.println("Generating integer with 5 pseudo-random bits...");
        int r1 = prg1.next(5);
        System.out.println(String.format("Integer r1 = %s", r1));
        System.out.println("Test complete!");
        System.out.println("Generating more integers using same PRG...");
        int r2 = prg1.next(5);
        int r3 = prg1.next(5); 
        System.out.println(String.format("Integer r2 = %s", r2));
        System.out.println(String.format("Integer r3 = %s", r3));
        System.out.println("Test complete!");

        // Test if PRG is deterministic
        System.out.println("Calling different generators with same seed and sequence...");
        byte[] k2 = {121,68,79,81,-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51,-56,108,-21,-73,83,1,-2,-117,-52,-66,-96,-51,89,-79,100,-106};
        System.out.println(String.format("Using key k2 = %s", k2.toString()));
        PRGen prg2 = new PRGen(k2);
        PRGen prg3 = new PRGen(k2);
        int s1 = prg2.next(28);
        s1 = prg2.next(28);
        s1 = prg2.next(28);
        s1 = prg2.next(28);
        int s2 = prg3.next(28);
        s2 = prg3.next(28);
        s2 = prg3.next(28);
        s2 = prg3.next(28);
        assert s1 == s2;
        System.out.println(String.format("Sequence s1 = %s", s1));
        System.out.println(String.format("Sequence s2 = %s", s2));
        System.out.println("Test Complete!");
        prg1 = prg2 = prg3 = null;

        System.out.println("END TESTS");
    }
}
