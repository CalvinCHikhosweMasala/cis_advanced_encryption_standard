import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * AvalancheTest 
 * Demonstrates that flipping a single bit of the plaintext (or key)
 * changes roughly half of the output ciphertext bits, in an
 * unpredictable way. Starting from the FIPS-197 base plaintext/key
 * pair, this program flips each of the 128 plaintext bits one at a
 * time (key held fixed), then each of the 128 key bits one at a time
 * (plaintext held fixed) — 256 trials total — and measures the
 * Hamming distance between each resulting ciphertext and the
 * unmodified base ciphertext. For every trial, the report shows
 * exactly which byte/bit was flipped and the full before/after input
 * value, so the change is visible, not just its effect. A full
 * per-bit report is written to a file, and summary averages are
 * printed to stdout.
 *
 * Usage:
 *   java AvalancheTest avalanche_report.txt
 */
public class AvalancheTest {

    public static void main(String[] args) throws IOException {
        String outputPath = (args.length > 0) ? args[0] : "avalanche_report.txt";

        // FIPS-197 Appendix B base case
        byte[] baseKey = hexToBytes("000102030405060708090a0b0c0d0e0f");
        byte[] basePt = hexToBytes("00112233445566778899aabbccddeeff");

        try (PrintWriter writer = new PrintWriter(new FileWriter(outputPath))) {
            writer.println("AES-128 Avalanche Effect Report");
            writer.println("================================");
            writer.println();

            double avgPlaintextFlip = runSeries("Plaintext bit-flip test", basePt, baseKey, true, writer);
            double avgKeyFlip = runSeries("Key bit-flip test", basePt, baseKey, false, writer);

            System.out.printf("Plaintext bit-flip test: average %.1f%% of ciphertext bits changed per single input-bit flip%n",
                    avgPlaintextFlip);
            System.out.printf("Key bit-flip test: average %.1f%% of ciphertext bits changed per single input-bit flip%n",
                    avgKeyFlip);
        }

        System.out.println();
        System.out.println("Full per-bit report written to: " + outputPath);
    }

    /**
     * Flips each of the 128 bits (of either the plaintext or the key, depending
     * on flipPlaintext) one at a time, re-encrypts, and measures the Hamming
     * distance of the resulting ciphertext against the unmodified base
     * ciphertext. Returns the average percentage of differing bits.
     */
    private static double runSeries(String label, byte[] basePt, byte[] baseKey,
                                     boolean flipPlaintext, PrintWriter writer) {
        byte[] baseCt = AES128.encryptBlock(basePt, baseKey);
        byte[] baseInput = flipPlaintext ? basePt : baseKey;

        writer.println("=== " + label + " ===");
        writer.println("Base plaintext : " + toHex(basePt));
        writer.println("Base key       : " + toHex(baseKey));
        writer.println("Base ciphertext: " + toHex(baseCt));
        writer.println();

        long totalDiffBits = 0;

        for (int bit = 0; bit < 128; bit++) {
            byte[] pt = basePt.clone();
            byte[] key = baseKey.clone();

            int byteIndex = bit / 8;
            int bitInByte = bit % 8;
            byte originalByte = baseInput[byteIndex];

            if (flipPlaintext) {
                flipBit(pt, bit);
            } else {
                flipBit(key, bit);
            }

            byte[] modifiedInput = flipPlaintext ? pt : key;
            byte flippedByte = modifiedInput[byteIndex];

            byte[] ct = AES128.encryptBlock(pt, key);
            int diff = hammingDistance(baseCt, ct);
            totalDiffBits += diff;

            // Show exactly which byte/bit changed and the value before -> after,
            // plus the full modified input, so the flip itself is visible.
            writer.printf(
                "Flip bit %3d (byte[%2d] bit %d): 0x%02x -> 0x%02x | %s: %s%n" +
                "    ciphertext: %s | differing bits: %3d / 128 (%.1f%%)%n",
                bit, byteIndex, bitInByte,
                originalByte & 0xFF, flippedByte & 0xFF,
                flipPlaintext ? "plaintext" : "key",
                toHex(modifiedInput),
                toHex(ct), diff, 100.0 * diff / 128.0
            );
        }

        double avg = totalDiffBits / 128.0;
        writer.printf("%nAverage differing bits across all 128 single-bit flips: %.2f / 128 (%.1f%%)%n%n",
                avg, 100.0 * avg / 128.0);

        return 100.0 * avg / 128.0;
    }

    /** Flips exactly one bit (0..127) of a 16-byte block, in place. */
    private static void flipBit(byte[] block, int bitIndex) {
        int byteIndex = bitIndex / 8;
        int bitInByte = bitIndex % 8;
        block[byteIndex] ^= (byte) (1 << bitInByte);
    }

    private static int hammingDistance(byte[] a, byte[] b) {
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            int x = (a[i] ^ b[i]) & 0xFF;
            diff += Integer.bitCount(x);
        }
        return diff;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
