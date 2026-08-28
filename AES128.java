import java.util.Arrays;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * AES-128 implementation from scratch (no external crypto libraries).
 * Implements ECB-mode single-block encryption and decryption exactly as
 * defined in FIPS-197 (Advanced Encryption Standard).
 *
 * Key size   : 128 bits (16 bytes)
 * Block size : 128 bits (16 bytes)
 * Rounds     : 10 (Nr = 10, Nk = 4, Nb = 4)
 */
public class AES128 {

    // ---------------------------------------------------------------
    // 1. CONSTANT TABLES
    // ---------------------------------------------------------------

    // Forward S-box: used in SubBytes / SubWord (key expansion)
    private static final int[] SBOX = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    // Inverse S-box: used in InvSubBytes (decryption)
    private static final int[] INV_SBOX = new int[256];
    static {
        for (int i = 0; i < 256; i++) {
            INV_SBOX[SBOX[i]] = i;
        }
    }

    // Round constant word array, used in key expansion (Rcon[i] = x^(i-1) in GF(2^8))
    private static final int[] RCON = {
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
    };

    private static final int Nb = 4;   // block size in 32-bit words (always 4 for AES)
    private static final int Nk = 4;   // key length in 32-bit words (4 for AES-128)
    private static final int Nr = 10;  // number of rounds (10 for AES-128)

    // ---------------------------------------------------------------
    // 2. GALOIS FIELD (GF(2^8)) MULTIPLICATION
    //    Needed for MixColumns / InvMixColumns.
    // ---------------------------------------------------------------
    private static int gmul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            boolean hiBitSet = (a & 0x80) != 0;
            a = (a << 1) & 0xFF;
            if (hiBitSet) a ^= 0x1B; // reduction polynomial x^8+x^4+x^3+x+1
            b >>= 1;
        }
        return p & 0xFF;
    }

    // ---------------------------------------------------------------
    // 3. KEY EXPANSION (Rijndael key schedule)
    //    Turns the 16-byte key into 11 round keys (44 words total).
    // ---------------------------------------------------------------
    private static int[] keyExpansion(byte[] key) {
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("AES-128 key must be exactly 16 bytes");
        }
        int[] w = new int[Nb * (Nr + 1)]; // 44 words

        // First Nk words = the cipher key itself
        for (int i = 0; i < Nk; i++) {
            w[i] = ((key[4*i] & 0xFF) << 24) | ((key[4*i+1] & 0xFF) << 16)
                 | ((key[4*i+2] & 0xFF) << 8) | (key[4*i+3] & 0xFF);
        }

        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            int temp = w[i - 1];
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) ^ RCON[i / Nk];
            }
            w[i] = w[i - Nk] ^ temp;
        }
        return w;
    }

    // RotWord: cyclic left shift of a word's 4 bytes, e.g. [a0,a1,a2,a3] -> [a1,a2,a3,a0]
    private static int rotWord(int word) {
        return (word << 8) | ((word >>> 24) & 0xFF);
    }

    // SubWord: apply the S-box to each of the 4 bytes in a word
    private static int subWord(int word) {
        int b0 = SBOX[(word >>> 24) & 0xFF];
        int b1 = SBOX[(word >>> 16) & 0xFF];
        int b2 = SBOX[(word >>> 8) & 0xFF];
        int b3 = SBOX[word & 0xFF];
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    // ---------------------------------------------------------------
    // 4. STATE HELPERS
    //    State is a 4x4 byte matrix stored column-major, per FIPS-197.
    // ---------------------------------------------------------------
    private static byte[][] bytesToState(byte[] in) {
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = in[i];
        }
        return state;
    }

    private static byte[] stateToBytes(byte[][] state) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            out[i] = state[i % 4][i / 4];
        }
        return out;
    }

    // AddRoundKey: XOR each column of the state with a 32-bit word of the round key
    private static void addRoundKey(byte[][] state, int[] w, int round) {
        for (int c = 0; c < 4; c++) {
            int word = w[round * 4 + c];
            state[0][c] ^= (word >>> 24) & 0xFF;
            state[1][c] ^= (word >>> 16) & 0xFF;
            state[2][c] ^= (word >>> 8) & 0xFF;
            state[3][c] ^= word & 0xFF;
        }
    }

    // SubBytes: replace every byte with its S-box substitution (non-linear step)
    private static void subBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = (byte) SBOX[state[r][c] & 0xFF];
    }

    private static void invSubBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = (byte) INV_SBOX[state[r][c] & 0xFF];
    }

    // ShiftRows: row r is cyclically shifted left by r bytes (diffusion step)
    private static void shiftRows(byte[][] state) {
        for (int r = 1; r < 4; r++) {
            byte[] row = state[r].clone();
            for (int c = 0; c < 4; c++) {
                state[r][c] = row[(c + r) % 4];
            }
        }
    }

    private static void invShiftRows(byte[][] state) {
        for (int r = 1; r < 4; r++) {
            byte[] row = state[r].clone();
            for (int c = 0; c < 4; c++) {
                state[r][c] = row[(c - r + 4) % 4];
            }
        }
    }

    // MixColumns: mix the 4 bytes of each column via a fixed matrix multiply in GF(2^8)
    private static void mixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            int a0 = state[0][c] & 0xFF, a1 = state[1][c] & 0xFF;
            int a2 = state[2][c] & 0xFF, a3 = state[3][c] & 0xFF;

            state[0][c] = (byte) (gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3);
            state[1][c] = (byte) (a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3);
            state[2][c] = (byte) (a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3));
            state[3][c] = (byte) (gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2));
        }
    }

    private static void invMixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            int a0 = state[0][c] & 0xFF, a1 = state[1][c] & 0xFF;
            int a2 = state[2][c] & 0xFF, a3 = state[3][c] & 0xFF;

            state[0][c] = (byte) (gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9));
            state[1][c] = (byte) (gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13));
            state[2][c] = (byte) (gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11));
            state[3][c] = (byte) (gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14));
        }
    }

    // ---------------------------------------------------------------
    // 5. SINGLE-BLOCK ENCRYPT / DECRYPT (16 bytes in, 16 bytes out)
    // ---------------------------------------------------------------
    public static byte[] encryptBlock(byte[] in, byte[] key) {
        if (in == null || in.length != 16) throw new IllegalArgumentException("AES block must be exactly 16 bytes");
        if (key == null || key.length != 16) throw new IllegalArgumentException("AES-128 key must be exactly 16 bytes");
        int[] w = keyExpansion(key);
        byte[][] state = bytesToState(in);

        addRoundKey(state, w, 0);

        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, w, round);
        }

        // Final round: no MixColumns
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, w, Nr);

        return stateToBytes(state);
    }

    public static byte[] decryptBlock(byte[] in, byte[] key) {
        if (in == null || in.length != 16) throw new IllegalArgumentException("AES block must be exactly 16 bytes");
        if (key == null || key.length != 16) throw new IllegalArgumentException("AES-128 key must be exactly 16 bytes");
        int[] w = keyExpansion(key);
        byte[][] state = bytesToState(in);

        addRoundKey(state, w, Nr);

        for (int round = Nr - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, w, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, w, 0);

        return stateToBytes(state);
    }

   

    // ---------------------------------------------------------------
    // 6. UTILITIES + DEMO / SELF-TEST
    // ---------------------------------------------------------------
    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /**
     * Program entry point.
     *
     * No arguments:
     *   1) Runs the FIPS-197 AES-128 known-answer test.
     *   2) Reads input.txt and writes output.txt using the simple file format
     *      described below.
     *
     * One argument ending in .rsp:
     *   Runs all KEY/PLAINTEXT/CIPHERTEXT records in a NIST AES KAT .rsp file.
     *
     * Two arguments:
     *   Treats args[0] as the input file and args[1] as the output file.
     *   The input file format is:
     *       KEY=000102030405060708090a0b0c0d0e0f
     *       PLAINTEXT=00112233445566778899aabbccddeeff
     *       EXPECTED=69c4e0d86a7b0430d8cdb78070b4c55a
     */
    public static void main(String[] args) throws IOException {
        if (args.length == 1 && args[0].toLowerCase().endsWith(".rsp")) {
            runNistKat(Paths.get(args[0]));
            return;
        }

        if (args.length == 2) {
            runFileTest(Paths.get(args[0]), Paths.get(args[1]));
            return;
        }

        if (args.length != 0) {
            System.out.println("Usage:");
            System.out.println("  java AES128");
            System.out.println("  java AES128 <nist-vector-file.rsp>");
            System.out.println("  java AES128 <input.txt> <output.txt>");
            return;
        }

        // -----------------------------------------------------------
        // 1. FIPS-197 AES-128 known-answer test
        // -----------------------------------------------------------
        String keyHex = "000102030405060708090a0b0c0d0e0f";
        String plaintextHex = "00112233445566778899aabbccddeeff";
        String expectedHex = "69c4e0d86a7b0430d8cdb78070b4c55a";

        byte[] key = hexToBytes(keyHex);
        byte[] plaintext = hexToBytes(plaintextHex);
        byte[] cipher = encryptBlock(plaintext, key);
        String actualHex = toHex(cipher);

        System.out.println("=== AES-128 Known Answer Test ===");
        System.out.println("Key       : " + keyHex);
        System.out.println("Plaintext : " + plaintextHex);
        System.out.println("Ciphertext: " + actualHex);
        System.out.println("Expected  : " + expectedHex);
        System.out.println("Result    : " + (actualHex.equalsIgnoreCase(expectedHex) ? "PASS" : "FAIL"));

        byte[] decrypted = decryptBlock(cipher, key);
        System.out.println("Round-trip: " +
                (Arrays.equals(plaintext, decrypted) ? "PASS" : "FAIL"));

        // -----------------------------------------------------------
        // 2. File input/output demonstration
        // -----------------------------------------------------------
        Path input = Paths.get("input.txt");
        Path output = Paths.get("output.txt");

        if (Files.exists(input)) {
            runFileTest(input, output);
        } else {
            System.out.println();
            System.out.println("No input.txt found; skipping file I/O test.");
            System.out.println("Create input.txt using the format documented above.");
        }
    }

    /**
     * Reads one simple AES test vector from a text file and writes the result.
     */
    private static void runFileTest(Path inputFile, Path outputFile) throws IOException {
        Map<String, String> values = new LinkedHashMap<>();

        for (String rawLine : Files.readAllLines(inputFile, StandardCharsets.UTF_8)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            int equals = line.indexOf('=');
            if (equals <= 0) continue;

            String name = line.substring(0, equals).trim().toUpperCase();
            String value = line.substring(equals + 1).trim();
            values.put(name, value);
        }

        String keyHex = requireHex(values, "KEY", 32);
        String plaintextHex = requireHex(values, "PLAINTEXT", 32);
        String expectedHex = values.get("EXPECTED");

        byte[] key = hexToBytes(keyHex);
        byte[] plaintext = hexToBytes(plaintextHex);
        String actualHex = toHex(encryptBlock(plaintext, key));

        boolean pass = expectedHex != null && actualHex.equalsIgnoreCase(expectedHex);

        StringBuilder result = new StringBuilder();
        result.append("AES-128 File Test\n");
        result.append("Key= ").append(keyHex).append('\n');
        result.append("Plaintext= ").append(plaintextHex).append('\n');
        result.append("Ciphertext= ").append(actualHex).append('\n');
        if (expectedHex != null) {
            result.append("Expected= ").append(expectedHex).append('\n');
            result.append("Result= ").append(pass ? "PASS" : "FAIL").append('\n');
        } else {
            result.append("Result=ENCRYPTED (no EXPECTED value supplied)\n");
        }

        Files.writeString(outputFile, result.toString(), StandardCharsets.UTF_8);
        System.out.println();
        System.out.println("File input : " + inputFile.toAbsolutePath());
        System.out.println("File output: " + outputFile.toAbsolutePath());
        System.out.println("File test  : " + (expectedHex == null ? "ENCRYPTED" : (pass ? "PASS" : "FAIL")));
    }

    /**
     * Reads NIST AES Known Answer Test .rsp files.
     * Each test case is identified by a line such as [COUNT = 0] and may
     * contain KEY, PLAINTEXT and CIPHERTEXT fields.  Only complete records
     * with all three fields are tested.
     */
    private static void runNistKat(Path rspFile) throws IOException {
        List<String> lines = Files.readAllLines(rspFile, StandardCharsets.UTF_8);

        String key = null;
        String plaintext = null;
        String ciphertext = null;
        int count = -1;
        int total = 0;
        int passed = 0;
        int skipped = 0;

        System.out.println("=== NIST AES Known Answer Test ===");
        System.out.println("File: " + rspFile.toAbsolutePath());

        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

  if (line.toUpperCase().startsWith("COUNT")) {

    if (key != null && plaintext != null && ciphertext != null) {
        boolean result = executeKatCase(count, key, plaintext, ciphertext);
        if (result) passed++;
        total++;
    }

    key = plaintext = ciphertext = null;
    count = parseCount(line);
    continue;
}

            int equals = line.indexOf('=');
            if (equals < 0) continue;

            String name = line.substring(0, equals).trim().toUpperCase();
            String value = line.substring(equals + 1).trim();

            switch (name) {
                case "KEY":
                    key = value;
                    break;
                case "PLAINTEXT":
                    plaintext = value;
                    break;
                case "CIPHERTEXT":
                    ciphertext = value;
                    break;
                default:
                    // Ignore unrelated NIST fields.
                    break;
            }
        }

        if (key != null || plaintext != null || ciphertext != null) {
            if (key != null && plaintext != null && ciphertext != null) {
                boolean result = executeKatCase(count, key, plaintext, ciphertext);
                if (result) passed++;
                total++;
            } else {
                skipped++;
            }
        }

        System.out.println();
        System.out.println("Tests run : " + total);
        System.out.println("Passed    : " + passed);
        System.out.println("Failed    : " + (total - passed));
        if (skipped > 0) System.out.println("Skipped   : " + skipped);
        System.out.println("Overall   : " + (total > 0 && passed == total ? "PASS" : "FAIL"));
    }

    private static boolean executeKatCase(int count, String keyHex,
                                          String plaintextHex, String expectedHex) {
        try {
            if (keyHex.length() != 32 || plaintextHex.length() != 32 || expectedHex.length() != 32) {
                return false;
            }

            byte[] key = hexToBytes(keyHex);
            byte[] plaintext = hexToBytes(plaintextHex);
            String actual = toHex(encryptBlock(plaintext, key));
            boolean pass = actual.equalsIgnoreCase(expectedHex);

            if (!pass) {
                System.out.println("FAIL: COUNT=" + count);
                System.out.println("  Key      = " + keyHex);
                System.out.println("  Plaintext= " + plaintextHex);
                System.out.println("  Expected = " + expectedHex);
                System.out.println("  Actual   = " + actual);
            }
            return pass;
        } catch (RuntimeException ex) {
            System.out.println("FAIL: COUNT=" + count + " (" + ex.getMessage() + ")");
            return false;
        }
    }

    private static int parseCount(String line) {
        int equals = line.indexOf('=');
        if (equals < 0) return -1;
        int close = line.indexOf(']', equals);
        if (close < 0) return -1;
        try {
            return Integer.parseInt(line.substring(equals + 1, close).trim());
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    private static String requireHex(Map<String, String> values, String name, int expectedLength) {
        String value = values.get(name);
        if (value == null || value.length() != expectedLength || !value.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException(
                    name + " must contain exactly " + expectedLength + " hexadecimal characters");
        }
        return value.toLowerCase();
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.trim();
        if ((hex.length() & 1) != 0 || !hex.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException("Invalid hexadecimal string");
        }

        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }
}