import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Assignment1 {
    // Prime modulus p (1024-bit prime)
    private static final BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
    // Generator g
    private static final BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
    // Public shared value A
    private static final BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java Assignment1 <input_file>");
            return;
        }

        // Step 1: Generate 1023-bit random integer b
        SecureRandom random = new SecureRandom();
        BigInteger b = new BigInteger(1023, random);

        // Step 2: Calculate B = g^b (mod p)
        BigInteger B = squareAndMultiply(g, b, p);

        // Step 3: Calculate the shared secret s = A^b (mod p)
        BigInteger s = squareAndMultiply(A, b, p);

        // Step 4: Derive AES key k by hashing the shared secret s with SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] k = sha256.digest(s.toByteArray());

        // Log the generated keys and shared secrets
        System.out.println("Secret value b: " + b.toString(16));
        System.out.println("Public value B: " + B.toString(16));
        System.out.println("Shared secret s: " + s.toString(16));
        System.out.println("AES key k (SHA-256 digest of s): " + bytesToHex(k));

        // Step 5: Generate random 128-bit IV
        byte[] iv = new byte[16]; // 128-bit IV
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        System.out.println("IV: " + bytesToHex(iv));

        // Step 6: Perform AES encryption in CBC mode with NoPadding (custom padding added later)
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(k, "AES"), ivSpec);

        // Step 7: Read input file and pad it manually
        byte[] inputFileBytes = Files.readAllBytes(Paths.get(args[0]));
        byte[] paddedInput = applyCustomPadding(inputFileBytes, 16);

        // Encrypt the padded input
        byte[] encrypted = cipher.doFinal(paddedInput);

        // Step 8: Create the folder "txt" and save files
        Path folderPath = Paths.get("txt");
        if (!Files.exists(folderPath)) {
            Files.createDirectory(folderPath);
        }

        // Write DH.txt (public value B)
        Files.write(Paths.get("txt/DH.txt"), B.toString(16).getBytes());

        // Write IV.txt (IV in hexadecimal)
        Files.write(Paths.get("txt/IV.txt"), bytesToHex(iv).getBytes());

        // Write Encryption.txt (encrypted class file in hexadecimal)
        Files.write(Paths.get("txt/Encryption.txt"), bytesToHex(encrypted).getBytes());

        // Step 9: Write the original message (padded) to plaintext.txt
        Files.write(Paths.get("txt/plaintext.txt"), inputFileBytes);

        System.out.println("Encryption successful. Files saved to 'txt' folder.");

        // Print OpenSSL command for verification
        System.out.println("\nTo verify encryption using OpenSSL, run the following command:\n");
        System.out.println("openssl enc -aes-256-cbc -K " + bytesToHex(k) + " -iv " + bytesToHex(iv) + " -in txt/plaintext.txt -out openssl_encrypted.bin");
        System.out.println("xxd -p -c 1000000 openssl_encrypted.bin > correct.txt");
    }

    // Custom padding method according to the assignment's specification
    public static byte[] applyCustomPadding(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];

        System.arraycopy(data, 0, paddedData, 0, data.length);
        paddedData[data.length] = (byte) 0x80; // Append 1-bit as 0x80 (10000000 in binary)

        // Remaining bytes are already 0 (default initialized as 0)
        return paddedData;
    }

    // Square and multiply method for modular exponentiation
    public static BigInteger squareAndMultiply(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        String binary = exponent.toString(2);
        for (int i = 0; i < binary.length(); i++) {
            result = result.multiply(result).mod(modulus);
            if (binary.charAt(i) == '1') {
                result = result.multiply(base).mod(modulus);
            }
        }
        return result;
    }

    // Helper method to convert byte array to hexadecimal string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
