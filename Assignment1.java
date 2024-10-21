package cryptography.assignment;

import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.file.*;
import java.util.Arrays;

public class Assignment1 {

    private static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        while (!exp.equals(BigInteger.ZERO)) {
            if (exp.testBit(0)) {
                result = result.multiply(base).mod(mod);
            }
            base = base.multiply(base).mod(mod);
            exp = exp.shiftRight(1);
        }
        return result;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // Custom padding as per the assignment instructions
    private static byte[] addPadding(byte[] data) {
        int blockSize = 16;
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
        paddedData[data.length] = (byte) 0x80;  // 1-bit represented by 0x80 in hex
        // Remaining padding is zero-filled
        for (int i = data.length + 1; i < paddedData.length; i++) {
            paddedData[i] = 0x00;
        }
        return paddedData;
    }

    // Remove custom padding
    private static byte[] removePadding(byte[] data) {
        int i = data.length - 1;
        while (i >= 0 && data[i] == 0x00) {
            i--;
        }
        if (data[i] == (byte) 0x80) {
            return Arrays.copyOf(data, i);
        }
        return data;  // No padding found
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("Filename expected as argument.");
        }

        Path classFilePath = Paths.get(args[0]);
        Path txtDir = Paths.get("txt");
        if (!Files.exists(txtDir)) {
            Files.createDirectories(txtDir);
        }

        // Prime p and generator g as provided
        BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
        BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);

        // Generate secret value b
        SecureRandom random = new SecureRandom();
        BigInteger b = new BigInteger(1023, random);
        BigInteger B = modExp(g, b, p); // B = g^b % p
        BigInteger s = modExp(A, b, p); // Shared secret s = A^b % p

        // Convert shared secret to byte array
        byte[] sBytes = s.toByteArray();
        if (sBytes[0] == 0) {
            sBytes = Arrays.copyOfRange(sBytes, 1, sBytes.length); // Remove leading zero if present
        }

        // Derive AES key using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] aesKey = sha256.digest(sBytes);
        
        // Generate random IV
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        // Initialize AES cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt class file data
        cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, ivSpec);
        byte[] classFileData = Files.readAllBytes(classFilePath);
        byte[] paddedData = addPadding(classFileData);
        byte[] encryptedData = cipher.doFinal(paddedData);

        // Decrypt to verify
        cipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivSpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        byte[] originalData = removePadding(decryptedData);

        // Write outputs to files
        Files.write(txtDir.resolve("DH.txt"), B.toString(16).getBytes());
        Files.write(txtDir.resolve("IV.txt"), bytesToHex(iv).getBytes());
        Files.write(txtDir.resolve("Encryption.txt"), bytesToHex(encryptedData).getBytes());

        // Output to console for verification
        System.out.println("Private Key (b): " + b.toString(16) + "\n");
        System.out.println("Shared Secret (s): " + s.toString(16) + "\n");
        System.out.println("AES Key: " + bytesToHex(aesKey) + "\n");
        System.out.println("IV: " + bytesToHex(iv) + "\n");
        System.out.println("Decrypted Data Matches Original: " + Arrays.equals(classFileData, originalData) + "\n");
    }
}
