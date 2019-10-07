import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Scanner;
import java.nio.ByteBuffer;
import java.nio.file.*;

public class Receiver {

    private static int BUFFER_SIZE = 32 * 1024;
    public static String symmetricKey;
    public static byte[] symmetricBytes;
    public static PublicKey XpubKey;
    public static byte[] digSig;


    public static void main(String[] args) throws Exception {
        // Step 1:
        // Copy X Public key and symmetric key into Receiver folder (Done)

        // Step 2:
        // Read X Public key and symmetric key
        XpubKey = readPubKeyFromFile("XPublic.key");
        symmetricKey = keyToUTF8("symmetric.key");

        // Step 3:
        // Get output file name from user
        Scanner scan = new Scanner(System.in);
        String messageFile;
        System.out.println("Input the name of the output message file: ");
        messageFile = scan.nextLine();

        // Step 4:
        // Read file and decrypt using symmetric key and AES decryption
        byte[] decPlaintextBytes = aesDecrypt("message.aescipher");

        // Step 5:
        // Parse digital signature and message from decrypted file
        // Save message to user specified message file
        byte[] digSig = parseDecryptedMsg(
                "/Users/dominicklicciardi/Documents/Security_Projects/Project1/Sender/message.ds-msg", messageFile);
        // Decrypt digital signature using X Public key with RSA
        rsaDecrypt(digSig);

        // Step 6:
        // Hash message using SHA256 and and compare digital digests
        verifySha256(messageFile, "message.dd");
    }

    static byte[] trim(byte[] bytes) {
        int i = bytes.length - 1;
        while (i >= 0 && bytes[i] == 0)
            --i;
        return Arrays.copyOf(bytes, i );
    }

    public static String keyToUTF8(String fileName) throws IOException {
        System.out.println("Symmetric.key string for AES En(): ");
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = br.readLine();
            }
            symmetricKey = sb.toString();
            System.out.print(symmetricKey);
            return sb.toString();
        } finally {
            br.close();
            System.out.println("128-bit UTF-8 encoding of Symmetric.key for AES: ");
            symmetricBytes = symmetricKey.getBytes("UTF-8");
            symmetricBytes = trim(symmetricBytes);
            for (byte x: symmetricBytes) {
                System.out.print(x + " ");
            }
            System.out.println("\n");
        }
    }

    public static byte[] aesDecrypt(String encryptedFile) throws Exception {
        // Reading file as bytes
        byte[] cipherBytes = fileStringToByteArray(encryptedFile);
        System.out.println("file: " + cipherBytes);
        byte[] iv = new byte[16];
        String IV = "AAAAAAAAAAAAAAAA"; // do not need for AES/ECB/PKCS5Padding mode
        //Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symmetricBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(iv));
        PrintWriter ds_out = new PrintWriter("message.ds-out");
        byte[] plainBytes = cipher.doFinal(cipherBytes);

        //System.out.println(cipherText);
        System.out.print("cipherBytes:  \n");
        for (int i = 0, j = 0; i < cipherBytes.length; i++, j++) {
            System.out.format("%02X ", cipherBytes[i]);
            //ds_out.format("%02X ", cipherBytes[i]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }

        String plainText = new String(plainBytes);

        System.out.println("\nDecrypted bytes: \n" + plainText);
        ds_out.format(plainText);
        ds_out.close();
        return plainBytes;
    }

    public static byte[] parseDecryptedMsg(String dsMsgFname, String msgOutFname) throws IOException {
        // Single byte = "XX ", 3 chararacters * 128 [- final space]
        int dsSize = 128 * 3;

        // Read file as string
        // Path dsMsgPath = Paths.get(dsMsgFname);
        BufferedReader br = new BufferedReader(new FileReader(dsMsgFname));
        StringBuilder sb = new StringBuilder();
        String line = br.readLine();
        sb.append(line);
        String ds_msg = sb.toString();

        System.out.println("****");
        System.out.println(ds_msg);
        System.out.println("****");
        // String ds_msg = new String(Files.readString(dsMsgPath));

        // Get first 128 bytes (without space) as string
        String digSigString = ds_msg.substring(0, dsSize - 1);
        // Get remaining bytes as message less final character (extra '\n')
        String messageString = ds_msg.substring(dsSize, ds_msg.length());

        // Convert digital signature string to bytes
        byte[] digSigBytes = stringToByteArray(digSigString);

        // Write out message to user specified file
        PrintWriter msg_out = new PrintWriter(msgOutFname);
        msg_out.format(messageString);
        msg_out.close();

        // Return digital signature in bytes
        return digSigBytes;
    }

    public static void rsaDecrypt(byte[] digSig) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, XpubKey);
        byte[] digDigest = cipher.doFinal(digSig);

        PrintWriter dd_out = new PrintWriter("message.dd");

        System.out.println("Digital digest received:\n");
        for (int i = 0, j = 0; i < digDigest.length; i++, j++) {
            System.out.format("%02X ", digDigest[i]);
            dd_out.format("%02X ", digDigest[i]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
        dd_out.close();
        System.out.println("");
    }

    public static void verifySha256(String messageFile, String ddFile) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(messageFile));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, md);
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            i = in.read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        md = in.getMessageDigest();
        in.close();

        byte[] hashCreated = md.digest();
        byte[] digestReceived = fileStringToByteArray(ddFile);

        System.out.println("Hash of decrypted message:\n");
        printBytes(hashCreated);

        if (Arrays.equals(hashCreated, digestReceived)) {
            System.out.println("\nDigital digests match. Message integrity confirmed.\n");
        } else {
            System.out.println("\nWARNING: Digital digests do not match. Message integrity may be compromised.\n");
        }

    }

    public static void printBytes(byte[] byteArr) throws Exception {
        for (int i = 0, j = 0; i < byteArr.length; i++, j++) {
            System.out.format("%02X ", byteArr[i]);
            if (j >= 15) {
                System.out.println("");
                j = -1;
            }
        }
    }

    public static byte[] fileStringToByteArray(String fname) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(fname));
        String str = br.readLine();

        return stringToByteArray(str);
    }

    public static byte[] stringToByteArray(String str) throws IOException {
        String[] splitText = str.split("\\s+");
        int byteInt;
        byte[] byteArr = new byte[splitText.length];
        for (int i = 0; i < splitText.length; i++) {
            byteInt = Integer.parseInt(splitText[i], 16);
            byteArr[i] = (byte) byteInt;
        }
        return byteArr;
    }

    public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {

        InputStream in =
                new FileInputStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
}
