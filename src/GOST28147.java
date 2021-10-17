import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

class GOST28147 {
    //final private byte[] key;
    public static byte[] key_hash;
    public static String message = "";
    public static String ciphered_message = "";
    public static IvParameterSpec iv;

    public static void main(String[] args) {
        //byte[] key_hash;
        //String message;
        for (int i = 0; i < args.length; ++i) {
            switch (args[i]) {
                case "-k" -> {
                    if (!args[i+1].isBlank())
                        key_hash = hashKey(args[++i]);
                    else {
                        System.out.println("Error: Invalid key");
                        return;
                    }
                }
                case "-m" -> {
                    message = args[++i];
                    if (message.length() < 64) {
                        int l = message.length();
                        for (int j = 0; j < 64 - l; ++j) {
                            message += " ";
                        }
                    }
                }
                default -> {
                    System.out.println("Error: Invalid parameter key");
                    return;
                }
            }
        }
        if (message.isBlank()) {
            System.out.println("Error: Invalid message");
            return;
        }
        System.out.printf("Message: %s\n", message);
        ciphered_message = encrypt();
        System.out.printf("Cipher: %s\n", ciphered_message);
        System.out.printf("Decrypted: %s\n", decrypt());
    }


    public static byte[] hashKey(String key) {
        byte[] result;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(key.getBytes());
            result = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            result = "Error".getBytes(StandardCharsets.UTF_8);
        }
        return result;
    }

    public static String encrypt() {
        String result;
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(key_hash, "GOST28147");
            Cipher cipher = Cipher.getInstance("GOST28147/ECB/NoPadding", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            result = Base64.getEncoder().encodeToString(encrypted);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            result = "Error";
        }
        return result;
    }

    public static String decrypt() {
        String result;
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(key_hash, "GOST28147");
            Cipher cipher = Cipher.getInstance("GOST28147/ECB/NoPadding", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphered_message));
            result = new String(decrypted);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            result = "Error";
        }
        return result;
    }
}