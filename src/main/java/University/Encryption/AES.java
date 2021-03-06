package University.Encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import static University.Info.MailInfo.AES_ALG;

public class AES {


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String encryptAES(String content, String password) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, UnsupportedEncodingException {
        byte[] textBytes = content.getBytes(StandardCharsets.UTF_8);

        SecretKey key = getSecretKeyFromPassword(password);

        Cipher aesCipher;
        aesCipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedText = aesCipher.doFinal(textBytes);

        return Base64.getEncoder().encodeToString(encryptedText);
    }

    public static String decryptAES(String encContent, String password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        byte[] textBytes = Base64.getDecoder().decode(encContent);

        SecretKey key = getSecretKeyFromPassword(password);

        Cipher aesCipher;

        aesCipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

        aesCipher.init(Cipher.DECRYPT_MODE, key);

        byte[] textDecrypted = aesCipher.doFinal(textBytes);
        return new String(textDecrypted, StandardCharsets.UTF_8);
    }

    private static SecretKey getSecretKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
//        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
//        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(AES_ALG);

//        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//        KeySpec spec = new PBEKeySpec(password.toCharArray());
//        SecretKey tmp = factory.generateSecret(spec);

        MessageDigest digester = MessageDigest.getInstance("MD5");
        for (int i = 0; i < password.toCharArray().length; i++) {
            digester.update((byte) password.toCharArray()[i]);
        }
        byte[] passwordData = digester.digest();


        return new SecretKeySpec(passwordData, "AES");
    }

}
