package crypt;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;


/**
 * Created by yuzhiqiang on 16/8/19.
 */
public class EncryptUtil {
    private static int RandomStringSize = 20;

    //加密
    public static String encryptData(String content) throws Exception {
        //base64编码
        String encryptStr = encodeBase64(content.getBytes());
        //生成随机字符串
        String randString = getRandomString();
        //加密，并将加密之后的byte数字用base64编码
        encryptStr = encrypt(encryptStr, randString.substring(0, 16));
        //拼接
        encryptStr = randString + encryptStr;
        //base64编码
        encryptStr = encodeBase64(encryptStr.getBytes());
        return encryptStr;
    }

    //解密
    public static String decryptData(String encryptStr) {
        if (encryptStr.isEmpty()) {
            return encryptStr;
        }
        try {
            //base64解码
            byte[] content = decodeBase64(encryptStr);
            //获取aes密钥
            String key = new String(content).substring(0, 16);
            //获取aes密文
            encryptStr = new String(content).substring(20, new String(content).length());
            //对encryptStr进行base64解码后，解密
            String result = decrypt(encryptStr,key);
            //base64解密
            result = new String(decodeBase64(result));
            return result;
        } catch (IllegalArgumentException e) {
            return encryptStr;
        }
    }

    private static String encodeBase64(byte[] content) {
        return Base64.encodeBase64String(content);
    }

    private static byte[] decodeBase64(String encryptContent) {
        return Base64.decodeBase64(encryptContent);
    }

    private static String getRandomString() {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < RandomStringSize; i++) {
            int num = random.nextInt(62);
            buf.append(str.charAt(num));
        }
        return buf.toString();
    }


    private static String encrypt(String sSrc, String sKey) throws Exception {
        byte[] raw = sKey.getBytes("utf-8");
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        byte[] AES_KEY = sKey.getBytes();
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(AES_KEY));
        byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));
        return encodeBase64(encrypted);
    }


    private static String decrypt(String sSrc, String sKey) {
        try {
            byte[] raw = sKey.getBytes("utf-8");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            byte[] AES_KEY = sKey.getBytes();
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(AES_KEY));
            byte[] encrypted1 = decodeBase64(sSrc);//先用base64解密
            try {
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original, "utf-8");
                return originalString;
            } catch (Exception e) {
                System.out.println(e.toString());
                return null;
            }
        } catch (Exception ex) {
            System.out.println(ex.toString());
            return null;
        }
    }
}
