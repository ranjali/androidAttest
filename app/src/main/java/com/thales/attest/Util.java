package com.thales.attest;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

public class Util {

    public static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    public static final String KEY_ALIAS = "alias2";

    private static String CLIENT_DATA = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}";

    public static byte[] toUnsignedByteArray(BigInteger bigInt) {
        byte[] byteArray = bigInt.toByteArray();
        if (byteArray[0] == 0x00 && byteArray.length > 1) {
            // Remove the leading sign byte
            return Arrays.copyOfRange(byteArray, 1, byteArray.length);
        }
        return byteArray;
    }

    public static void logLongString(String tag, String longString) {
        final int maxLogLength = 4000; // Logcat's maximum string length
        for (int i = 0; i < longString.length(); i += maxLogLength) {
            int end = Math.min(longString.length(), i + maxLogLength);
            Log.d(tag, longString.substring(i, end));
        }
    }

    public static void logString(String tag, String str) {
        Log.d(tag, str);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] sha256(byte[] data) throws Exception {
        // Compute SHA-256 hash of the public key bytes
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);  // Returns 32-byte SHA-256 hash of the public key
    }

    public static boolean checkKeyExists(String alias) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
        //We get the Keystore instance
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        return keyStore.containsAlias(alias);
    }

    public static Key getKey(boolean isPrivate) throws Exception {
        if (!checkKeyExists(KEY_ALIAS)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    .setAttestationChallenge(sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8)))
                    .setUserAuthenticationRequired(true)
                    ;

            kpg.initialize(builder.build());
            KeyPair keyPair = kpg.genKeyPair();
            return isPrivate ? keyPair.getPrivate() : keyPair.getPublic();
        } else {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            if (isPrivate) {
                return keyStore.getKey(KEY_ALIAS, null);
            }
            return keyStore.getCertificate(KEY_ALIAS).getPublicKey();
        }
    }
}
