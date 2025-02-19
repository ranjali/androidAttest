package com.thales.attest;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

public class Util {

    public static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    public static final String KEY_ALIAS = "alias2";

    public static final String KEY_ALIAS_MASTERCARD = "alias3";

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

    public static String getAppSigningKey(Context context) {
        try {
            // Get the PackageManager and package info
            PackageManager packageManager = context.getPackageManager();
            String packageName = context.getPackageName();
            PackageInfo packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);

            // Extract the signing certificate
            return bytesToHex(sha256(packageInfo.signatures[0].toByteArray()));

        } catch (Exception e) {
            Log.e("AppSignatureUtils", "Error retrieving app signing key", e);
            return null;
        }
    }

    public static Key getKey(boolean isPrivate) throws Exception {
        if (!checkKeyExists(KEY_ALIAS)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    .setAttestationChallenge(sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8)))
//                    .setUserAuthenticationRequired(true)
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

    public static Key generateECDSAKeyPair(boolean isPrivate) throws Exception {
        if (!checkKeyExists(KEY_ALIAS_MASTERCARD)) {
            // Create the KeyPairGenerator instance for ECDSA using the Keystore provider
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);

            // Define the KeyGenParameterSpec for the key pair
            KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_ALIAS_MASTERCARD, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    // Only permit the private key to be used if the user authenticated
                    .setAttestationChallenge(sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8)))
                    .build();

            // Initialize the key generator with the specified parameters
            keyPairGenerator.initialize(keyGenParameterSpec);

            // Generate the key pair
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Extract public and private keys
            PublicKey publicKey = keyPair.getPublic();

            // Display the public key in Base64 format for example
            String publicKeyBase64 = Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
            Log.d("Util", "Public Key (Base64): " + publicKeyBase64);
            return publicKey;
        } else {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            if (isPrivate) {
                return keyStore.getKey(KEY_ALIAS_MASTERCARD, null);
            }
            return keyStore.getCertificate(KEY_ALIAS_MASTERCARD).getPublicKey();
        }
    }

    public static String prepareDeviceCertificate(byte[] devicePublicKey) {
        return "-----BEGIN CERTIFICATE-----\n" +
                Base64.encodeToString(devicePublicKey,Base64.DEFAULT)
                + "\n-----END CERTIFICATE-----";
    }

    // Function to construct Attested Credential Data
    public static byte[] constructAttestedCredentialData(PublicKey publicKey, byte[] credentialPublicKey) throws Exception {
        // Compute the credentialId as the SHA-256 hash of the encoded publicKey
        byte[] credentialId = Util.sha256(publicKey.getEncoded());

        // AAGUID is set to 16 bytes of 0
        byte[] aaguid = new byte[16];

        // Credential ID length (2 bytes)
        short credentialIdLength = (short) credentialId.length;
        ByteBuffer credentialIdLengthBuffer = ByteBuffer.allocate(2);
        credentialIdLengthBuffer.putShort(credentialIdLength);
        byte[] credentialIdLengthBytes = credentialIdLengthBuffer.array();

        // Construct the Attested Credential Data
        ByteBuffer buffer = ByteBuffer.allocate(16 + 2 + credentialId.length + credentialPublicKey.length);
        buffer.put(aaguid);                // AAGUID (16 bytes)
        buffer.put(credentialIdLengthBytes); // Credential ID length (2 bytes)
        buffer.put(credentialId);          // Credential ID (32 bytes, derived from SHA-256 of the publicKey)
        buffer.put(credentialPublicKey); // Credential Public Key (encoded form of the publicKey)

        return buffer.array();
    }
}
