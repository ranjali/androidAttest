package com.thales.attest;

import static com.thales.attest.Util.bytesToHex;

import android.app.Activity;
import android.content.Context;
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

public class Attestation {
    public static String TAG = "att2";

    private static String CLIENT_DATA = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}";

    private static byte[] authData;

    private static byte[] clientDataHash;

    private static Signature signature;

    public static void test(FragmentActivity context) throws Exception {
        PublicKey key =  (PublicKey) Util.getKey(false);
        byte[] credentialPublicKeyCbor = createCredentialPublicKeyCbor(key);
        Util.logString(TAG, "credPubKey: " + bytesToHex(credentialPublicKeyCbor) );

        byte[] atData = constructAttestedCredentialData(key, credentialPublicKeyCbor);
        Util.logString(TAG, "atData: " + bytesToHex(atData) );

        authData = constructAuthenticatorData(context, atData);
        Util.logString(TAG, "authData: " + bytesToHex(authData) );

        clientDataHash = Util.sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8));
        Util.logString(TAG, "clientDataHash: " + bytesToHex(clientDataHash));

        authenticateAndSign(context);

//        constructWebAuthnCbor(authData, clientDataHash);
//        byte[] attest = constructWebAuthnCbor(Util.KEY_ALIAS, authData, clientDataHash);
//        String attestStr = bytesToHex(attest);
//        Util.logLongString("attest", attestStr);
    }

    public static byte[] createCredentialPublicKeyCbor(PublicKey rsaPublicKey) throws Exception {
        // Extract RSA public key components: modulus (n) and exponent (e)
        RSAPublicKeySpec rsaKeySpec = KeyFactory.getInstance("RSA").getKeySpec(rsaPublicKey, RSAPublicKeySpec.class);
        BigInteger modulus = rsaKeySpec.getModulus();
        BigInteger exponent = rsaKeySpec.getPublicExponent();

        // Convert modulus and exponent to byte arrays
        byte[] nBytes = Util.toUnsignedByteArray(modulus);
        byte[] eBytes = Util.toUnsignedByteArray(exponent);

        // Parse JSON into a Map
        Map<Integer, Object> data = new LinkedHashMap<>();
        data.put(1, 3);
        data.put(3, -37);
        data.put(-1, nBytes);
        data.put(-2, eBytes);

        CBORFactory cborFactory = new CBORFactory();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Create CBOR generator with fixed size start
        try (CBORGenerator cborGenerator = cborFactory.createGenerator(byteArrayOutputStream)) {
            // Write start object with size (fixed length)
            cborGenerator.writeStartObject(data.size()); // Pass the fixed length (map size)

            // Write key-value pairs to the CBOR object
            for (Map.Entry<Integer, Object> entry : data.entrySet()) {
                cborGenerator.writeFieldId(entry.getKey());
                cborGenerator.writeObject(entry.getValue());
            }

            // End the object
            cborGenerator.writeEndObject();
        }

        // Convert the updated Map to CBOR
        byte[] cborBytes = byteArrayOutputStream.toByteArray();

        return cborBytes;
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

    public static byte[] constructAuthenticatorData(Context context, byte[] credentialData) throws Exception {
        // 1. Retrieve the package name from the context
        String packageName = context.getPackageName();

        // 2. Compute rpIdHash (SHA-256 of the package name)
        byte[] rpIdHash = Util.sha256(packageName.getBytes());

        // 3. Flags (set to 0x45)
        byte flags = 0x45;

        // 4. Sign count (set to 0x00000000)
        byte[] signCount = ByteBuffer.allocate(4).putInt(0).array();

        // 5. Concatenate all parts to form authenticatorData
        ByteBuffer buffer = ByteBuffer.allocate(
                rpIdHash.length + 1 + signCount.length + credentialData.length
        );
        buffer.put(rpIdHash);         // rpIdHash (32 bytes)
        buffer.put(flags);           // Flags (1 byte)
        buffer.put(signCount);       // Sign Count (4 bytes)
        buffer.put(credentialData);  // Attested Credential Data (variable length)

        return buffer.array();
    }

    public static void authenticateAndSign(FragmentActivity context) {
        Executor executor = ContextCompat.getMainExecutor(context);

//        try {
//            // Load the Keystore and initialize the Signature
//            KeyStore keyStore = KeyStore.getInstance(Util.ANDROID_KEYSTORE);
//            keyStore.load(null);
//            PrivateKey privateKey = (PrivateKey) keyStore.getKey(Util.KEY_ALIAS, null);
//
//            signature = Signature.getInstance("SHA256withRSA/PSS");
//            signature.initSign(privateKey);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            return;
//        }

        // Attach the Signature to a CryptoObject
        BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);

        // Create the BiometricPrompt
        BiometricPrompt biometricPrompt = new BiometricPrompt(
                context,
                executor,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        try {
                            // Perform signing after authentication
                            constructWebAuthnCbor(result);
////                            byte[] signature = signData(dataToSign);
////                            System.out.println("Signature: " + bytesToHex(signature));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        System.err.println("Authentication error: " + errString);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        System.err.println("Authentication failed.");
                    }
                });

        // Create the PromptInfo
        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric Authentication Required")
                .setSubtitle("Authenticate to use your private key")
                .setNegativeButtonText("Cancel") // You can add a fallback button here
                .build();

        // Start the authentication process
        biometricPrompt.authenticate(promptInfo, cryptoObject);
    }

    public static void constructWebAuthnCbor(BiometricPrompt.AuthenticationResult result) throws Exception {
        // Load the Android Keystore
        KeyStore keyStore = KeyStore.getInstance(Util.ANDROID_KEYSTORE);
        keyStore.load(null);

        // Retrieve the certificate chain
        Certificate[] certificateChain = keyStore.getCertificateChain(Util.KEY_ALIAS);
        if (certificateChain == null || certificateChain.length == 0) {
            throw new IllegalStateException("Certificate chain is empty for alias: " + Util.KEY_ALIAS);
        }

        // Get the CryptoObject from the result
        Signature cryptoSignature = result.getCryptoObject().getSignature();

        // Update the data and sign
        cryptoSignature.update(authData);
        cryptoSignature.update(clientDataHash);
        byte[] signedData = cryptoSignature.sign();
        Util.logString(TAG, "sign: " + bytesToHex(signedData));

        // Convert x5c (certificate chain) to a list of DER-encoded certificates
        List<byte[]> x5cList = new ArrayList<>();
        for (Certificate cert : certificateChain) {
            byte[] certBytes = cert.getEncoded();
            x5cList.add(certBytes);
            Util.logString(TAG, "cert: " + bytesToHex(certBytes));
        }

        // Create attestation statement
        Map<String, Object> attStmt = new LinkedHashMap<>();
        attStmt.put("alg", -37); // RSA PSS (RSASSA-PSS using SHA-256, alg value -37 in COSE)
        attStmt.put("sig", signedData);
        attStmt.put("x5c", x5cList);

        // Create WebAuthn object
        Map<String, Object> webAuthnObject = new LinkedHashMap<>();
        webAuthnObject.put("fmt", "android-key");
        webAuthnObject.put("attStmt", attStmt);
        webAuthnObject.put("authData", authData);

        // Create CBOR factory and object mapper
        CBORFactory cborFactory = new CBORFactory();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Create CBOR generator
        try (CBORGenerator cborGenerator = cborFactory.createGenerator(byteArrayOutputStream)) {
            // Write start object without specifying size
            cborGenerator.writeStartObject(webAuthnObject.size());

            // Write simple key-value pairs
            for (Map.Entry<String, Object> entry : webAuthnObject.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                cborGenerator.writeFieldName(key);
                if (value instanceof Map) {
                    cborGenerator.writeStartObject(attStmt.size());
                    for (Map.Entry<String, Object> subEntry : ((Map<String, Object>) value).entrySet()) {
                        cborGenerator.writeFieldName(subEntry.getKey());
                        Object subValue = subEntry.getValue();
                        if (subValue instanceof List) {
                            List<byte[]> subValueList = (List<byte[]>) subValue;
                            // Handle nested array
                            cborGenerator.writeStartArray(new ArrayList<byte[]>(), subValueList.size());
                            for (byte[] x5cVal : subValueList) {
                                cborGenerator.writeBinary(x5cVal);
                            }
                            cborGenerator.writeEndArray();
                        } else {
                            cborGenerator.writeObject(subValue);
                        }
                    }
                    cborGenerator.writeEndObject();
                } else {
                    // Handle normal key-value pairs
                    cborGenerator.writeObject(value);
                }
            }

            // End the main object
            cborGenerator.writeEndObject();
        }

        // Output the CBOR encoded byte array
        byte[] cborBytes = byteArrayOutputStream.toByteArray();
        String attestStr = bytesToHex(cborBytes);
        Util.logLongString("attest", attestStr);
    }

}
