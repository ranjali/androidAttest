package com.thales.attest;

import android.content.Context;
import android.util.Log;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

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

public class Attestation {
    public static String TAG = "att2";

    private static String CLIENT_DATA = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}";

    public static void test(Context context) throws Exception {
        PublicKey key =  (PublicKey) Util.getKey(false);
        byte[] credentialPublicKeyCbor = createCredentialPublicKeyCbor(key);
        Log.d(TAG, "credPubKey: " + Util.bytesToHex(credentialPublicKeyCbor) );

        byte[] atData = constructAttestedCredentialData(key, credentialPublicKeyCbor);
        Log.d(TAG, "atData: " + Util.bytesToHex(atData) );

        byte[] authData = constructAuthenticatorData(context, atData);
        Log.d(TAG, "authData: " + Util.bytesToHex(authData) );

        byte[] clientDataHash = Util.sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8));
        byte[] attest = constructWebAuthnCbor(Util.KEY_ALIAS, authData, clientDataHash);
        String attestStr = Util.bytesToHex(attest);
        Util.logLongString("attest", attestStr);
    }

    public static byte[] createCredentialPublicKeyCbor(PublicKey rsaPublicKey) throws Exception {
        // Extract RSA public key components: modulus (n) and exponent (e)
        RSAPublicKeySpec rsaKeySpec = KeyFactory.getInstance("RSA").getKeySpec(rsaPublicKey, RSAPublicKeySpec.class);
        BigInteger modulus = rsaKeySpec.getModulus();
        BigInteger exponent = rsaKeySpec.getPublicExponent();

        // Convert modulus and exponent to byte arrays
        byte[] nBytes = modulus.toByteArray();
        byte[] eBytes = exponent.toByteArray();

        // Parse JSON into a Map
        Map<Integer, Object> data = new LinkedHashMap<>();
        data.put(1, 3);
        data.put(3, -37);
        data.put(-1, nBytes);
        data.put(-2, eBytes);

        // Create an ObjectMapper for CBOR
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());

        // Convert the updated Map to CBOR
        byte[] cborBytes = cborMapper.writeValueAsBytes(data);

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
        ByteBuffer buffer = ByteBuffer.allocate(16 + 2 + credentialId.length + publicKey.getEncoded().length);
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

    public static byte[] constructWebAuthnCbor(String alias, byte[] authenticatorData, byte[] clientDataHash) throws Exception {
        // Load the Android Keystore
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        // Retrieve the private key and public key using the alias
        PrivateKey privateKey = (PrivateKey) Util.getKey(true);

        // Retrieve the certificate chain
        Certificate[] certificateChain = keyStore.getCertificateChain(alias);
        if (certificateChain == null || certificateChain.length == 0) {
            throw new IllegalStateException("Certificate chain is empty for alias: " + alias);
        }

        // Perform RSA signature using SHA-256 with PSS padding
        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        signature.initSign(privateKey);
        signature.update(authenticatorData);
        signature.update(clientDataHash);
        byte[] signedData = signature.sign();

        // Convert x5c (certificate chain) to a list of DER-encoded certificates
        List<byte[]> x5cList = new ArrayList<>();
        for (Certificate cert : certificateChain) {
            x5cList.add(cert.getEncoded());
        }

        // CBOR factory and mapper
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper cborMapper = new ObjectMapper(cborFactory);

        // Create attestation statement
        Map<String, Object> attStmt = new LinkedHashMap<>();
        attStmt.put("alg", -37); // RSA PSS (RSASSA-PSS using SHA-256, alg value -37 in COSE)
        attStmt.put("sig", signedData);
        attStmt.put("x5c", x5cList);

        // Create WebAuthn object
        Map<String, Object> webAuthnObject = new LinkedHashMap<>();
        webAuthnObject.put("fmt", "android-key");
        webAuthnObject.put("attStmt", attStmt);
        webAuthnObject.put("authData", authenticatorData);

        // Serialize to CBOR
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (JsonGenerator generator = cborFactory.createGenerator(outputStream)) {
            cborMapper.writeValue(generator, webAuthnObject);
        }

        return outputStream.toByteArray();
    }

}
