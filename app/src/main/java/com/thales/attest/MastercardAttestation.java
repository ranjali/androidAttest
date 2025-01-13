package com.thales.attest;

import android.content.Context;
import android.security.keystore.KeyProperties;
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
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class MastercardAttestation {

    public static String TAG = "att2_Mastercard";

    private static String CLIENT_DATA = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}";


    public static void test(Context context) throws Exception {
        Util.getAppSigningKey(context);
        PublicKey key =  (PublicKey) Util.generateECDSAKeyPair(false);
        byte[] credentialPublicKeyCbor = createCredentialPublicKeyCbor(key);
        Log.d(TAG, "credPubKey: " + Util.bytesToHex(credentialPublicKeyCbor) );

        Util.logLongString(TAG,"credPubKey Hex( "+Util.bytesToHex(credentialPublicKeyCbor)+" )");

        byte[] atData = Util.constructAttestedCredentialData(key, credentialPublicKeyCbor);
        Log.d(TAG, "atData: " + Util.bytesToHex(atData) );

        Util.logLongString(TAG,"atData Hex( "+Util.bytesToHex(atData)+" )");

        byte[] authData = constructAuthenticatorData(context, atData);
        Log.d(TAG, "authData: " + Util.bytesToHex(authData) );

        Util.logLongString(TAG,"authData Hex( "+Util.bytesToHex(authData)+" )");

        byte[] clientDataHash = Util.sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8));
        byte[] attest = constructWebAuthnCbor(Util.KEY_ALIAS_MASTERCARD, authData, clientDataHash);
        String attestStr = Util.bytesToHex(attest);
        Util.logLongString("attest", attestStr);

        Util.logLongString(TAG, "attest Hex( "+attestStr+" )");

        byte[] assertion = constructAssertionData(context);
        byte[] assertionArray = constructAssertionWebAuthnCbor(Util.KEY_ALIAS_MASTERCARD,assertion,clientDataHash);
        String assertionStr = Util.bytesToHex(assertionArray);
        Util.logLongString("assertionObject", assertionStr);

    }

    public static byte[] createCredentialPublicKeyCbor(PublicKey ecdsaPublicKey) throws Exception {
        // Extract ECDSA public key components: modulus (n) and exponent (e)
        ECPublicKeySpec ecdsaKeySpec = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).getKeySpec(ecdsaPublicKey, ECPublicKeySpec.class);
        BigInteger modulus = ecdsaKeySpec.getW().getAffineX();
        BigInteger exponent = ecdsaKeySpec.getW().getAffineY();

        // Convert modulus and exponent to byte arrays
        byte[] nBytes = modulus.toByteArray();
        byte[] eBytes = exponent.toByteArray();

        // Parse JSON into a Map
        Map<Integer, Object> data = new LinkedHashMap<>();
        data.put(1, 2);
        data.put(3, -7);
        data.put(-1, 1);
        data.put(-2, nBytes);
        data.put(-3, eBytes);

        // Create an ObjectMapper for CBOR
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());

        // Convert the updated Map to CBOR
        byte[] cborBytes = cborMapper.writeValueAsBytes(data);

        return cborBytes;
    }

    public static byte[] constructAssertionData(Context context) {

        byte[] rpIdHash;
        byte flag = 0x5;
        byte[] signCount;
        signCount = ByteBuffer.allocate(4).putInt(1).array();
        String packageName = context.getPackageName();
        try {
            rpIdHash =  Util.sha256(packageName.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // RpIdHash 16 bytes + flags 1 byte + SignCount 4 bytes
        ByteBuffer byteBuffer = ByteBuffer.allocate(rpIdHash.length + 1 + 4);
        byteBuffer.put(rpIdHash);
        byteBuffer.put(flag);
        byteBuffer.put(signCount);

        return byteBuffer.array();

    }


    // Function to construct Attested Credential Data


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


    public static byte[] constructAssertionWebAuthnCbor(String alias, byte[] authenticatorData, byte[] clientDataHash) throws Exception {
        // Load the Android Keystore
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        // Retrieve the private key and public key using the alias
        PrivateKey privateKey = (PrivateKey) Util.generateECDSAKeyPair(true);

        // Retrieve the certificate chain
        Certificate[] certificateChain = keyStore.getCertificateChain(alias);
        if (certificateChain == null || certificateChain.length == 0) {
            throw new IllegalStateException("Certificate chain is empty for alias: " + alias);
        }

        // Perform ECDSA signature using SHA-256 with PSS padding
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(clientDataHash);
        byte[] signedData = signature.sign();

        // CBOR factory and mapper
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper cborMapper = new ObjectMapper(cborFactory);


        // Create WebAuthn object
        Map<String, Object> webAuthnObject = new LinkedHashMap<>();

        webAuthnObject.put("signature", signedData);
        webAuthnObject.put("authenticatorData", authenticatorData);

        // Serialize to CBOR
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (JsonGenerator generator = cborFactory.createGenerator(outputStream)) {
            cborMapper.writeValue(generator, webAuthnObject);
        }

        return outputStream.toByteArray();
    }

    public static byte[] constructWebAuthnCbor(String alias, byte[] authenticatorData, byte[] clientDataHash) throws Exception {
        // Load the Android Keystore
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        // Retrieve the private key and public key using the alias
        PrivateKey privateKey = (PrivateKey) Util.generateECDSAKeyPair(true);

        // Retrieve the certificate chain
        Certificate[] certificateChain = keyStore.getCertificateChain(alias);
        if (certificateChain == null || certificateChain.length == 0) {
            throw new IllegalStateException("Certificate chain is empty for alias: " + alias);
        }

        // Perform ECDSA signature using SHA-256 with PSS padding
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(authenticatorData);
        signature.update(clientDataHash);
        byte[] signedData = signature.sign();

        Util.logLongString(TAG, "Signed Data Hex( "+Util.bytesToHex(signedData)+" )");
        // Convert x5c (certificate chain) to a list of DER-encoded certificates
        List<byte[]> x5cList = new ArrayList<>();
        for (Certificate cert : certificateChain) {
            String certificate = Util.prepareDeviceCertificate(cert.getEncoded());
            Util.logLongString("x5c:",certificate);
            x5cList.add(cert.getEncoded());
        }

        // CBOR factory and mapper
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper cborMapper = new ObjectMapper(cborFactory);

        // Create attestation statement
        Map<String, Object> attStmt = new LinkedHashMap<>();
        attStmt.put("alg", -7); // ECDSA PSS (ECDSA-PSS using SHA-256, alg value -37 in COSE)
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
