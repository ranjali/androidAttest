package com.thales.attest;

import android.content.Context;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import com.google.protobuf.ByteString;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;

import org.jetbrains.annotations.NotNull;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
        Util.logString(TAG, "credPubKey: " + Util.bytesToHex(credentialPublicKeyCbor) );

        byte[] atData = constructAttestedCredentialData(key, credentialPublicKeyCbor);
        Util.logString(TAG, "atData: " + Util.bytesToHex(atData) );

        byte[] authData = constructAuthenticatorData(context, atData);
        Util.logString(TAG, "authData: " + Util.bytesToHex(authData) );

        byte[] clientDataHash = Util.sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8));
        Util.logString(TAG, "clientDataHash: " + Util.bytesToHex(clientDataHash));
        byte[] attest = constructWebAuthnCbor(Util.KEY_ALIAS, authData, clientDataHash);
        String attestStr = Util.bytesToHex(attest);

//        Util.logLongString("attest", attestStr);

        try {
            webAuth4JParseCBOR(attest, clientDataHash, context);
        } catch (IOException e) {
            System.out.println(e);
        }
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
        Util.logString(TAG, "sign: " + Util.bytesToHex(signedData));

        // Convert x5c (certificate chain) to a list of DER-encoded certificates
        List<byte[]> x5cList = new ArrayList<>();
        for (Certificate cert : certificateChain) {
            byte[] certBytes = cert.getEncoded();
            x5cList.add(certBytes);
            Util.logString(TAG, "cert: " + Util.bytesToHex(certBytes));
        }

        // Create attestation statement
        Map<String, Object> attStmt = new LinkedHashMap<>();
        attStmt.put("alg", -257); // RSA PSS (RSASSA-PSS using SHA-256, alg value -37 in COSE)
        attStmt.put("sig", signedData);
        attStmt.put("x5c", x5cList);

        // Create WebAuthn object
        Map<String, Object> webAuthnObject = new LinkedHashMap<>();
        webAuthnObject.put("fmt", "android-key");
        webAuthnObject.put("attStmt", attStmt);
        webAuthnObject.put("authData", authenticatorData);

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
        return byteArrayOutputStream.toByteArray();
    }

    public static void webAuth4JParseCBOR(byte[] cborData, byte[] clientDataHash, Context context) throws IOException {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();
        //When
        AttestationObject result = cborConverter.readValue(cborData, AttestationObject.class);
        int a = 0;

        CoreRegistrationObject registrationObject = new CoreRegistrationObject(result, cborData, clientDataHash, new CoreServerProperty(context.getPackageName(), new Challenge() {
            @Override
            public @NotNull byte[] getValue() {
                return CLIENT_DATA.getBytes(StandardCharsets.UTF_8);
            }
        }));
        LocalAndroidKeyAttestationStatementVerifier target = new LocalAndroidKeyAttestationStatementVerifier();
        target.verify(registrationObject);
    }

}
