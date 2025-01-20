package com.thales.attest;

import android.content.Context;
import android.os.Build;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.verifier.CoreRegistrationObject;

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
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Attestation {
    public static String TAG = "att2";

    private static String CLIENT_DATA = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}";

    private static String CLIENT_DATA_SAMPLE = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}";

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

        try {
            webAuth4JParseCBOR_SAMPLE(context);
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
        attStmt.put("alg", -37); // RSA PSS (RSASSA-PSS using SHA-256, alg value -37 in COSE)
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

    public static void webAuth4JParseCBOR(byte[] attestationObjectBytes, byte[] clientDataHash, Context context) throws IOException {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();
        AttestationObject result = cborConverter.readValue(attestationObjectBytes, AttestationObject.class);
        CoreRegistrationObject registrationObject = new CoreRegistrationObject(result, attestationObjectBytes, clientDataHash, new CoreServerProperty(context.getPackageName(), new Challenge() {
            @Override
            public @NotNull byte[] getValue() {
                return CLIENT_DATA.getBytes(StandardCharsets.UTF_8);
            }
        }));
        LocalAndroidKeyAttestationStatementVerifier target = new LocalAndroidKeyAttestationStatementVerifier();
        target.verify(registrationObject);

        LocalAndroidKeyAttestationStatementVerifier2 target2 = new LocalAndroidKeyAttestationStatementVerifier2();
        target2.verify(registrationObject);
    }

    public static void webAuth4JParseCBOR_SAMPLE(Context context) throws IOException {
        String base64EncodedAttestationObject = "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";
        String base64EncodedClientDataHash = "eyJhcHBJbnN0YW5jZUlEIjoiMDVjNjY2YjYtYzgzMy00NmMyLWE0YWItNjMyMWZjM2NmZThjIiwidGltZVN0YW1wIjoiMjAyNC0xMS0yMlQxMjo1MDozMFoifQ==";

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedAttestationObject);
            byte[] decodedClientDataHash = Base64.getDecoder().decode(base64EncodedClientDataHash);
            ObjectConverter objectConverter = new ObjectConverter();
            CborConverter cborConverter = objectConverter.getCborConverter();
            AttestationObject result = cborConverter.readValue(decodedBytes, AttestationObject.class);
            CoreRegistrationObject registrationObject = new CoreRegistrationObject(result, decodedBytes, decodedClientDataHash, new CoreServerProperty("U_YoaLZuuHlF8UKMAK_eclG_EKE", new Challenge() {
                @Override
                public @NotNull byte[] getValue() {
                    return CLIENT_DATA_SAMPLE.getBytes(StandardCharsets.UTF_8);
                }
            }));
            LocalAndroidKeyAttestationStatementVerifier target = new LocalAndroidKeyAttestationStatementVerifier();
            target.verify(registrationObject);

            LocalAndroidKeyAttestationStatementVerifier2 target2 = new LocalAndroidKeyAttestationStatementVerifier2();
            target2.verify(registrationObject);
        }
    }


}
