package com.thales.attest;

import static com.google.android.attestation.Constants.GOOGLE_ROOT_CA_PUB_KEY;
import static com.google.android.attestation.ParsedAttestationRecord.createParsedAttestationRecord;

import android.content.Context;

import androidx.annotation.NonNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.google.android.attestation.AttestationApplicationId;
import com.google.android.attestation.AuthorizationList;
import com.google.android.attestation.CertificateRevocationStatus;
import com.google.android.attestation.CertificateRevocationStatusListener;
import com.google.android.attestation.ParsedAttestationRecord;
import com.google.android.attestation.RootOfTrust;
import com.google.protobuf.ByteString;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class Attestation {
    public static String TAG = "att2";

    private static String CLIENT_DATA = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}";

    public static void test(Context context) throws Exception {
        PublicKey key =  (PublicKey) Util.getKey(false);

        byte[] clientDataHash = Util.sha256(CLIENT_DATA.getBytes(StandardCharsets.UTF_8));
        Util.logString(TAG, "clientDataHash: " + Util.bytesToHex(clientDataHash));

//        parseAndVerifyAttestationExtensionData(Util.KEY_ALIAS);

        byte[] credentialPublicKeyCbor = createCredentialPublicKeyCbor(key);
        Util.logString(TAG, "credPubKey: " + Util.bytesToHex(credentialPublicKeyCbor) );

        byte[] atData = constructAttestedCredentialData(key, credentialPublicKeyCbor);
        Util.logString(TAG, "atData: " + Util.bytesToHex(atData) );

        byte[] authData = constructAuthenticatorData(context, atData);
        Util.logString(TAG, "authData: " + Util.bytesToHex(authData) );


        byte[] attest = constructWebAuthnCbor(Util.KEY_ALIAS, authData, clientDataHash);
        String attestStr = Util.bytesToHex(attest);
//        Util.logLongString("attest", attestStr);

        byte[] attestationObjectBytes = Util.hexToBytes(attestStr);

        /**
         * Parse CBOR Data
         */
        reverseCBORTest(attestationObjectBytes);

        List<X509Certificate> x509CertificateList = getCertificatesFromCBOR(attestationObjectBytes);
        /**
         * 1. Verify X509 certificate validity for each certificate
         * 2. Verify revocation status by checking serial number with list of revoked certificates
         *      https://android.googleapis.com/attestation/status
         * 3. If the attestation is trustworthy and the device ships with hardware-
         *          backed key attestation, Android 7.0 (API level 24) or higher, and
         *          Google Play services, the root certificate should be signed with the
         *          Google attestation root key.
         */
        try {
            verifyCertificateChainForValidityRevocationStatusRootOfTrust(x509CertificateList);
        } catch (InvalidKeyException | NoSuchProviderException | SignatureException e) {
            throw new RuntimeException(e);
        }

        //Verify certificate extension data
        parseAndVerifyAttestationExtensionData(x509CertificateList);

        //Verify attestationChallenge is equal to clientDataHash
        ParsedAttestationRecord parsedAttestationRecord = createParsedAttestationRecord(x509CertificateList);
        /// Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
        byte[] attestationChallenge = parsedAttestationRecord.attestationChallenge().toByteArray();
        // As attestationChallenge is known data to client side(potential attacker) because it is calculated from parts of a message,
        // there is no need to prevent timing attack and it is OK to use `Arrays.equals` instead of `MessageDigest.isEqual` here.
        if (!Arrays.equals(attestationChallenge, clientDataHash)) {
            System.out.println("Attestation challenge doesn't match.");
        }

        //verify authorization list
        verifyAuthorizationList(true, parsedAttestationRecord.softwareEnforced(), parsedAttestationRecord.teeEnforced());

        // Verify the certificate chain
        Certificate[] certificateChain = getCertificatesChainFromCBOR(attestationObjectBytes);
        if (verifyCertificateChain(certificateChain)) {
            System.out.println("Certificate chain is valid.");
        } else {
            System.out.println("Certificate chain is invalid.");
        }

        /**
         * Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
         *
         * using the public key in the first certificate in x5c with the algorithm specified in alg.
         */
        boolean signatureVerificationStatus = verifySignature(attestationObjectBytes, clientDataHash);
        Util.logString(TAG, "Verification status: " + signatureVerificationStatus);

        /**
         * Verify that the public key in the first certificate in x5c matches the
         *
         * credentialPublicKey in the attestedCredentialData in authenticatorData.
         */
        boolean verifyPublicKeyCredentialsData = verifyCredentialPublicKeyMatch(attestationObjectBytes);
        Util.logString(TAG, "Verify publicKey Credentials ddata: " + verifyPublicKeyCredentialsData);
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

    private static void parseAndVerifyAttestationExtensionData(List<X509Certificate> certs) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        ParsedAttestationRecord parsedAttestationRecord = createParsedAttestationRecord(certs);

        System.out.println("Attestation version: " + parsedAttestationRecord.attestationVersion());
        System.out.println(
                "Attestation Security Level: " + parsedAttestationRecord.attestationSecurityLevel().name());
        System.out.println("Keymaster Version: " + parsedAttestationRecord.keymasterVersion());
        System.out.println(
                "Keymaster Security Level: " + parsedAttestationRecord.keymasterSecurityLevel().name());
        //Util.bytesToHex(parsedAttestationRecord.attestationChallenge().toByteArray()) should be equal to clientDataHash
        System.out.println(
                "Attestation Challenge: " + parsedAttestationRecord.attestationChallenge().toStringUtf8());
        System.out.println(
                "Unique ID: " + Arrays.toString(parsedAttestationRecord.uniqueId().toByteArray()));

        System.out.println("Software Enforced Authorization List:");
        AuthorizationList softwareEnforced = parsedAttestationRecord.softwareEnforced();
        printAuthorizationList(softwareEnforced, "\t");

        System.out.println("TEE Enforced Authorization List:");
        AuthorizationList teeEnforced = parsedAttestationRecord.teeEnforced();
        printAuthorizationList(teeEnforced, "\t");
    }

    private static void verifyAuthorizationList(boolean teeEnforcedOnly, AuthorizationList softwareEnforced, AuthorizationList teeEnforced) throws Exception {
        /// For the following,
        /// use only the teeEnforced authorization list if the RP wants to accept only keys
        /// from a trusted execution environment,
        if (teeEnforcedOnly) {
            /// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
            /// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
            if(!(teeEnforced.origin().isPresent() && teeEnforced.origin().get().name().equals("GENERATED"))){
                throw new Exception("Key is not generated in keymaster.");
            }
            if(!(!teeEnforced.purpose().asList().isEmpty() && teeEnforced.purpose().asList().get(0).name().equals("SIGN"))) {
                throw new Exception("Key purpose is invalid.");
            }
        }
        /// otherwise use the union of teeEnforced and softwareEnforced.
        else {
            /// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
            /// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
            if(!(softwareEnforced.origin().isPresent() && softwareEnforced.origin().get().name().equals("GENERATED")) &&
                    !(teeEnforced.origin().isPresent() && teeEnforced.origin().get().name().equals("GENERATED"))){
                throw new Exception("Key is not generated in keymaster.");
            }

            if( !(!softwareEnforced.purpose().asList().isEmpty() && softwareEnforced.purpose().asList().get(0).name().equals("SIGN")) &&
                    !(!teeEnforced.purpose().asList().isEmpty() && teeEnforced.purpose().asList().get(0).name().equals("SIGN"))) {
                throw new Exception("Key purpose is invalid.");
            }
        }
    }


    public static void reverseCBORTest(byte[] cborData) throws Exception {
        // Create CBOR factory and object mapper
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper objectMapper = new ObjectMapper(cborFactory);

        // Parse CBOR byte array into a Java Map (can also map to specific classes)
        Map<String, Object> parsedWebAuthnObject = objectMapper.readValue(new ByteArrayInputStream(cborData), Map.class);

        // Extract data from the parsed map
        String fmt = (String) parsedWebAuthnObject.get("fmt");
        Map<String, Object> attStmt = (Map<String, Object>) parsedWebAuthnObject.get("attStmt");
        byte[] authData = (byte[]) parsedWebAuthnObject.get("authData");

        // Extract attStmt fields
        Integer alg = (Integer) attStmt.get("alg");
        byte[] sig = (byte[]) attStmt.get("sig");
        List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");

        // Print the parsed information
        System.out.println("fmt: " + fmt);
        System.out.println("alg: " + alg);
        System.out.println("sig: " + Util.bytesToHex(sig));
        System.out.println("x5c size: " + x5c.size());
        System.out.println("authData: " + Util.bytesToHex(authData));

        // If you need to print or process the certificate chain (x5c)
        for (byte[] certBytes : x5c) {
            System.out.println("Certificate: " + Util.bytesToHex(certBytes));
        }

        // Reconstruct the certificate chain from the byte arrays in x5c
        Certificate[] certificateChain = getCertificateChainFromBytes(x5c);

        // Print out the certificate chain
        for (Certificate cert : certificateChain) {
            X509Certificate x509Cert = (X509Certificate) cert;
            System.out.println("Certificate Subject: " + x509Cert.getSubjectDN());
            System.out.println("Certificate Issuer: " + x509Cert.getIssuerDN());
            System.out.println("Certificate Serial Number: " + x509Cert.getSerialNumber());
        }

        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate cert:certificateChain) {
            if(cert instanceof  X509Certificate){
                certs.add((X509Certificate) cert);
            }
        }
    }

    private static void verifyCertificateChainForValidityRevocationStatusRootOfTrust(List<X509Certificate> certs)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, IOException {
        X509Certificate parent = certs.get(certs.size() - 1);
        for (int i = certs.size() - 1; i >= 0; i--) {
            X509Certificate cert = certs.get(i);
            // Verify that the certificate has not expired.
            cert.checkValidity();
            cert.verify(parent.getPublicKey());
            parent = cert;

            //For each certificate in the certificate chain, check revocation status
            ThreadUtils.getBackgroundThreadExecutor().execute(() -> CertificateRevocationStatus.fetchStatus(cert.getSerialNumber(), ThreadUtils.wrapD1TaskCallbackInMainThread(new CertificateRevocationStatusListener(){
                @Override
                public void onSuccess(CertificateRevocationStatus data) {
                    if (data != null) {
                        System.out.println("Certificate revocation status is " + data.status.name());
                    }
                }
                @Override
                public void onError(@NonNull Exception e) {
                    System.out.println(e.getMessage());
                }
            })));
        }

        // If the attestation is trustworthy and the device ships with hardware-
        // backed key attestation, Android 7.0 (API level 24) or higher, and
        // Google Play services, the root certificate should be signed with the
        // Google attestation root key.
        byte[] googleRootCaPubKey = Base64.getDecoder().decode(GOOGLE_ROOT_CA_PUB_KEY);
        if (Arrays.equals(
                googleRootCaPubKey,
                certs.get(certs.size() - 1).getPublicKey().getEncoded())) {
            System.out.println(
                    "The root certificate is correct, so this attestation is trustworthy, as long as none of"
                            + " the certificates in the chain have been revoked.");
        } else {
            System.out.println(
                    "The root certificate is NOT correct. The attestation was probably generated by"
                            + " software, not in secure hardware. This means that there is no guarantee that the"
                            + " claims within the attestation are correct. If you're using a production-level"
                            + " system, you should disregard any claims made within this attestation certificate"
                            + " as there is no authority backing them up.");
        }
    }

    // Verify the returned certificate chain
    public static boolean verifyCertificateChain(Certificate[] certificateChain) {
        try {
            // Start from the last certificate (root) and move backward
            for (int i = certificateChain.length - 1; i > 0; i--) {
                X509Certificate currentCert = (X509Certificate) certificateChain[i];
                X509Certificate previousCert = (X509Certificate) certificateChain[i - 1];

                // Verify current certificate's signature using the previous certificate's public key
                previousCert.verify(currentCert.getPublicKey());
                System.out.println("Certificate " + i + " correctly signs the previous certificate.");
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean verifySignature(byte[] cborData, byte[] clientDataHash) throws Exception {
        Map<String, Object> webAuthnObject = parseCbor(cborData);

        // Extract fields from the CBOR object
        byte[] authenticatorData = (byte[]) webAuthnObject.get("authData");
        Map<String, Object> attStmt = (Map<String, Object>) webAuthnObject.get("attStmt");
        List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");
        byte[] signature = (byte[]) attStmt.get("sig");
        int alg = (int) attStmt.get("alg");

        // Step 1: Concatenate authenticatorData and clientDataHash
        ByteArrayOutputStream dataToVerify = new ByteArrayOutputStream();
        dataToVerify.write(authenticatorData);
        dataToVerify.write(clientDataHash);
        byte[] dataForSignatureVerification = dataToVerify.toByteArray();

        // Step 2: Extract the public key from the first certificate in x5c
        PublicKey publicKey = extractPublicKeyFromCertificate(x5c.get(0));
        // Step 3: Initialize the signature verifier based on the algorithm
        Signature signatureVerifier = Signature.getInstance("SHA256withRSA/PSS");
        signatureVerifier.initVerify(publicKey);
        signatureVerifier.update(dataForSignatureVerification);

        // Step 4: Verify the signature
        return signatureVerifier.verify(signature);
    }

    public static boolean verifyCredentialPublicKeyMatch(byte[] cborData) throws Exception {
        // Parse the CBOR data to get the WebAuthn object
        Map<String, Object> webAuthnObject = parseCbor(cborData);

        // Extract fields from the CBOR object
        byte[] authenticatorData = (byte[]) webAuthnObject.get("authData");
        Map<String, Object> attStmt = (Map<String, Object>) webAuthnObject.get("attStmt");
        List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");

        byte[] extractedPublicKeyDataFromAuthenticationData = extractPublicKeyFromAuthenticatorData(authenticatorData);

        // Extract public key from the first certificate in x5c
        PublicKey publicKey = extractPublicKeyFromCertificate(x5c.get(0));

        // Log the extracted credential public key from authenticatorData for debugging
        System.out.println("Public key from authenticator data: " + Util.bytesToHex(extractedPublicKeyDataFromAuthenticationData));

        RSAPublicKey publicKeyFromCbor = extractPublicKeyFromCbor(extractedPublicKeyDataFromAuthenticationData);

        // Compare the modulus and exponent of both keys
        boolean match =  publicKeyFromCbor.getModulus().equals(((RSAPublicKey) publicKey).getModulus()) &&
                publicKeyFromCbor.getPublicExponent().equals(((RSAPublicKey) publicKey).getPublicExponent());
        // Log the result for debugging
        System.out.println("Public key match: " + match);

        return match;
    }

    public static Map<String, Object> parseCbor(byte[] cborData) throws IOException {
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper objectMapper = new ObjectMapper(cborFactory);
        return objectMapper.readValue(cborData, Map.class);
    }

    // Helper method to convert a list of byte arrays (x5c) into a certificate chain (Certificate[])
    public static Certificate[] getCertificateChainFromBytes(List<byte[]> x5c) throws Exception {
        // Initialize the CertificateFactory for X.509 certificates
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        // Create a list to hold the certificates
        Certificate[] certificateChain = new Certificate[x5c.size()];

        // Convert each byte array into a certificate
        for (int i = 0; i < x5c.size(); i++) {
            byte[] certBytes = x5c.get(i);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certBytes);
            certificateChain[i] = certFactory.generateCertificate(byteArrayInputStream);
        }

        return certificateChain;
    }

    public static PublicKey extractPublicKeyFromCertificate(byte[] certBytes) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream certStream = new ByteArrayInputStream(certBytes);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certStream);
        return certificate.getPublicKey();
    }

    // Method to extract the public key from Authenticator Data
    public static byte[] extractPublicKeyFromAuthenticatorData(byte[] authenticatorData) throws Exception {
        // 1. Extract the rpIdHash (32 bytes) and skip it
        int rpIdHashLength = 32;  // SHA-256 hash length (rpIdHash)
        int flagsLength = 1;      // flags length
        int signCountLength = 4;  // signCount length

        ByteBuffer buffer = ByteBuffer.wrap(authenticatorData);

        // Skip rpIdHash, flags, and signCount
        buffer.position(rpIdHashLength + flagsLength + signCountLength);

        // 2. Read the Attested Credential Data (this will be the remaining part of the buffer)
        byte[] attestedCredentialData = new byte[buffer.remaining()];
        buffer.get(attestedCredentialData);

        // 3. Parse Attested Credential Data
        ByteBuffer attestedBuffer = ByteBuffer.wrap(attestedCredentialData);

        // Skip AAGUID (16 bytes)
        byte[] aaguid = new byte[16];
        attestedBuffer.get(aaguid);

        // Skip the Credential ID Length (2 bytes)
        byte[] credentialIdShort = new byte[2];
        attestedBuffer.get(credentialIdShort); // This will be the length of the Credential ID (2 bytes)

        // Skip the Credential ID (its length is given by the 2-byte Credential ID Length)
        short credentialIdLength = ByteBuffer.wrap(credentialIdShort).getShort();// Get the length of the Credential ID
        byte[] credentialId = new byte[credentialIdLength];
        attestedBuffer.get(credentialId);

        // The remaining part of the Attested Credential Data is the Credential Public Key
        byte[] credentialPublicKey = new byte[attestedBuffer.remaining()];
        attestedBuffer.get(credentialPublicKey);

        // Return the extracted public key bytes
        return credentialPublicKey;
    }

    // Method to decode CBOR and extract the raw RSA public key
    public static RSAPublicKey extractPublicKeyFromCbor(byte[] cborData) throws Exception {
        CBORFactory cborFactory = new CBORFactory();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(cborData);

        // Use ObjectMapper to parse the CBOR data into a JsonNode
        ObjectMapper objectMapper = new ObjectMapper(cborFactory);
        JsonNode rootNode = objectMapper.readTree(byteArrayInputStream);

        // Extract the modulus (n) and exponent (e) from the CBOR structure
        byte[] modulusBytes = rootNode.get("-1").binaryValue();
        byte[] exponentBytes = rootNode.get("-2").binaryValue();

        // Convert the modulus and exponent into BigInteger
        BigInteger modulus = new BigInteger(1, modulusBytes);  // 1 for unsigned BigInteger
        BigInteger exponent = new BigInteger(1, exponentBytes);  // 1 for unsigned BigInteger

        // Create and return the RSAPublicKey
        RSAPublicKey rsaPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(modulus, exponent)
        );

        return rsaPublicKey;
    }

    private static List<X509Certificate> getCertificatesFromCBOR(byte[] attestationObjectBytes) throws Exception {
        Map<String, Object> webAuthnObject = parseCbor(attestationObjectBytes);
        // Extract fields from the CBOR object
        byte[] authenticatorData = (byte[]) webAuthnObject.get("authData");
        Map<String, Object> attStmt = (Map<String, Object>) webAuthnObject.get("attStmt");
        List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");
        // Reconstruct the certificate chain from the byte arrays in x5c
        Certificate[] certificateChain = getCertificateChainFromBytes(x5c);

        // Print out the certificate chain
        for (Certificate cert : certificateChain) {
            X509Certificate x509Cert = (X509Certificate) cert;
            System.out.println("Certificate Subject: " + x509Cert.getSubjectDN());
            System.out.println("Certificate Issuer: " + x509Cert.getIssuerDN());
            System.out.println("Certificate Serial Number: " + x509Cert.getSerialNumber());
        }

        List<X509Certificate> certs = new ArrayList<>();
        for (Certificate cert:certificateChain) {
            if(cert instanceof  X509Certificate){
                certs.add((X509Certificate) cert);
            }
        }
        return certs;
    }

    private static Certificate[] getCertificatesChainFromCBOR(byte[] attestationObjectBytes) throws Exception {
        Map<String, Object> webAuthnObject = parseCbor(attestationObjectBytes);
        // Extract fields from the CBOR object
        byte[] authenticatorData = (byte[]) webAuthnObject.get("authData");
        Map<String, Object> attStmt = (Map<String, Object>) webAuthnObject.get("attStmt");
        List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");
        // Reconstruct the certificate chain from the byte arrays in x5c
        Certificate[] certificateChain = getCertificateChainFromBytes(x5c);

        // Print out the certificate chain
        for (Certificate cert : certificateChain) {
            X509Certificate x509Cert = (X509Certificate) cert;
            System.out.println("Certificate Subject: " + x509Cert.getSubjectDN());
            System.out.println("Certificate Issuer: " + x509Cert.getIssuerDN());
            System.out.println("Certificate Serial Number: " + x509Cert.getSerialNumber());
        }

        return certificateChain;
    }

    private static void printAuthorizationList(AuthorizationList authorizationList, String indent) {
        // Detailed explanation of the keys and their values can be found here:
        // https://source.android.com/security/keystore/tags
        print(authorizationList.purpose(), indent + "Purpose(s)");
        print(authorizationList.algorithm(), indent + "Algorithm");
        print(authorizationList.keySize(), indent + "Key Size");
        print(authorizationList.digest(), indent + "Digest");
        print(authorizationList.padding(), indent + "Padding");
        print(authorizationList.ecCurve(), indent + "EC Curve");
        print(authorizationList.rsaPublicExponent(), indent + "RSA Public Exponent");
        System.out.println(indent + "Rollback Resistance: " + authorizationList.rollbackResistance());
        print(authorizationList.activeDateTime(), indent + "Active DateTime");
        print(authorizationList.originationExpireDateTime(), indent + "Origination Expire DateTime");
        print(authorizationList.usageExpireDateTime(), indent + "Usage Expire DateTime");
        System.out.println(indent + "No Auth Required: " + authorizationList.noAuthRequired());
        print(authorizationList.userAuthType(), indent + "User Auth Type");
        print(authorizationList.authTimeout(), indent + "Auth Timeout");
        System.out.println(indent + "Allow While On Body: " + authorizationList.allowWhileOnBody());
        System.out.println(
                indent
                        + "Trusted User Presence Required: "
                        + authorizationList.trustedUserPresenceRequired());
        System.out.println(
                indent
                        + "Trusted Confirmation Required: "
                        + authorizationList.trustedConfirmationRequired());
        System.out.println(
                indent + "Unlocked Device Required: " + authorizationList.unlockedDeviceRequired());
        print(authorizationList.creationDateTime(), indent + "Creation DateTime");
        print(authorizationList.origin(), indent + "Origin");
        authorizationList
                .rootOfTrust()
                .ifPresent(
                        rootOfTrust -> {
                            System.out.println(indent + "Root Of Trust:");
                            print(rootOfTrust, indent + "\t");
                        });
        print(authorizationList.osVersion(), indent + "OS Version");
        print(authorizationList.osPatchLevel(), indent + "OS Patch Level");
        authorizationList
                .attestationApplicationId()
                .ifPresent(
                        attestationApplicationId -> {
                            System.out.println(indent + "Attestation Application ID:");
                            print(attestationApplicationId, indent + "\t");
                        });
        print(authorizationList.attestationIdBrand(), indent + "Attestation ID Brand");
        print(authorizationList.attestationIdDevice(), indent + "Attestation ID Device");
        print(authorizationList.attestationIdProduct(), indent + "Attestation ID Product");
        print(authorizationList.attestationIdSerial(), indent + "Attestation ID Serial");
        print(authorizationList.attestationIdImei(), indent + "Attestation ID IMEI");
        print(authorizationList.attestationIdSecondImei(), indent + "Attestation ID SECOND IMEI");
        print(authorizationList.attestationIdMeid(), indent + "Attestation ID MEID");
        print(authorizationList.attestationIdManufacturer(), indent + "Attestation ID Manufacturer");
        print(authorizationList.attestationIdModel(), indent + "Attestation ID Model");
        print(authorizationList.vendorPatchLevel(), indent + "Vendor Patch Level");
        print(authorizationList.bootPatchLevel(), indent + "Boot Patch Level");
    }

    private static void print(RootOfTrust rootOfTrust, String indent) {
        System.out.println(
                indent
                        + "Verified Boot Key: "
                        + Base64.getEncoder().encodeToString(rootOfTrust.verifiedBootKey().toByteArray()));
        System.out.println(indent + "Device Locked: " + rootOfTrust.deviceLocked());
        System.out.println(indent + "Verified Boot State: " + rootOfTrust.verifiedBootState().name());
        rootOfTrust.verifiedBootHash().ifPresent(
                verifiedBootHash ->
                        System.out.println(
                                indent
                                        + "Verified Boot Hash: "
                                        + Base64.getEncoder().encodeToString(verifiedBootHash.toByteArray())));
    }

    private static void print(AttestationApplicationId attestationApplicationId, String indent) {
        System.out.println(indent + "Package Infos (<package name>, <version>): ");
        for (AttestationApplicationId.AttestationPackageInfo info : attestationApplicationId.packageInfos()) {
            System.out.println(indent + "\t" + info.packageName() + ", " + info.version());
        }
        System.out.println(indent + "Signature Digests:");
        for (ByteString digest : attestationApplicationId.signatureDigests()) {
            System.out.println(indent + "\t" + Base64.getEncoder().encodeToString(digest.toByteArray()));
        }
    }

    private static <T> void print(Optional<T> optional, String caption) {
        if (optional.isPresent()) {
            if (optional.get() instanceof byte[]) {
                System.out.println(
                        caption + ": " + Base64.getEncoder().encodeToString((byte[]) optional.get()));
            } else {
                System.out.println(caption + ": " + optional.get());
            }
        }
    }

    private static <T> void print(Set<T> set, String caption) {
        if (!set.isEmpty()) {
            System.out.println(caption + ": " + set);
        }
    }
}
