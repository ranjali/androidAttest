package com.thales.attest;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.appattest.DeviceCheckManager;
import com.webauthn4j.appattest.converter.jackson.DeviceCheckCBORModule;
import com.webauthn4j.appattest.data.DCAttestationData;
import com.webauthn4j.appattest.data.DCAttestationParameters;
import com.webauthn4j.appattest.data.DCAttestationRequest;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.exception.VerificationException;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

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

    private static byte[] base64ToBytes(String val) {
        return Base64.decode(val, Base64.DEFAULT);
    }
    public static void verifyIosAttestation() {
        // Client properties
        byte[] keyId = base64ToBytes("NQC6+7zLTfC5h9uVv9XjYcYomJVniFpNK8+fHwo4XTM="); /* set keyId */
        byte[] attestationObject = base64ToBytes("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"); /* set attestationObject */
        byte[] challenge = "{\"appInstanceID\":\"05c666b6-c833-46c2-a4ab-6321fc3cfe8c\",\"timeStamp\":\"2024-11-22T12:50:30Z\"}".getBytes(Charset.defaultCharset()); /* set challenge */
        byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(challenge);

// Server properties
        String teamIdentifier = "LMY4YJ949Q" /* set teamIdentifier */;
        String cfBundleIdentifier = "com.thales.appattest2" /* set cfBundleIdentifier */;
        DCServerProperty dcServerProperty = new DCServerProperty(teamIdentifier, cfBundleIdentifier, new DefaultChallenge(challenge));

        DCAttestationRequest dcAttestationRequest = new DCAttestationRequest(keyId, attestationObject, clientDataHash);
        DCAttestationParameters dcAttestationParameters = new DCAttestationParameters(dcServerProperty);
        DCAttestationData dcAttestationData;
        DeviceCheckManager deviceCheckManager = DeviceCheckManager.createNonStrictDeviceCheckManager();
        deviceCheckManager.getAttestationDataValidator().setProduction(false);
        try {
            dcAttestationData = deviceCheckManager.parse(dcAttestationRequest);
        } catch (DataConversionException e) {
            // If you would like to handle Apple App Attest data structure parse error, please catch DataConversionException
            throw e;
        }
        try {
            DCAttestationData attestationData = deviceCheckManager.validate(dcAttestationData, dcAttestationParameters);
            int a = 111;
        } catch (VerificationException e) {
            // If you would like to handle Apple App Attest data validation error, please catch VerificationException
            Log.e("web4j", "error: " + e);
            throw e;
        }
    }

    public static Challenge createChallenge() {
        UUID uuid = UUID.randomUUID();
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        byte[] challengeValue = ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
        return new DefaultChallenge(challengeValue);
    }

    public static ServerProperty createServerProperty() {
        return createServerProperty(createChallenge());
    }

    public static Origin createOrigin() {
        return new Origin("https://localhost:8080");
    }

    public static ServerProperty createServerProperty(Challenge challenge) {
        return new ServerProperty(createOrigin(), "example.com", challenge, new byte[32]);
    }

    public static RegistrationObject createRegistrationObjectWithAndroidKeyAttestation() {
        ObjectMapper jsonMapper = new ObjectMapper();
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerModule(new DeviceCheckCBORModule());
        ObjectConverter objectConverter = new ObjectConverter(jsonMapper, cborMapper);
        CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);

        byte[] collectedClientDataBytes = Base64UrlUtil.decode("eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJjaGFsbGVuZ2UiOiJ2MmgxYzJWeWJtRnRaWFEwYVY5T2JUUm9iakZEZUVrd1NHYzNPSGh6VFdsamFHRnNiR1Z1WjJWUXR1YkVEQzRPU3BHSGViSExMTmVyRmY4IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9");
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(collectedClientDataBytes);

        byte[] attestationObjectBytes = Base64UrlUtil.decode("o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYSDBGAiEAl0EDZokwnDApmVkWnSc24ELfZCI-Fx3s7K6YLM-W-xACIQCHvO-RPrqBSVV8rHYlWvRUt-UXpwRc4NQPBnVZ6k9CGGN4NWOCWQMEMIIDADCCAqegAwIBAgIBATAKBggqhkjOPQQDAjCBzjFFMEMGA1UEAww8RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBGQUtFMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMCAXDTcwMDIwMTAwMDAwMFoYDzIwOTkwMTMxMjM1OTU5WjApMScwJQYDVQQDDB5GQUtFIEFuZHJvaWQgS2V5c3RvcmUgS2V5IEZBS0UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQsOMT5hyL6rg0c9ilM8skJWRYWTG4vpnP2MpS9aOeYzxkCOREmADn0fEDOqrk0EqMoY2RE_NOgN8jqAlHtgFiRo4IBFjCCARIwCwYDVR0PBAQDAgeAMIHhBgorBgEEAdZ5AgERBIHSMIHPAgECCgEAAgEBCgEABCAhLBhI9_zUhPMmw_wgGYR4IbEhgriX50b2mPD1DoesJgQAMGm_hT0IAgYBXtPjz6C_hUVZBFcwVTEvMC0EKGNvbS5hbmRyb2lkLmtleXN0b3JlLmFuZHJvaWRrZXlzdG9yZWRlbW8CAQExIgQgdM_LUHSI9SkQhZHHpQWRnzJ3MvvB2ANSauqYAAbS2JgwMqEFMQMCAQKiAwIBA6MEAgIBAKUFMQMCAQSqAwIBAb-DeAMCAQK_hT4DAgEAv4U_AgUAMB8GA1UdIwQYMBaAFFKaGzLgVqrNUQ_vX4A3BovykSMdMAoGCCqGSM49BAMCA0cAMEQCIAgOX0m5-z0iFe-5iG049P5hmYwJ70PsC1gYvsQyL7SOAiA2cqK2McZgFvnoiGURFVEXR69LKX1gogUaO9IJZhR8TlkC7jCCAuowggKRoAMCAQICAQIwCgYIKoZIzj0EAwIwgcYxPTA7BgNVBAMMNEZBS0UgQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290IEZBS0UxMTAvBgkqhkiG9w0BCQEWImNvbmZvcm1hbmNlLXRvb2xzQGZpZG9hbGxpYW5jZS5vcmcxFjAUBgNVBAoMDUZJRE8gQWxsaWFuY2UxDDAKBgNVBAsMA0NXRzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYDVQQHDAlXYWtlZmllbGQwHhcNMTgwNTA5MTIzMTQ0WhcNNDUwOTI0MTIzMTQ0WjCBzjFFMEMGA1UEAww8RkFLRSBBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZSBGQUtFMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq1BhK2JNF7vDtRsESTsFSQuMH4udvPN5st7coHxSode2DdMhddwrft28JtsI1V-G9nG2lNwwTaSiioxOA6b1x6NmMGQwEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0OBBYEFKPSqizvDYzyJALVHLRgvL9qWyQUMB8GA1UdIwQYMBaAFFKaGzLgVqrNUQ_vX4A3BovykSMdMAoGCCqGSM49BAMCA0cAMEQCIGndnqPxgftCSjmtGgrfudLjM9eG_rlFYFX6PcyZeLnSAiA-0w-m9wa1VukUJCqwZvKHE92SOLyW1xhdBV8yF1SlFmhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAARlUOS1SqR0CfmpUat2wTATEAIHEiziyGohCFUc_hJJZGdtSu9ThnEb74K6NZC3U-KbwgpQECAyYgASFYICw4xPmHIvquDRz2KUzyyQlZFhZMbi-mc_YylL1o55jPIlggGQI5ESYAOfR8QM6quTQSoyhjZET806A3yOoCUe2AWJE");
        AttestationObject attestationObject = attestationObjectConverter.convert(attestationObjectBytes);
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> authenticationExtensionsClientOutputs = new AuthenticationExtensionsClientOutputs<>();
        return new RegistrationObject(attestationObject, attestationObjectBytes, collectedClientData, collectedClientDataBytes, authenticationExtensionsClientOutputs, transports, createServerProperty());
    }

    public static void verifyAndroidAttestation(byte[] sig) throws Exception {
//        // Load the Android Keystore
//        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
//        keyStore.load(null);
//
//        // Retrieve the private key and public key using the alias
//        PrivateKey privateKey = (PrivateKey) Util.getKey(true);

        // Retrieve the certificate chain
//        X509Certificate[] certificateChain = (X509Certificate[]) keyStore.getCertificateChain(KEY_ALIAS);
//        AttestationCertificatePath certPath = new AttestationCertificatePath(Arrays.asList(certificateChain));
//        AndroidKeyAttestationStatement androidAttest = new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.RS256, sig, certPath);

        RegistrationObject registrationObject = createRegistrationObjectWithAndroidKeyAttestation();

        AndroidKeyAttestationStatementVerifier target = new AndroidKeyAttestationStatementVerifier();
        AttestationType verify = target.verify(registrationObject);
        int aaa = 122;
    }
}
