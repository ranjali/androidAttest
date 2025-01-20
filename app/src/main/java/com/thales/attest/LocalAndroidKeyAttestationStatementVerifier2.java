package com.thales.attest;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.AbstractStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.KeyDescriptionVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.BadSignatureException;
import com.webauthn4j.verifier.exception.PublicKeyMismatchException;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

public class LocalAndroidKeyAttestationStatementVerifier2 extends AbstractStatementVerifier<AndroidKeyAttestationStatement> {

    // ~ Instance fields
    // ================================================================================================

    private final KeyDescriptionVerifier keyDescriptionVerifier = new KeyDescriptionVerifier();
    private boolean teeEnforcedOnly = true;

    @Override
    public @NotNull AttestationType verify(@NotNull CoreRegistrationObject registrationObject) {

        /// Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the public key in the first certificate in x5c with the algorithm specified in alg.
        verifySignature(registrationObject);

        return AttestationType.BASIC;
    }

    private void verifySignature(@NotNull CoreRegistrationObject registrationObject) {
        AndroidKeyAttestationStatement attestationStatement = (AndroidKeyAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] signedData = getSignedData(registrationObject);
        byte[] signature = attestationStatement.getSig();
        PublicKey publicKey = getPublicKey(attestationStatement);

        try {
            String jcaName;
            jcaName = getJcaName(attestationStatement.getAlg());
            jcaName = "SHA256withRSA/PSS";
            Signature verifier = SignatureUtil.createSignature(jcaName);
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            if (verifier.verify(signature)) {
                return;
            }
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.");
        } catch (SignatureException | InvalidKeyException e) {
            throw new BadSignatureException("`sig` in attestation statement is not valid signature over the concatenation of authenticatorData and clientDataHash.", e);
        }
    }

    private @NotNull byte[] getSignedData(@NotNull CoreRegistrationObject registrationObject) {
        byte[] authenticatorData = registrationObject.getAuthenticatorDataBytes();
        byte[] clientDataHash = registrationObject.getClientDataHash();
        return ByteBuffer.allocate(authenticatorData.length + clientDataHash.length).put(authenticatorData).put(clientDataHash).array();
    }

    private @NotNull PublicKey getPublicKey(@NotNull AndroidKeyAttestationStatement attestationStatement) {
        AttestationCertificatePath x5c = attestationStatement.getX5c();
        Certificate cert = x5c.getEndEntityAttestationCertificate().getCertificate();
        return cert.getPublicKey();
    }
}
