package com.google.android.attestation;

import com.thales.attest.ThreadUtils;

public interface CertificateRevocationStatusListener extends ThreadUtils.Callback<CertificateRevocationStatus> {

}
