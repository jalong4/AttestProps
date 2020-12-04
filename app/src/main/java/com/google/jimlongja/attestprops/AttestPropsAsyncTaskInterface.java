package com.google.jimlongja.attestprops;

import java.security.cert.X509Certificate;

public interface AttestPropsAsyncTaskInterface {
    void onComplete(X509Certificate x509cert, Boolean isDevicePropertyAttestationSupported);
}
