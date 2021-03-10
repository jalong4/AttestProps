package com.google.jimlongja.attestprops;

import android.util.Pair;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public interface AttestPropsAsyncTaskInterface {
    void onComplete(Pair<X509Certificate, List<Certificate>> pair, Boolean isDevicePropertyAttestationSupported);
}
