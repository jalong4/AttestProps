package com.google.jimlongja.attestprops;

import android.content.Context;
import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.google.jimlongja.attestprops.Utils.AttestPropsUtils;
import com.google.jimlongja.attestprops.Utils.ReflectionUtil;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class AttestPropsAsyncTask extends AsyncTask<AttestPropsAsyncTaskParams, Integer, X509Certificate> {

    private static final int ID_TYPE_BASE_INFO = 1;
    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;
    private static final String KEYSTORE_ALIAS = "test_key";
    private static final String TAG = "AttestPropsAsyncTask";
    private AttestPropsAsyncTaskInterface mCallback;
    private AttestPropsUtils mAttestPropsUtils = new AttestPropsUtils();

    @Override
    protected X509Certificate doInBackground(AttestPropsAsyncTaskParams... params) {
        if (params.length != 1) {
            return null;
        }
        Context context = params[0].context;
        mCallback = params[0].callback;
        String challenge = params[0].challenge;
        X509Certificate cert = mAttestPropsUtils.getAttestationCertificate(context, challenge);

        if (mAttestPropsUtils.isDevicePropertyAttestationSupported()
                && mAttestPropsUtils.didDevicePropertyAttestationFail()) {
            cert = new AttestPropsUtils().getAttestationCertificate(context, challenge,
                    false);
        }

        return cert;
    }

    protected void onPostExecute(X509Certificate x509cert) {
        mCallback.onComplete(x509cert, mAttestPropsUtils.isDevicePropertyAttestationSupported());
    }

}
