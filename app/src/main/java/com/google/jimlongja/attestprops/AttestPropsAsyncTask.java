package com.google.jimlongja.attestprops;

import android.os.AsyncTask;
import android.util.Log;

import com.google.jimlongja.attestprops.utils.AttestPropsUtils;

import java.security.cert.X509Certificate;


public class AttestPropsAsyncTask extends AsyncTask<AttestPropsAsyncTaskParams, Integer,
        X509Certificate> {

    private static final int ID_TYPE_BASE_INFO = 1;
    private static final String TAG = "AttestPropsAsyncTask";
    private AttestPropsAsyncTaskInterface mCallback;
    private final AttestPropsUtils mAttestPropsUtils = new AttestPropsUtils();
    private Boolean mIsDevicePropertyAttestationSupported;

    @Override
    protected X509Certificate doInBackground(AttestPropsAsyncTaskParams... params) {
        if (params.length != 1) {
            return null;
        }
        mCallback = params[0].getCallback();
        X509Certificate cert = mAttestPropsUtils.getAttestationCertificate(params[0].getContext(),
                params[0].getChallenge(), true);
        mIsDevicePropertyAttestationSupported =
                mAttestPropsUtils.isDevicePropertyAttestationSupported();
        if (mIsDevicePropertyAttestationSupported
                &&  mAttestPropsUtils.didDevicePropertyAttestationFail()) {
            Log.d(TAG, "Calling Attestation without DevicePropertyAttestation");
            cert = mAttestPropsUtils.getAttestationCertificate(params[0].getContext(),
                    params[0].getChallenge(), false);
        }
        return cert;

    }

    protected void onPostExecute(X509Certificate x509cert) {
        mCallback.onComplete(x509cert, mIsDevicePropertyAttestationSupported);
    }

}
