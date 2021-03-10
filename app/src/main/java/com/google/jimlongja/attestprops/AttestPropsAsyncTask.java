package com.google.jimlongja.attestprops;

import android.os.AsyncTask;
import android.util.Log;
import android.util.Pair;

import com.google.jimlongja.attestprops.Utils.AttestPropsUtils;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;


public class AttestPropsAsyncTask extends AsyncTask<AttestPropsAsyncTaskParams, Integer,
        Pair<X509Certificate, List<Certificate>>> {

    private static final int ID_TYPE_BASE_INFO = 1;
    private static final String TAG = "AttestPropsAsyncTask";
    private AttestPropsAsyncTaskInterface mCallback;
    private final AttestPropsUtils mAttestPropsUtils = new AttestPropsUtils();
    private Boolean mIsDevicePropertyAttestationSupported;
    private List<Certificate> mCertChain = null;

    @Override
    protected Pair<X509Certificate, List<Certificate>> doInBackground(AttestPropsAsyncTaskParams... params) {
        if (params.length != 1) {
            return null;
        }

        boolean devicePropertyAttestationFailed = false;

        mCallback = params[0].getCallback();
        Pair<X509Certificate, List<Certificate>> pair = mAttestPropsUtils.getAttestationCertificateAndChain(
                params[0].getContext(), params[0].getChallenge(), true);
        mIsDevicePropertyAttestationSupported =
                mAttestPropsUtils.isDevicePropertyAttestationSupported();
        mCertChain = pair == null ? null : pair.second;

        if (mAttestPropsUtils.didDevicePropertyAttestationFail()) {
            Log.i(TAG, "Calling Attestation without attesting props");
            pair = mAttestPropsUtils.getAttestationCertificateAndChain(
                    params[0].getContext(), params[0].getChallenge(), false);
        }
        return pair;

    }

    protected void onPostExecute(Pair<X509Certificate, List<Certificate>> pair) {
        mCallback.onComplete(pair, mIsDevicePropertyAttestationSupported);
    }

}
