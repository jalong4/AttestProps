package com.google.jimlongja.attestprops;

import android.content.Context;

class AttestPropsAsyncTaskParams {
    private final Context mContext;
    private final String mChallenge;
    private final AttestPropsAsyncTaskInterface mCallback;

    AttestPropsAsyncTaskParams(Context context,
                               String challenge,
                               AttestPropsAsyncTaskInterface callback) {
        this.mContext = context;
        this.mChallenge = challenge;
        this.mCallback = callback;
    }

    public Context getContext() {
        return mContext;
    }

    public String getChallenge() {
        return mChallenge;
    }

    public AttestPropsAsyncTaskInterface getCallback() {
        return mCallback;
    }
}