package com.google.jimlongja.attestprops;

import android.content.Context;

class AttestPropsAsyncTaskParams {
    AttestPropsAsyncTaskParams(Context context,
                            String challenge,
                               AttestPropsAsyncTaskInterface callback) {
        this.context = context;
        this.challenge = challenge;
        this.callback = callback;
    }
    Context context;
    String challenge;
    AttestPropsAsyncTaskInterface callback;
}
