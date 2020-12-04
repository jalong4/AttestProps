package com.google.jimlongja.attestprops.Models;

import com.google.gson.annotations.SerializedName;

public class Challenge {

    @SerializedName("N")
    public Nonce nonce;
    @SerializedName("S")
    public String signiture;

    public Challenge(Nonce nonce, String signiture) {
        this.nonce = nonce;
        this.signiture = signiture;
    }
}

