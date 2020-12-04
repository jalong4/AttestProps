package com.google.jimlongja.attestprops.Models;

import com.google.gson.annotations.SerializedName;

public class Nonce {
    @SerializedName("V")
    public String value;
    @SerializedName(value = "E")
    public long expirationEpoc;

    public Nonce(String value, long expirationEpoc) {
        this.value = value;
        this.expirationEpoc = expirationEpoc;
    }
}
