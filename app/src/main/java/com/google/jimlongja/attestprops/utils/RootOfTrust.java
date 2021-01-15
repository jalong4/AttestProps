/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.jimlongja.attestprops.utils;

import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;

import java.security.cert.CertificateParsingException;

public class RootOfTrust {
    public static final int KM_VERIFIED_BOOT_VERIFIED = 0;
    public static final int KM_VERIFIED_BOOT_SELF_SIGNED = 1;
    public static final int KM_VERIFIED_BOOT_UNVERIFIED = 2;
    public static final int KM_VERIFIED_BOOT_FAILED = 3;
    private static final int VERIFIED_BOOT_KEY_INDEX = 0;
    private static final int DEVICE_LOCKED_INDEX = 1;
    private static final int VERIFIED_BOOT_STATE_INDEX = 2;
    private final byte[] mVerifiedBootKey;
    private final int mVerifiedBootState;
    private boolean mDeviceLocked;

    public RootOfTrust(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        this(asn1Encodable, true);
    }

    public RootOfTrust(ASN1Encodable asn1Encodable, boolean strictParsing)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence)) {
            throw new CertificateParsingException("Expected sequence for root of trust, found "
                    + asn1Encodable.getClass().getName());
        }

        ASN1Sequence sequence = (ASN1Sequence) asn1Encodable;
        mVerifiedBootKey =
                Asn1Utils.getByteArrayFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_KEY_INDEX));
        mDeviceLocked = Asn1Utils.getBooleanFromAsn1(sequence.getObjectAt(DEVICE_LOCKED_INDEX),
                strictParsing);
        mVerifiedBootState =
                Asn1Utils.getIntegerFromAsn1(sequence.getObjectAt(VERIFIED_BOOT_STATE_INDEX));
    }

    public static String verifiedBootStateToString(int verifiedBootState) {
        switch (verifiedBootState) {
            case KM_VERIFIED_BOOT_VERIFIED:
                return "Verified";
            case KM_VERIFIED_BOOT_SELF_SIGNED:
                return "Self-signed";
            case KM_VERIFIED_BOOT_UNVERIFIED:
                return "Unverified";
            case KM_VERIFIED_BOOT_FAILED:
                return "Failed";
            default:
                return "Unknown";
        }
    }

    public byte[] getVerifiedBootKey() {
        return mVerifiedBootKey;
    }

    public boolean isDeviceLocked() {
        return mDeviceLocked;
    }

    public int getVerifiedBootState() {
        return mVerifiedBootState;
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("\nVerified boot Key: ")
                .append(BaseEncoding.base64().encode(mVerifiedBootKey))
                .append("\nDevice locked: ")
                .append(mDeviceLocked)
                .append("\nVerified boot state: ")
                .append(verifiedBootStateToString(mVerifiedBootState))
                .toString();
    }
}
