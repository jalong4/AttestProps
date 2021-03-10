/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.jimlongja.attestprops.Utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateParsingException;

public class AttestationPackageInfo implements java.lang.Comparable<AttestationPackageInfo> {
    private static final int PACKAGE_NAME_INDEX = 0;
    private static final int VERSION_INDEX = 1;

    private final String mPackageName;
    private final long mVersion;

    public AttestationPackageInfo(String packageName, long version) {
        this.mPackageName = packageName;
        this.mVersion = version;
    }

    public AttestationPackageInfo(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence)) {
            throw new CertificateParsingException(
                    "Expected sequence for AttestationPackageInfo, found "
                            + asn1Encodable.getClass().getName());
        }

        ASN1Sequence sequence = (ASN1Sequence) asn1Encodable;
        try {
            mPackageName = Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(
                    sequence.getObjectAt(PACKAGE_NAME_INDEX));
        } catch (UnsupportedEncodingException e) {
            throw new CertificateParsingException(
                    "Converting octet stream to String triggered an UnsupportedEncodingException",
                    e);
        }
        mVersion = Asn1Utils.getLongFromAsn1(sequence.getObjectAt(VERSION_INDEX));
    }

    public String getmPackageName() {
        return mPackageName;
    }

    public long getmVersion() {
        return mVersion;
    }

    @Override
    public String toString() {
        return new StringBuilder().append("Package name: ").append(getmPackageName())
                .append("\nVersion: " + getmVersion()).toString();
    }

    @Override
    public int compareTo(AttestationPackageInfo other) {
        int res = mPackageName.compareTo(other.mPackageName);
        if (res != 0) return res;
        res = Long.compare(mVersion, other.mVersion);
        if (res != 0) return res;
        return res;
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof AttestationPackageInfo)
                && (0 == compareTo((AttestationPackageInfo) o));
    }
}
