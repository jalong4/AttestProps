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

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;

public class AttestationApplicationId implements java.lang.Comparable<AttestationApplicationId> {
    private static final int PACKAGE_INFOS_INDEX = 0;
    private static final int SIGNATURE_DIGESTS_INDEX = 1;

    private final List<AttestationPackageInfo> mPackageInfos;
    private final List<byte[]> mSignatureDigests;

    public AttestationApplicationId(Context context)
            throws NoSuchAlgorithmException, NameNotFoundException {
        PackageManager pm = context.getPackageManager();
        int uid = context.getApplicationInfo().uid;
        String[] packageNames = pm.getPackagesForUid(uid);
        if (packageNames == null || packageNames.length == 0) {
            throw new NameNotFoundException("No names found for uid");
        }
        mPackageInfos = new ArrayList<AttestationPackageInfo>();
        for (String packageName : packageNames) {
            // get the package info for the given package name including
            // the signatures
            PackageInfo packageInfo = pm.getPackageInfo(packageName, 0);
            mPackageInfos.add(new AttestationPackageInfo(packageName, packageInfo.versionCode));
        }
        // The infos must be sorted, the implementation of Comparable relies on it.
        mPackageInfos.sort(null);

        // compute the sha256 digests of the signature blobs
        mSignatureDigests = new ArrayList<byte[]>();
        PackageInfo packageInfo = pm.getPackageInfo(packageNames[0], PackageManager.GET_SIGNATURES);
        for (Signature signature : packageInfo.signatures) {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            mSignatureDigests.add(sha256.digest(signature.toByteArray()));
        }
        // The digests must be sorted. the implementation of Comparable relies on it
        mSignatureDigests.sort(new ByteArrayComparator());
    }

    public AttestationApplicationId(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence)) {
            throw new CertificateParsingException(
                    "Expected sequence for AttestationApplicationId, found "
                            + asn1Encodable.getClass().getName());
        }

        ASN1Sequence sequence = (ASN1Sequence) asn1Encodable;
        mPackageInfos = parseAttestationPackageInfos(sequence.getObjectAt(PACKAGE_INFOS_INDEX));
        // The infos must be sorted, the implementation of Comparable relies on it.
        mPackageInfos.sort(null);
        mSignatureDigests = parseSignatures(sequence.getObjectAt(SIGNATURE_DIGESTS_INDEX));
        // The digests must be sorted. the implementation of Comparable relies on it
        mSignatureDigests.sort(new ByteArrayComparator());
    }

    public List<AttestationPackageInfo> getAttestationPackageInfos() {
        return mPackageInfos;
    }

    public List<byte[]> getmSignatureDigests() {
        return mSignatureDigests;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("AttestationApplicationId:");
        int noOfInfos = mPackageInfos.size();
        int i = 1;
        for (AttestationPackageInfo info : mPackageInfos) {
            sb.append("\n### Package info " + i + "/" + noOfInfos + " ###\n");
            sb.append(info);
        }
        i = 1;
        int noOfSigs = mSignatureDigests.size();
        for (byte[] sig : mSignatureDigests) {
            sb.append("\nSignature digest " + i++ + "/" + noOfSigs + ":");
            for (byte b : sig) {
                sb.append(String.format(" %02X", b));
            }
        }
        return sb.toString();
    }

    @Override
    public int compareTo(AttestationApplicationId other) {
        int res = Integer.compare(mPackageInfos.size(), other.mPackageInfos.size());
        if (res != 0) return res;
        for (int i = 0; i < mPackageInfos.size(); ++i) {
            res = mPackageInfos.get(i).compareTo(other.mPackageInfos.get(i));
            if (res != 0) return res;
        }
        res = Integer.compare(mSignatureDigests.size(), other.mSignatureDigests.size());
        if (res != 0) return res;
        ByteArrayComparator cmp = new ByteArrayComparator();
        for (int i = 0; i < mSignatureDigests.size(); ++i) {
            res = cmp.compare(mSignatureDigests.get(i), other.mSignatureDigests.get(i));
            if (res != 0) return res;
        }
        return res;
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof AttestationApplicationId)
                && (0 == compareTo((AttestationApplicationId) o));
    }

    private List<AttestationPackageInfo> parseAttestationPackageInfos(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set)) {
            throw new CertificateParsingException(
                    "Expected set for AttestationApplicationsInfos, found "
                            + asn1Encodable.getClass().getName());
        }

        ASN1Set set = (ASN1Set) asn1Encodable;
        List<AttestationPackageInfo> result = new ArrayList<AttestationPackageInfo>();
        for (ASN1Encodable e : set) {
            result.add(new AttestationPackageInfo(e));
        }
        return result;
    }

    private List<byte[]> parseSignatures(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set)) {
            throw new CertificateParsingException("Expected set for Signature digests, found "
                    + asn1Encodable.getClass().getName());
        }

        ASN1Set set = (ASN1Set) asn1Encodable;
        List<byte[]> result = new ArrayList<byte[]>();

        for (ASN1Encodable e : set) {
            result.add(Asn1Utils.getByteArrayFromAsn1(e));
        }
        return result;
    }

    private class ByteArrayComparator implements java.util.Comparator<byte[]> {
        @Override
        public int compare(byte[] a, byte[] b) {
            int res = Integer.compare(a.length, b.length);
            if (res != 0) return res;
            for (int i = 0; i < a.length; ++i) {
                res = Byte.compare(a[i], b[i]);
                if (res != 0) return res;
            }
            return res;
        }
    }
}
