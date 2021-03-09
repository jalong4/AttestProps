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

import com.google.common.base.CharMatcher;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Sequence;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Parses an attestation certificate and provides an easy-to-use interface for examining the
 * contents.
 */
public class Attestation {
    public static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
    public static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int KM_SECURITY_LEVEL_STRONG_BOX = 2;
    static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
    static final String KEY_USAGE_OID = "2.5.29.15";  // Standard key usage extension.
    static final int ATTESTATION_VERSION_INDEX = 0;
    static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
    static final int KEYMASTER_VERSION_INDEX = 2;
    static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
    static final int ATTESTATION_CHALLENGE_INDEX = 4;
    static final int UNIQUE_ID_INDEX = 5;
    static final int SW_ENFORCED_INDEX = 6;
    static final int TEE_ENFORCED_INDEX = 7;
    private final int mAttestationVersion;
    private final int mAttestationSecurityLevel;
    private final int mKeymasterVersion;
    private final int mKeymasterSecurityLevel;
    private final byte[] mAttestationChallenge;
    private final byte[] mUniqueId;
    private final AuthorizationList mSoftwareEnforced;
    private final AuthorizationList mTeeEnforced;
    private final Set<String> mUnexpectedExtensionOids;


    /**
     * Constructs an {@code Attestation} object from the provided {@link X509Certificate},
     * extracting the attestation data from the attestation extension.
     *
     * @throws CertificateParsingException if the certificate does not contain a properly-formatted
     *                                     attestation extension.
     */

    public Attestation(X509Certificate x509Cert) throws CertificateParsingException {
        this(x509Cert, true);
    }

    public Attestation(X509Certificate x509Cert, boolean strictParsing)
            throws CertificateParsingException {
        ASN1Sequence seq = getAttestationSequence(x509Cert);
        mUnexpectedExtensionOids = retrieveUnexpectedExtensionOids(x509Cert);

        mAttestationVersion = Asn1Utils.getIntegerFromAsn1(
                seq.getObjectAt(ATTESTATION_VERSION_INDEX));
        mAttestationSecurityLevel = Asn1Utils.getIntegerFromAsn1(
                seq.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX));
        mKeymasterVersion = Asn1Utils.getIntegerFromAsn1(seq.getObjectAt(KEYMASTER_VERSION_INDEX));
        mKeymasterSecurityLevel = Asn1Utils.getIntegerFromAsn1(
                seq.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX));

        mAttestationChallenge = Asn1Utils.getByteArrayFromAsn1(
                seq.getObjectAt(Attestation.ATTESTATION_CHALLENGE_INDEX));

        mUniqueId = Asn1Utils.getByteArrayFromAsn1(seq.getObjectAt(Attestation.UNIQUE_ID_INDEX));

        mSoftwareEnforced = new AuthorizationList(seq.getObjectAt(SW_ENFORCED_INDEX), strictParsing);
        mTeeEnforced = new AuthorizationList(seq.getObjectAt(TEE_ENFORCED_INDEX), strictParsing);
    }

    public static String securityLevelToString(int attestationSecurityLevel) {
        switch (attestationSecurityLevel) {
            case KM_SECURITY_LEVEL_SOFTWARE:
                return "Software";
            case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                return "TEE";
            case KM_SECURITY_LEVEL_STRONG_BOX:
                return "StrongBox";
            default:
                return "Unknown";
        }
    }

    public int getAttestationVersion() {
        return mAttestationVersion;
    }

    public int getAttestationSecurityLevel() {
        return mAttestationSecurityLevel;
    }

    public int getKeymasterVersion() {
        return mKeymasterVersion;
    }

    public int getKeymasterSecurityLevel() {
        return mKeymasterSecurityLevel;
    }

    public byte[] getAttestationChallenge() {
        return mAttestationChallenge;
    }

    public byte[] getUniqueId() {
        return mUniqueId;
    }

    public AuthorizationList getSoftwareEnforced() {
        return mSoftwareEnforced;
    }

    public AuthorizationList getTeeEnforced() {
        return mTeeEnforced;
    }

    public Set<String> getUnexpectedExtensionOids() {
        return mUnexpectedExtensionOids;
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("Attest version: " + mAttestationVersion);
        s.append("\nAttest security: " + securityLevelToString(mAttestationSecurityLevel));
        s.append("\nKM version: " + mKeymasterVersion);
        s.append("\nKM security: " + securityLevelToString(mKeymasterSecurityLevel));

        s.append("\nChallenge");
        String stringChallenge = new String(mAttestationChallenge);
        if (CharMatcher.ascii().matchesAllOf(stringChallenge)) {
            s.append(": [" + stringChallenge + "]");
        } else {
            s.append(" (base64): [" + BaseEncoding.base64().encode(mAttestationChallenge) + "]");
        }
        if (mUniqueId != null) {
            s.append("\nUnique ID (base64): [" + BaseEncoding.base64().encode(mUniqueId) + "]");
        }

        s.append("\n-- SW enforced --");
        s.append(mSoftwareEnforced);
        s.append("\n-- TEE enforced --");
        s.append(mTeeEnforced);

        return s.toString();
    }

    private ASN1Sequence getAttestationSequence(X509Certificate x509Cert)
            throws CertificateParsingException {
        byte[] attestationExtensionBytes = x509Cert.getExtensionValue(KEY_DESCRIPTION_OID);
        if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
            throw new CertificateParsingException(
                    "Did not find extension with OID " + KEY_DESCRIPTION_OID);
        }
        return Asn1Utils.getAsn1SequenceFromBytes(attestationExtensionBytes);
    }

    private Set<String> retrieveUnexpectedExtensionOids(X509Certificate x509Cert) {
        return new ImmutableSet.Builder<String>()
                .addAll(x509Cert.getCriticalExtensionOIDs()
                        .stream()
                        .filter(s -> !KEY_USAGE_OID.equals(s))
                        .iterator())
                .addAll(x509Cert.getNonCriticalExtensionOIDs()
                        .stream()
                        .filter(s -> !KEY_DESCRIPTION_OID.equals(s))
                        .iterator())
                .build();
    }
}
