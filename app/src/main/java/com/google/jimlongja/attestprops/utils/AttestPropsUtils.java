package com.google.jimlongja.attestprops.Utils;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.util.Pair;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class AttestPropsUtils {
    private static final String BUILD_VERSION = "ro.build.version.codename";
    public static final String HARDWARE_DEVICE_UNIQUE_ATTESTATION =
            "android.hardware.device_unique_attestation";
    public static final String SOFTWARE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";
    private static final String ANDROID_SYSTEM_PROPERTIES_CLASS = "android.os.SystemProperties";

    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;
    private static final String KEYSTORE_ALIAS = "test_key";

    private static final String TAG = "AttestPropsUtils";

    private boolean mIsDevicePropertyAttestationSupported = false;
    private boolean mDevicePropertyAttestationFailed = false;

    public AttestPropsUtils() {
    }

    public boolean isDevicePropertyAttestationSupported() {
        return mIsDevicePropertyAttestationSupported;
    }

    public boolean didDevicePropertyAttestationFail() {
        return mDevicePropertyAttestationFailed;
    }

    public String getSystemProperty(String prop) {

        try {
            Class<?> systemProperties = Class.forName(ANDROID_SYSTEM_PROPERTIES_CLASS);
            Method getMethod = systemProperties.getMethod("get", String.class);
            String value = (String) getMethod.invoke(systemProperties, prop);
            return value;
        } catch (Exception e) {
            Log.e(TAG, "Failed to read " + prop, e);
            return "";
        }
    }

    private KeyGenParameterSpec buildKeyGenParameterSpec(@NotNull String challenge,
                                                         boolean attestDeviceProperties) {

//        mIsDevicePropertyAttestationSupported = Build.VERSION.SDK_INT > Build.VERSION_CODES.R;
        mIsDevicePropertyAttestationSupported = "S".equals(getSystemProperty(BUILD_VERSION));
        Date KeyValidityStart = new Date();
        Date KeyValidyForOriginationEnd =
                new Date(KeyValidityStart.getTime() + ORIGINATION_TIME_OFFSET);
        Date KeyValidyForComsumptionnEnd =
                new Date(KeyValidityStart.getTime() + CONSUMPTION_TIME_OFFSET);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)

                .setUserAuthenticationRequired(false)
                .setAttestationChallenge(challenge.getBytes())
                .setKeyValidityStart(KeyValidityStart)
                .setKeyValidityForOriginationEnd(KeyValidyForOriginationEnd)
                .setKeyValidityForConsumptionEnd(KeyValidyForComsumptionnEnd);

        if (mIsDevicePropertyAttestationSupported) {
            builder.setDevicePropertiesAttestationIncluded(true);
        }


        Log.i(TAG, String.format("setDevicePropertiesAttestationIncluded:  %b",
                mIsDevicePropertyAttestationSupported ? "true" : "Not supported"));

        return builder.build();
    }

    private List<Certificate> getCertificateChainFromKeyStore(
            KeyPairGenerator keyPairGenerator,
            KeyGenParameterSpec keyGenParameterSpec) throws InvalidAlgorithmParameterException,
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException,
            InvalidKeyException {

        keyPairGenerator.initialize(keyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return Arrays.asList(keyStore.getCertificateChain(KEYSTORE_ALIAS));
    }

    public Pair<X509Certificate, List<Certificate>> getAttestationCertificateAndChain(
            Context context, String challenge) {
        return getAttestationCertificateAndChain(context, challenge, true);
    }

    public Pair<X509Certificate, List<Certificate>> getAttestationCertificateAndChain(
            Context context, String challenge, boolean attestDeviceProperties) {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = buildKeyGenParameterSpec(challenge,
                    attestDeviceProperties);

            Log.i(TAG, "Generating keypair using keyStore");

            List<Certificate> certificates = getCertificateChainFromKeyStore(keyPairGenerator,
                    keyGenParameterSpec);

            if (certificates == null || certificates.get(0) == null) {
                return null;
            }
            Certificate certificate = certificates.get(0);
            if (!(certificate instanceof X509Certificate)) {
                return null;
            }

            X509Certificate x509cert = (X509Certificate) certificate;
            return new Pair(x509cert, certificates);

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | KeyStoreException
                | IOException | NoSuchProviderException | CertificateException
                | InvalidKeyException e) {
            e.printStackTrace();
        } catch (ProviderException e) {
            mDevicePropertyAttestationFailed = true;
        }

        return null;
    }

    public static void verifyCertificateChain(Certificate[] certChain)
            throws GeneralSecurityException {
        assertNotNull(certChain);
        for (int i = 1; i < certChain.length; ++i) {
            try {
                PublicKey pubKey = certChain[i].getPublicKey();
                certChain[i - 1].verify(pubKey);
                if (i == certChain.length - 1) {
                    // Last cert should be self-signed.
                    certChain[i].verify(pubKey);
                }

                // Check that issuer in the signed cert matches subject in the signing cert.
                X509Certificate x509CurrCert = (X509Certificate) certChain[i];
                X509Certificate x509PrevCert = (X509Certificate) certChain[i - 1];
                X500Name signingCertSubject =
                        new JcaX509CertificateHolder(x509CurrCert).getSubject();
                X500Name signedCertIssuer =
                        new JcaX509CertificateHolder(x509PrevCert).getIssuer();
                // Use .toASN1Object().equals() rather than .equals() because .equals() is case
                // insensitive, and we want to verify an exact match.
                assertTrue(
                        signedCertIssuer.toASN1Object().equals(signingCertSubject.toASN1Object()));

                X500Name signedCertSubject =
                        new JcaX509CertificateHolder(x509PrevCert).getSubject();
                if (i == 1) {
                    // First cert should have subject "CN=Android Keystore Key".
                    assertEquals(signedCertSubject, new X500Name("CN=Android Keystore Key"));
                } else {
                    // Only strongbox implementations should have strongbox in the subject line
                    assertEquals(false, signedCertSubject.toString()
                            .toLowerCase()
                            .contains("strongbox"));
                }
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                    | NoSuchProviderException | SignatureException e) {
                throw new GeneralSecurityException("Failed to verify certificate "
                        + certChain[i - 1] + " with public key " + certChain[i].getPublicKey(), e);
            }
        }
    }
}
