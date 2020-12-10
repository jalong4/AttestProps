package com.google.jimlongja.attestprops.Utils;;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import android.util.Log;
import java.lang.reflect.Method;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;


public class AttestPropsUtils {
    public static final String HARDWARE_DEVICE_UNIQUE_ATTESTATION =
            "android.hardware.device_unique_attestation";
    public static final String SOFTWARE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";
    private static final String ANDROID_SYSTEM_PROPERTIES_CLASS = "android.os.SystemProperties";

    private static final int ORIGINATION_TIME_OFFSET = 1000000;
    private static final int CONSUMPTION_TIME_OFFSET = 2000000;
    private static final String KEYSTORE_ALIAS = "test_key";

    private static final String TAG = "AttestPropsUtils";

    private boolean mIsDevicePropertyAttestationSupported = true;
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

    private KeyGenParameterSpec buildKeyGenParameterSpec(String challenge,
                                                         boolean attestDeviceProperties) {

        Date KeyValidityStart = new Date();
        Date KeyValidyForOriginationEnd =
                new Date(KeyValidityStart.getTime() + ORIGINATION_TIME_OFFSET);
        Date KeyValidyForComsumptionnEnd =
                new Date(KeyValidityStart.getTime() + CONSUMPTION_TIME_OFFSET);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)

                .setUserAuthenticationRequired(false)
                .setAttestationChallenge(challenge.getBytes())
//                .setDevicePropertiesAttestationIncluded(true)
                .setKeyValidityStart(KeyValidityStart)
                .setKeyValidityForOriginationEnd(KeyValidyForOriginationEnd)
                .setKeyValidityForConsumptionEnd(KeyValidyForComsumptionnEnd);

        // Use reflection until new API signitures get update in the Android SDK
        // Print exception and continue if method is not present
        // setDevicePropertiesAttestationIncluded to true if it is supported

        // Sometimes device perperty attestation can be supported but not configured, in this case
        // the ProviderException is thrown and we will not get a cert back.
        // In these cased, we can request to not attest device properties so we get the cert which
        // has all other other attributes
        // So if attestDeviceProperties is set to false, it means don't
        // setDevicePropertiesAttestationIncluded to true even if it's supported

        if (attestDeviceProperties) {
            try {
                ReflectionUtil.invoke(builder, "setDevicePropertiesAttestationIncluded", new Class<?>[]{boolean.class}, true);

            } catch (ReflectionUtil.ReflectionIsTemporaryException e) {
                mIsDevicePropertyAttestationSupported = false;
            }

            Log.i(TAG, String.format("setDevicePropertiesAttestationIncluded:  %b",
                    mIsDevicePropertyAttestationSupported ? "true" : "Not supported"));
        }
        return builder.build();


    }

    private List<Certificate> getCertificateChainFromKeyStore(
            KeyPairGenerator keyPairGenerator,
            KeyGenParameterSpec keyGenParameterSpec) throws InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException {

        keyPairGenerator.initialize(keyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return Arrays.asList(keyStore.getCertificateChain(KEYSTORE_ALIAS));
    }

    public X509Certificate getAttestationCertificate(Context context, String challenge) {
        return getAttestationCertificate(context, challenge, true);
    }

    public X509Certificate getAttestationCertificate(Context context, String challenge,
            boolean attestDeviceProperties) {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec keyGenParameterSpec = buildKeyGenParameterSpec(challenge,
                    attestDeviceProperties);

            Log.i(TAG, "Generating keypair using keyStore");

            List<Certificate> certificates = getCertificateChainFromKeyStore(keyPairGenerator, keyGenParameterSpec);

            if (certificates == null || certificates.get(0) == null) {
                return null;
            }
            Certificate certificate = certificates.get(0);
            if (!(certificate instanceof X509Certificate)) {
                return null;
            }

            X509Certificate x509cert = (X509Certificate) certificate;
            x509cert.checkValidity();
            return x509cert;

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | KeyStoreException |
                IOException | NoSuchProviderException | CertificateException  |
                InvalidKeyException e) {
            e.printStackTrace();
        } catch (ProviderException e) {
            mDevicePropertyAttestationFailed = true;
        }

        return null;
    }
}
