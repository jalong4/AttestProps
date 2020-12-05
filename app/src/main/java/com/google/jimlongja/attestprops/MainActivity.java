package com.google.jimlongja.attestprops;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.jimlongja.attestprops.Models.Challenge;
import com.google.jimlongja.attestprops.Models.Nonce;
import com.google.jimlongja.attestprops.Utils.Attestation;
import com.google.jimlongja.attestprops.Utils.AuthorizationList;
import com.google.jimlongja.attestprops.Utils.RootOfTrust;

import java.lang.reflect.Method;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import androidx.annotation.VisibleForTesting;

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;

public class MainActivity extends Activity {

    @VisibleForTesting
    protected static final String HARDWARE_DEVICE_UNIQUE_ATTESTATION =
            "android.hardware.device_unique_attestation";
    @VisibleForTesting
    protected static final String SOFTWARE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";
    private static final String BUILD_FINGERPRINT = "ro.build.fingerprint";

    private static final String ANDROID_SYSTEM_PROPERTIES_CLASS = "android.os.SystemProperties";
    private static final String TAG = "AttestProps";
    private static final long ONE_MINUTE_IN_MILLIS=60000;
    @VisibleForTesting
    private Challenge mChallenge;
    private WidevineProperties mWidevineProperties = new WidevineProperties();

    private TextView mTvSoftwareIdAttestationSupported;
    private TextView mTvHardwareIdAttestationSupported;
    private TextView mTvVerifiedBootSupported;
    private TextView mTvDevicePropertiesAttestationSupported;

    private TextView mTvBrandProperty;
    private TextView mTvDeviceProperty;
    private TextView mTvProductProperty;
    private TextView mTvManufacturerProperty;
    private TextView mTvModelProperty;

    private TextView mTvAttestedBrandProperty;
    private TextView mTvAttestedDeviceProperty;
    private TextView mTvAttestedProductProperty;
    private TextView mTvAttestedManufacturerProperty;
    private TextView mTvAttestedModelProperty;

    private TextView mTvWidevineSystemId;
    private TextView mTvWidevineSPOID;

    private TextView mTvVerifiedBootKey;
    private TextView mTvVerifiedBootState;
    private TextView mTvDeviceLocked;
    private TextView mTvChallengeIsValid;

    private TextView mTvBuildFingerprint;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initTextViews();
        displayFeaturesAndProperties();

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        long expiryEpoc = new Date().toInstant().toEpochMilli() + ONE_MINUTE_IN_MILLIS * 15;
        mChallenge = new Challenge(
                new Nonce("MDEyMzQ1Njc4OUFCQ0RFRg==", expiryEpoc),
                "MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY=");

        Log.i(TAG,"Challenge: \n" + gson.toJson(mChallenge));

        logAndUpdateTextView(mTvWidevineSystemId, R.string.widevine_system_id, mWidevineProperties.getSystemID());
        logAndUpdateTextView(mTvWidevineSPOID, R.string.widevine_SPOID, mWidevineProperties.getSPOID());

        new AttestPropsAsyncTask().execute(new AttestPropsAsyncTaskParams(
                getApplicationContext(),
                gson.toJson(mChallenge),
                this::updateUIandLogOutput
        ));
    }

    private void initTextViews() {

        mTvSoftwareIdAttestationSupported = (TextView) findViewById(R.id.software_id_attestation_supported);
        mTvHardwareIdAttestationSupported = (TextView) findViewById(R.id.hardware_id_attestation_supported);
        mTvVerifiedBootSupported = (TextView) findViewById(R.id.verified_boot_supported);
        mTvDevicePropertiesAttestationSupported = (TextView) findViewById(R.id.device_properties_attestation_supported);

        mTvBrandProperty = (TextView) findViewById(R.id.brand_property);
        mTvDeviceProperty = (TextView) findViewById(R.id.device_property);
        mTvProductProperty = (TextView) findViewById(R.id.product_property);
        mTvManufacturerProperty = (TextView) findViewById(R.id.manufacturer_property);
        mTvModelProperty = (TextView) findViewById(R.id.model_property);

        mTvAttestedBrandProperty = (TextView) findViewById(R.id.attested_brand_property);
        mTvAttestedDeviceProperty = (TextView) findViewById(R.id.attested_device_property);
        mTvAttestedProductProperty = (TextView) findViewById(R.id.attested_product_property);
        mTvAttestedManufacturerProperty = (TextView) findViewById(R.id.attested_manufacturer_property);
        mTvAttestedModelProperty = (TextView) findViewById(R.id.attested_model_property);

        mTvWidevineSystemId = (TextView) findViewById(R.id.widevine_system_id);
        mTvWidevineSPOID = (TextView) findViewById(R.id.widevine_SPOID);

        mTvVerifiedBootKey = (TextView) findViewById(R.id.verified_boot_key);
        mTvVerifiedBootState = (TextView) findViewById(R.id.verified_boot_state);
        mTvDeviceLocked = (TextView) findViewById(R.id.device_locked);
        mTvChallengeIsValid = (TextView) findViewById(R.id.challenge_is_valid);

        mTvBuildFingerprint = (TextView) findViewById(R.id.build_fingerprint);
    }

    private void logAndUpdateTextView(TextView tv, int resourceId, String value) {
        String label = getResources().getString(resourceId);
        String msg = String.format("%s [%s]", label, value);
        Log.i(TAG, msg);
        tv.setText(msg);
    }

    private void displayFeaturesAndProperties() {

        logAndUpdateTextView(
                mTvSoftwareIdAttestationSupported,
                R.string.software_id_attestation_supported,
                Boolean.toString(hasSystemFeature(SOFTWARE_DEVICE_ID_ATTESTATION)));

        logAndUpdateTextView(
                mTvHardwareIdAttestationSupported,
                R.string.hardware_id_attestation_supported,
                Boolean.toString(hasSystemFeature(HARDWARE_DEVICE_UNIQUE_ATTESTATION)));

        logAndUpdateTextView(
                mTvVerifiedBootSupported,
                R.string.verified_boot_supported,
                Boolean.toString(hasSystemFeature(PackageManager.FEATURE_VERIFIED_BOOT)));


        Log.i(TAG," ");

        logAndUpdateTextView(mTvBrandProperty, R.string.brand_property, BRAND);
        logAndUpdateTextView(mTvDeviceProperty, R.string.device_property, DEVICE);
        logAndUpdateTextView(mTvProductProperty, R.string.product_property, PRODUCT);
        logAndUpdateTextView(mTvManufacturerProperty, R.string.manufacturer_property, MANUFACTURER);
        logAndUpdateTextView(mTvModelProperty, R.string.model_property, MODEL);

        logAndUpdateTextView(
                mTvBuildFingerprint,
                R.string.build_fingerprint,
                getSystemProperty(BUILD_FINGERPRINT));
    }

    private String getSystemProperty(String prop) {

        String defaultValue = "";
        try {
            Class<?> systemProperties = Class.forName(ANDROID_SYSTEM_PROPERTIES_CLASS);
            Method getMethod = systemProperties.getMethod("get", String.class);
            String value = (String) getMethod.invoke(systemProperties, prop);
            return "".equals(value) ? defaultValue : value;
        } catch (Exception e) {
            Log.e(TAG, "Failed to read " + prop, e);
            return defaultValue;
        }
    }

    private void updateUIandLogOutput(X509Certificate x509cert,
                                      Boolean isDevicePropertyAttestationSupported) {

        if (x509cert == null) {
            Log.e(TAG, "Failed to get x509 cert");
            return;
        }

        logAndUpdateTextView(mTvDevicePropertiesAttestationSupported,
                R.string.device_properties_attestation_supported,
                isDevicePropertyAttestationSupported.toString());

        try {
            Attestation attestation = new Attestation(x509cert);

            Log.i(TAG, " ");

            AuthorizationList teeEnforced = attestation.getTeeEnforced();

            logAndUpdateTextView(mTvAttestedBrandProperty, R.string.attested_brand_property, teeEnforced.getBrand());
            logAndUpdateTextView(mTvAttestedDeviceProperty, R.string.attested_device_property, teeEnforced.getDevice());
            logAndUpdateTextView(mTvAttestedProductProperty, R.string.attested_product_property, teeEnforced.getProduct());
            logAndUpdateTextView(mTvAttestedManufacturerProperty, R.string.attested_manufacturer_property, teeEnforced.getManufacturer());
            logAndUpdateTextView(mTvAttestedModelProperty, R.string.attested_model_property, teeEnforced.getModel());

            if (teeEnforced.getRootOfTrust() != null) {
                Log.i(TAG, "Root of Trust: ");
                logAndUpdateTextView(
                        mTvVerifiedBootKey,
                        R.string.verified_boot_key,
                        BaseEncoding.base64().encode(teeEnforced.getRootOfTrust().getVerifiedBootKey()));

                logAndUpdateTextView(
                        mTvVerifiedBootState,
                        R.string.verified_boot_state,
                        RootOfTrust.verifiedBootStateToString(teeEnforced.getRootOfTrust().getVerifiedBootState()));

                logAndUpdateTextView(mTvDeviceLocked,
                        R.string.device_locked,
                        Boolean.toString(teeEnforced.getRootOfTrust().isDeviceLocked()));

            }

            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            Challenge challenge = new Gson().fromJson(new String(attestation.getAttestationChallenge()), Challenge.class);
            Log.i(TAG, String.format("Challenge: %s", gson.toJson(challenge)));
            Log.i(TAG, String.format("Challenge Length: %d", attestation.getAttestationChallenge().length));
            logAndUpdateTextView(mTvChallengeIsValid, R.string.challenge_is_valid, isValidChallenge(challenge).toString());

        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }
    }


    Boolean isValidChallenge(Challenge challenge) {

        boolean result = true;
        if (challenge.nonce.expirationEpoc < new Date().toInstant().toEpochMilli()) {
            Log.e(TAG, "Challenge was expired");
            result = false;
        }

        if (!mChallenge.nonce.value.equals(challenge.nonce.value)) {
            Log.e(TAG, "Invalid Nonce value returned in certificate");
            result = false;
        }

        if (!mChallenge.signiture.equals(challenge.signiture)) {
            Log.e(TAG, "Invalid Challenge signiture returned in certificate");
            result = false;
        }

        return result;
    }
    @VisibleForTesting
    protected boolean hasSystemFeature(String feature) {
        PackageManager pm = getApplication().getPackageManager();
        return pm.hasSystemFeature(feature);
    }

}
