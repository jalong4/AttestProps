package com.google.jimlongja.attestprops;

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;

import static org.junit.Assume.assumeTrue;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.jimlongja.attestprops.utils.AttestPropsUtils;
import com.google.jimlongja.attestprops.utils.Attestation;
import com.google.jimlongja.attestprops.utils.AuthorizationList;
import com.google.jimlongja.attestprops.utils.RootOfTrust;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

@RunWith(AndroidJUnit4.class)
public class AttestPropsTest {

    private static final String CHALLENGE = "test challenge";
    private static final String TAG = AttestPropsTest.class.getSimpleName();
    private static Context sAppContext;
    private static AttestPropsUtils sAttestPropsUtils;
    private static X509Certificate sX509Certificate;
    private static boolean sIsDevicePropertyAttestationSupported = false;
    private static boolean sDevicePropertyAttestationFailed = false;

    @BeforeClass
    public static void setUp() {
        sAppContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        sAttestPropsUtils = new AttestPropsUtils();
        sX509Certificate = sAttestPropsUtils.getAttestationCertificate(sAppContext, CHALLENGE);
        sIsDevicePropertyAttestationSupported =
                sAttestPropsUtils.isDevicePropertyAttestationSupported();
        sDevicePropertyAttestationFailed = sAttestPropsUtils.didDevicePropertyAttestationFail();
        if (sIsDevicePropertyAttestationSupported && sDevicePropertyAttestationFailed) {
            sX509Certificate = sAttestPropsUtils.getAttestationCertificate(sAppContext, CHALLENGE,
                    false);
        }
    }

    @Test
    public void verifiedBootIsSupported() {
        Assert.assertTrue(sAppContext.getPackageManager()
                .hasSystemFeature(PackageManager.FEATURE_VERIFIED_BOOT));
    }

    @Test
    public void DevicePropertiesAttestationSupported() {
        Assert.assertTrue(sAttestPropsUtils.isDevicePropertyAttestationSupported());
    }

    @Test
    public void testTeeEnforcedAttestation() {
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Log.d(TAG, teeEnforced.toString());
        Assert.assertTrue(teeEnforced != null);
    }

    @Test
    public void testBootState() {
        RootOfTrust rootOfTrust = getRootOfTrust();
        Assert.assertTrue(rootOfTrust != null
                && rootOfTrust.getVerifiedBootState()
                == RootOfTrust.KM_VERIFIED_BOOT_VERIFIED);
    }

    @Test
    public void testDeviceIsLocked() {
        RootOfTrust rootOfTrust = getRootOfTrust();
        Assert.assertTrue(rootOfTrust != null
                && rootOfTrust.isDeviceLocked());
    }

    @Test
    public void attestedBrandProperty() {
        assumeTrue("Skipping ...", shouldRunNewTests());

        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getBrand() == BRAND);
    }

    @Test
    public void attestedDeviceProperty() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getDevice() == DEVICE);
    }

    @Test
    public void attestedProductProperty() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getProduct() == PRODUCT);
    }

    @Test
    public void attestedManufacturerProperty() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null
                && teeEnforced.getManufacturer() == MANUFACTURER);
    }

    @Test
    public void attestedModelProperty() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getModel() == MODEL);
    }

    @Test
    public void testChallenge() {
        String challenge = getChallenge();
        Assert.assertTrue(challenge != null
                && challenge.equals(CHALLENGE));
    }

    private String getChallenge() {
        Attestation attestation = getAttestation();
        if (attestation == null) {
            return null;
        }
        return new String(
                attestation.getAttestationChallenge(), StandardCharsets.UTF_8);
    }

    private RootOfTrust getRootOfTrust() {
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        if (teeEnforced == null) {
            return null;
        }
        return teeEnforced.getRootOfTrust();
    }


    private AuthorizationList getTeeEnforcedAuthorizationList() {
        Attestation attestation = getAttestation();
        return (attestation == null) ? null : attestation.getTeeEnforced();
    }

    private Attestation getAttestation() {
        Attestation result = null;
        if (sX509Certificate != null) {
            try {
                result = new Attestation(sX509Certificate);
            } catch (CertificateParsingException e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    private boolean shouldRunNewTests() {
        return sIsDevicePropertyAttestationSupported && !sDevicePropertyAttestationFailed;
    }

}
