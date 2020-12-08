package com.google.jimlongja.attestprops;

import android.content.Context;
import android.content.pm.PackageManager;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.jimlongja.attestprops.Utils.AttestPropsUtils;
import com.google.jimlongja.attestprops.Utils.Attestation;
import com.google.jimlongja.attestprops.Utils.AuthorizationList;
import com.google.jimlongja.attestprops.Utils.RootOfTrust;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import static android.os.Build.BRAND;
import static android.os.Build.DEVICE;
import static android.os.Build.MANUFACTURER;
import static android.os.Build.MODEL;
import static android.os.Build.PRODUCT;
import static org.junit.Assume.assumeTrue;

@RunWith(AndroidJUnit4.class)
public class AttestPropsTest {

    private PackageManager mPm;
    private static final String CHALLENGE = "test challenge";


    @Before
    public void setUp() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        mPm = appContext.getPackageManager();
    }
    @Test
    public void SoftwareIDAttestationIsSupported() {
        Assert.assertTrue(mPm.hasSystemFeature(AttestPropsUtils.SOFTWARE_DEVICE_ID_ATTESTATION));
    }

    @Test
    public void HardwareIDAttestationIsSupported() {
        Assert.assertTrue(mPm.hasSystemFeature(AttestPropsUtils.HARDWARE_DEVICE_UNIQUE_ATTESTATION));
    }

    @Test
    public void VerifiedBootIsSupported() {
        Assert.assertTrue(mPm.hasSystemFeature(PackageManager.FEATURE_VERIFIED_BOOT));
    }

    @Test
    public void DevicePropertiesAttestationSupported() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AttestPropsAsyncTaskReturnParams params = getAttestPropsAsyncTaskReturnParams();

        Boolean result = false;
        if (params != null) {
            result = params.isDevicePropertyAttestationSupported;
        }
        Assert.assertTrue(result);
    }

    @Test
    public void AttestationReturnsTeeEnforcedX509Certification() {
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null);
    }

    @Test
    public void VerifiedBootStateIsVerified() {
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null
                && teeEnforced.getRootOfTrust() != null
                && teeEnforced.getRootOfTrust().getVerifiedBootState()
                == RootOfTrust.KM_VERIFIED_BOOT_VERIFIED);
    }

    @Test
    public void AttestedBrandPropertyMatches() {
        assumeTrue("Skipping ...", shouldRunNewTests());

        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getBrand() == BRAND);
    }

    @Test
    public void AttestedDevicePropertyMatches() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getDevice() == DEVICE);
    }

    @Test
    public void AttestedProductPropertyMatches() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getProduct() == PRODUCT);
    }

    @Test
    public void AttestedManufacturerPropertyMatches() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getManufacturer() == MANUFACTURER);
    }

    @Test
    public void AttestedModelPropertyMatches() {
        assumeTrue("Skipping ...", shouldRunNewTests());
        AuthorizationList teeEnforced = getTeeEnforcedAuthorizationList();
        Assert.assertTrue(teeEnforced != null && teeEnforced.getModel() == MODEL);
    }

    @Test
    public void ChallengeInCertMatches() {
        Attestation attestation = getAttestation();
        Assert.assertTrue(attestation != null
                && new String(
                attestation.getAttestationChallenge(), StandardCharsets.UTF_8)
                .equals(CHALLENGE));
    }

    private AuthorizationList getTeeEnforcedAuthorizationList() {
        Attestation attestation = getAttestation();
        return (attestation == null) ? null : attestation.getTeeEnforced();
    }

    private static class AttestPropsAsyncTaskReturnParams {
        X509Certificate x509Certificate;
        Boolean isDevicePropertyAttestationSupported;
    }

    private Attestation getAttestation() {
        AttestPropsAsyncTaskReturnParams params = getAttestPropsAsyncTaskReturnParams();
        Attestation result = null;

        if (params != null && params.x509Certificate != null) {
            try {
                result = new Attestation(params.x509Certificate);
            } catch (CertificateParsingException e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    private AttestPropsAsyncTaskReturnParams getAttestPropsAsyncTaskReturnParams() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<AttestPropsAsyncTaskReturnParams> result = new AtomicReference<>(null);

        new AttestPropsAsyncTask().execute(new AttestPropsAsyncTaskParams(
                appContext,
                CHALLENGE,
                (x509cert, isDevicePropertyAttestationSupported) -> {
                    AttestPropsAsyncTaskReturnParams params = new AttestPropsAsyncTaskReturnParams();
                    params.x509Certificate = x509cert;
                    params.isDevicePropertyAttestationSupported = isDevicePropertyAttestationSupported;
                        result.set(params);
                        latch.countDown();
                }
        ));

        //Wait for api response async
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return result.get();
    }

    private boolean shouldRunNewTests() {
        // Temporary until SDK gets updated to 31 for Android S
        String osName = new AttestPropsUtils()
                .getSystemProperty("ro.product.build.version.release_or_codename");
        return osName.equals("S");
//        return Build.VERSION.SDK_INT > 30;
    }

}
