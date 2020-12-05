package com.google.jimlongja.attestprops;

import android.content.Context;
import android.content.pm.PackageManager;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class AttestPropsTest {

    private PackageManager mPm;

    @Before
    public void setUp() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        mPm = appContext.getPackageManager();
    }
    @Test
    public void SoftwareIDAttestationIsSupported() {
        assertTrue(mPm.hasSystemFeature(MainActivity.SOFTWARE_DEVICE_ID_ATTESTATION));
    }

    @Test
    public void HardwareIDAttestationIsSupported() {
        assertTrue(mPm.hasSystemFeature(MainActivity.SOFTWARE_DEVICE_ID_ATTESTATION));
    }

    @Test
    public void VerifiedBootIsSupported() {
        assertTrue(mPm.hasSystemFeature(PackageManager.FEATURE_VERIFIED_BOOT));
    }

    @Test
    public void DevicePropertiesAttestationSupported() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Boolean> supported = new AtomicReference<>(false);

        new AttestPropsAsyncTask().execute(new AttestPropsAsyncTaskParams(
                appContext,
                "testChallenge",
                (x509cert, isDevicePropertyAttestationSupported) -> {
                    supported.set(isDevicePropertyAttestationSupported);
                    latch.countDown();
                }
        ));
        //Wait for api response async
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        assertTrue(supported.get());
    }

}