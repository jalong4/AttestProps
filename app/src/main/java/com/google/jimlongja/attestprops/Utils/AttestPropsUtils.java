package com.google.jimlongja.attestprops.Utils;

import android.util.Log;
import java.lang.reflect.Method;

public class AttestPropsUtils {
    public static final String HARDWARE_DEVICE_UNIQUE_ATTESTATION =
            "android.hardware.device_unique_attestation";
    public static final String SOFTWARE_DEVICE_ID_ATTESTATION =
            "android.software.device_id_attestation";
    private static final String ANDROID_SYSTEM_PROPERTIES_CLASS = "android.os.SystemProperties";

    private static final String TAG = "AttestPropsUtils";

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
}
