package com.google.jimlongja.attestprops;

import android.media.MediaDrm;

import com.google.jimlongja.attestprops.Utils.Utils;

import java.util.UUID;

public class WidevineProperties {
    private static final UUID WIDEVINE_UUID = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private final MediaDrm mMediaDrm = null;
    private final String mSystemID;
    private final String mSPOID;

    public WidevineProperties() {
        mSystemID = getWidevineSystemId();
        mSPOID = getWidevineSPOID();
    }

    public String getSystemID() {
        return mSystemID;
    }

    public String getSPOID() {
        return mSPOID;
    }

    @Override
    public String toString() {
        return "WidevineProperties{" +
                "System ID ='" + mSystemID + '\'' +
                ", SPOID ='" + mSPOID + '\'' +
                '}';
    }

    private MediaDrm getDrmInfo() {

        MediaDrm mediaDrm = null;
        try {
            mediaDrm = new MediaDrm(WIDEVINE_UUID);
        } catch (Exception e) {
            throw new Error("Unexpected exception ", e);
        } finally {
            if (mMediaDrm != null) {
                mMediaDrm.close();
            }
        }

        return mediaDrm;

    }

    private String getWidevineSystemId() {
        return getDrmInfo().getPropertyString("systemId");
    }

    private String getWidevineSPOID() {
        return Utils.bytesToHex(getDrmInfo().getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID));
    }
}
