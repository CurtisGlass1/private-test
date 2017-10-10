package com.entersekt.cordova.fingerprintui;

import com.entersekt.fingerprintui.SdkFingerprintListener;
import com.entersekt.sdk.TransaktSDK;

import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;

/**
 * Plugin to link Android TransaktSDK to Cordova
 *
 * @see <a href="https://github.com/apache/cordova-android">github</a> for CordovaPlugin source
 */
public class FingerprintUi extends CordovaPlugin {
    private SdkFingerprintListener listener;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                enableFingerprintUi();
            }
        });
    }

    @Override
    public void onPause(boolean multitasking) {
        if (listener != null) listener.cancel();
        super.onPause(multitasking);
    }

    private void enableFingerprintUi() {
        listener = new SdkFingerprintListener(cordova.getActivity());
        TransaktSDK.setFingerprintListener(listener);
    }
}
