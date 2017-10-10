package com.entersekt.cordova.transaktsdk;

import android.util.Base64;
import android.util.Log;

import com.entersekt.sdk.AppMultifactor;
import com.entersekt.sdk.Auth;
import com.entersekt.sdk.Button;
import com.entersekt.sdk.CertificatePinner;
import com.entersekt.sdk.ConnectionContext;
import com.entersekt.sdk.EmCert;
import com.entersekt.sdk.Error;
import com.entersekt.sdk.Info;
import com.entersekt.sdk.Logger;
import com.entersekt.sdk.NameValue;
import com.entersekt.sdk.Notify;
import com.entersekt.sdk.Otp;
import com.entersekt.sdk.SecureData;
import com.entersekt.sdk.SecureDataFailed;
import com.entersekt.sdk.Service;
import com.entersekt.sdk.Signup;
import com.entersekt.sdk.TData;
import com.entersekt.sdk.TextBox;
import com.entersekt.sdk.TransaktSDK;
import com.entersekt.sdk.TrustToken;
import com.entersekt.sdk.callback.AppMultifactorCallback;
import com.entersekt.sdk.callback.AuthAnswerCallback;
import com.entersekt.sdk.callback.CertificatePinnerCallback;
import com.entersekt.sdk.callback.OtpCallback;
import com.entersekt.sdk.callback.PingCallback;
import com.entersekt.sdk.callback.SecureDataCallback;
import com.entersekt.sdk.callback.SignupCallback;
import com.entersekt.sdk.callback.TDataCallback;
import com.entersekt.sdk.callback.TransaktSDKCallback;
import com.entersekt.sdk.callback.TrustTokenCallback;
import com.entersekt.sdk.listener.AppMultifactorListener;
import com.entersekt.sdk.listener.AuthListener;
import com.entersekt.sdk.listener.ConnectionListener;
import com.entersekt.sdk.listener.NotifyListener;
import com.entersekt.sdk.listener.RegisterListener;
import com.entersekt.sdk.listener.TDataListener;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * Plugin to link Android TransaktSDK to Cordova
 *
 * @see <a href="https://github.com/apache/cordova-android">github</a> for CordovaPlugin source
 */
public class TransaktSDKPlugin extends CordovaPlugin {
    private static final String VERSION = "version";
    private static final String OS_PRIVILEGE = "osPrivilege";
    private static final String TYPE = "type";
    private static final String TEXT_BOXES = "textBoxes";
    private static final String BUTTONS = "buttons";
    private static final String NAME_VALUES = "nameValues";
    private static final String TITLE = "title";
    private static final String MIN_SIZE = "minSize";
    private static final String MAX_SIZE = "maxSize";
    private static final String CONSTRAINTS = "constraints";
    private static final String TEXT = "text";
    private static final String NAME = "name";
    private static final String ROLE = "role";
    private static final String LABEL = "label";
    private static final String IS_PIN_REQUIRED = "isPinRequired";
    private static final String TRANSAKT_SDK = "TransaktSDK";
    private static final String PIN_ENABLED = "pinEnabled";
    private static final String VALUE = "value";
    private static final String EXPIRES_IN_MILLIS = "expiresInMillis";
    private static final String TIMESTEP_SECONDS = "timestepSeconds";
    private static final String TOKEN = "token";
    private static final String EM_CERT_ID = "emCertId";
    private static final String CERTIFICATE_CHAIN = "certificateChain";
    private static final String TRUSTED_CERTIFICATES = "trustedCertificates";
    private static final String PING = "ping";
    private static final String SERVICE_ID = "serviceId";
    private static final String REGISTERED = "registered";
    private static final String REGISTERED_SERVICES = "registeredServices";
    private static final String EVENT = "event";
    private static final String ACTION = "action";
    private static final String CONNECTED = "connected";
    private static final String SENT = "sent";
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";
    private static final String PAYLOAD = "payload";
    private static final String LOCKED_DATA = "lockedData";
    private static final String UNLOCKED_DATA = "unlockedData";
    private static final String AUTH_ID = "authId";
    private static final String CHALLENGE = "challenge";

    private static final String LOG_TAG = "TransaktSDKPlugin";

    private enum Commands {
        start, connect, disconnect, getInfo, isConnected, getRegisteredServices, sendAuthAnswer,
        setAuthCallback, setNotifyCallback, setTDataCallback, setRegisterCallback,
        setConnectionCallback, setAppMultifactorCallback, appMultifactorSuccess, appMultifactorError,
        ping, getEmCert, isRegistered, getTrustToken, isOtpPinEnabled,
        getOtp, signup, enableDebug, setPushId, sendTData, getTrustedCertificates,
        secureDataLock, secureDataUnlock, setAppMultifactorCapabilities
    }

    private Auth currentAuth;

    private AppMultifactorCallback sdkAppMultifactorCallback;

    private String appMultifactorCapabilties;

    private TransaktSDK sdk;

    /**
     * Executes the request.
     *
     * This method is called from the WebView thread. To do a non-trivial amount of work, use:
     *     cordova.getThreadPool().execute(runnable);
     *
     * To run on the UI thread, use:
     *     cordova.getActivity().runOnUiThread(runnable);
     *
     * @param action          The action to execute.
     * @param args            The exec() arguments.
     * @param callbackContext The callback context used when calling back into JavaScript.
     * @return                Whether the action was valid.
     *
     * @see <a href="https://github.com/apache/cordova-android/blob/master/framework/src/org/apache/cordova/CordovaPlugin.java">CordovaPlugin.java</a>
     */
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) {
        String serviceId = args.optString(0, "");

//        Log.d(LOG_TAG, "args: " + args.toString());
//        Log.d(LOG_TAG, "action: " + action);

        Commands command = Commands.valueOf(action);
        switch (command) {
            // SDK Methods
            case start:
                start(callbackContext);
                break;
            case setPushId:
                setPushId(args);
                break;
            case connect:
                connect();
                break;
            case disconnect:
                disconnect();
                break;
            case getInfo:
                getInfo(callbackContext);
                break;
            case isConnected:
                isConnected(callbackContext);
                break;
            case getRegisteredServices:
                getRegisteredServices(callbackContext);
                break;
            case sendAuthAnswer:
                sendAuthAnswer(callbackContext, args);
                break;
            case enableDebug:
                enableDebug();
                break;
            // listeners
            case setAuthCallback:
                setAuthCallback(callbackContext);
                break;
            case setNotifyCallback:
                setNotifyCallback(callbackContext);
                break;
            case setTDataCallback:
                setTDataCallback(callbackContext);
                break;
            case setConnectionCallback:
                setConnectionCallback(callbackContext);
                break;
            case setRegisterCallback:
                setRegisterCallback(callbackContext);
                break;
            case setAppMultifactorCallback:
                setAppMultifactorCallback(callbackContext);
                break;
            case appMultifactorSuccess:
                appMultifactorSuccess(args);
                break;
            case appMultifactorError:
                appMultifactorError();
                break;
            case setAppMultifactorCapabilities:
                setAppMultifactorCapabilties(args);
                break;
            // service Methods
            case ping:
                ping(callbackContext, serviceId);
                break;
            case getEmCert:
                getEmCert(callbackContext, serviceId);
                break;
            case isRegistered:
                isRegistered(callbackContext, serviceId);
                break;
            case sendTData:
                sendTData(callbackContext, serviceId, args);
                break;
            case getTrustToken:
                getTrustToken(callbackContext, serviceId);
                break;
            case isOtpPinEnabled:
                isOtpPinEnabled(callbackContext, serviceId);
                break;
            case getOtp:
                getOtp(callbackContext, serviceId, args);
                break;
            case signup:
                signup(callbackContext, serviceId, args);
                break;
            case getTrustedCertificates:
                getTrustedCertificates(callbackContext, serviceId);
                break;
            case secureDataLock:
                secureDataLock(callbackContext, serviceId, args);
                break;
            case secureDataUnlock:
                secureDataUnlock(callbackContext, serviceId, args);
                break;
            default:
                Log.d(LOG_TAG, "action: " + action + " not understood");
                return false;
        }
        return true;
    }

    private void start(final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                TransaktSDK.getConfig().setAppMultifactorCapabilities(appMultifactorCapabilties);
                TransaktSDK.start(cordova.getActivity().getApplicationContext(),
                        new TransaktSDKCallback() {
                            @Override
                            public void onReady(TransaktSDK transaktSDK) {
                                sdk = transaktSDK;
                                callbackContext.success();
                            }

                            @Override
                            public void onError(Error error) {
                                PluginResult pluginResult = new PluginResult(
                                        PluginResult.Status.ERROR, error.name());
                                callbackContext.sendPluginResult(pluginResult);
                            }
                        });
            }
        });
    }

    @Override
    public void onDestroy() {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                TransaktSDK.setConnectionListener(null);
                TransaktSDK.setAuthListener(null);
                TransaktSDK.setNotifyListener(null);
                TransaktSDK.setRegisterListener(null);
                TransaktSDK.setTDataListener(null);
                TransaktSDK.destroy(cordova.getActivity().getApplicationContext());
            }
        });
        super.onDestroy();
    }

    private void connect() {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.connect();
            }
        });
    }

    private void disconnect() {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.disconnect();
            }
        });
    }

    private void setPushId(final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                final String pushId = args.optString(0, null);
                if (pushId != null) TransaktSDK.getConfig().setGoogleCloudMessagingId(pushId);
            }
        });
    }

    private void getInfo(final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                Info info = TransaktSDK.getInfo();
                JSONObject json = json(
                        Entry.get(VERSION, info.getVersion()),
                        Entry.get(OS_PRIVILEGE, info.getOsPrivilege().toString()));
                callbackContext.success(json);
            }
        });
    }

    private void isConnected(final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                JSONObject json = json(
                        Entry.get(CONNECTED, sdk.isConnected()),
                        Entry.get(ACTION, sdk.getConnectionContext().getAction().toString()),
                        Entry.get(EVENT, sdk.getConnectionContext().getEvent().toString()));
                callbackContext.success(json);
            }
        });
    }

    private void getRegisteredServices(final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                Set<Service> services = sdk.getRegisteredServices();

                JSONArray serviceArray = new JSONArray();
                for (Service service : services) {
                    serviceArray.put(service.getServiceId());
                }

                JSONObject servicesJson = json(Entry.get(REGISTERED_SERVICES, serviceArray));
                callbackContext.success(servicesJson);

                JSONObject json = json(Entry.get(SENT, true));
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                callbackContext.sendPluginResult(pluginResult);
            }
        });
    }

    private void sendAuthAnswer(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                if (currentAuth != null) {
                    final int BUTTON = 0;
                    final int PIN = 1;
                    final int TEXT_BOXES = 2;

                    String buttonText = args.optString(BUTTON, "");
                    String pin = args.optString(PIN, null);
                    JSONArray textBoxes = args.optJSONArray(TEXT_BOXES);

                    setAuthAnswerFromJson(currentAuth, buttonText, pin, textBoxes);

                    sdk.sendAuthAnswer(currentAuth, new AuthAnswerCallback() {
                        @Override
                        public void onSuccess(Service service, Auth auth) {
                            JSONObject json = json(Entry.get(SENT, true));
                            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                            callbackContext.sendPluginResult(pluginResult);
                            currentAuth = null;
                        }

                        @Override
                        public void onError(Service service, Error error, Auth auth) {
                            JSONObject json = json(
                                    Entry.get(ERROR, error.name()),
                                    Entry.get(ERROR_DESCRIPTION, error.toString()));
                            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                            callbackContext.sendPluginResult(pluginResult);
                        }
                    });

                } else {
                    JSONObject json = json(Entry.get(SENT, false));
                    PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                    callbackContext.sendPluginResult(pluginResult);
                }
            }
        });
    }

    // The "listeners" in the native code
    private void setAuthCallback(final CallbackContext callbackContext) {
        TransaktSDK.setAuthListener(new AuthListener() {

            @Override
            public void onAuthReceived(Service service, Auth auth) {
                String serviceId = service.getServiceId();
                currentAuth = auth;

                JSONObject json = json(
                        Entry.get(TITLE, auth.getTitle()),
                        Entry.get(TEXT, auth.getText()),
                        Entry.get(NAME_VALUES, authNameValuesToJson(auth.getNameValues())),
                        Entry.get(BUTTONS, authButtonsToJson(auth.getButtons())),
                        Entry.get(TEXT_BOXES, authTextBoxesToJson(auth.getTextBoxes())),
                        Entry.get(SERVICE_ID, serviceId));

                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }
        });
    }

    private void setNotifyCallback(final CallbackContext callbackContext) {
        TransaktSDK.setNotifyListener(new NotifyListener() {
            @Override
            public void onNotify(Service service, Notify notify) {
                JSONObject json = json(
                        Entry.get(SERVICE_ID, service.getServiceId()),
                        Entry.get(TYPE, notify.getType()),
                        Entry.get(TEXT, notify.getText()));
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }
        });
    }

    private void setTDataCallback(final CallbackContext callbackContext) {
        TransaktSDK.setTDataListener(new TDataListener() {
            @Override
            public void onTData(Service service, TData tData) {
                JSONObject json = json(
                        Entry.get(SERVICE_ID, service.getServiceId()),
                        Entry.get(PAYLOAD, tData.getPayload()));
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }
        });
    }

    private void setConnectionCallback(final CallbackContext callbackContext) {
        TransaktSDK.setConnectionListener(new ConnectionListener() {
            @Override
            public void onDisconnected(ConnectionContext context) {
                JSONObject json = json(
                        Entry.get(CONNECTED, false),
                        Entry.get(ACTION, context.getAction().toString()),
                        Entry.get(EVENT, context.getEvent().toString()));
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }

            @Override
            public void onConnected(ConnectionContext context) {
                JSONObject json = json(
                        Entry.get(CONNECTED, true),
                        Entry.get(ACTION, context.getAction().toString()),
                        Entry.get(EVENT, context.getEvent().toString()));
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }
        });

    }

    private void setRegisterCallback(final CallbackContext callbackContext) {
        TransaktSDK.setRegisterListener(new RegisterListener() {
            @Override
            public void onUnregister(Service service) {
                JSONObject json = json(
                        Entry.get(REGISTERED, false),
                        Entry.get(SERVICE_ID, service.getServiceId()));
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }

            @Override
            public void onRegister(Service service) {
                JSONObject json = json(
                        Entry.get(REGISTERED, true),
                        Entry.get(SERVICE_ID, service.getServiceId()));
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }
        });
    }

    private void setAppMultifactorCallback(final CallbackContext callbackContext) {
        TransaktSDK.setAppMultifactorListener(new AppMultifactorListener() {
            @Override
            public void onAppMultifactor(AppMultifactor appMultifactor, AppMultifactorCallback appMultifactorCallback) {
                sdkAppMultifactorCallback = appMultifactorCallback;
                JSONObject json = json(
                        Entry.get(AUTH_ID, appMultifactor.getAuthId()),
                        Entry.get(CHALLENGE, appMultifactor.getChallenge())
                );
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, json);
                pluginResult.setKeepCallback(true);
                callbackContext.sendPluginResult(pluginResult);
            }
        });
    }

    private void appMultifactorSuccess(JSONArray args) {
        final int RESPONSE = 0;
        String response = args.optString(RESPONSE, "");
        sdkAppMultifactorCallback.onSuccess(response);
    }

    private void appMultifactorError() {
        sdkAppMultifactorCallback.onError();
    }

    private void setAppMultifactorCapabilties(JSONArray args) {
        final int APP_MULTIFACTOR_CAPABILITIES = 0;
        appMultifactorCapabilties = args.optString(APP_MULTIFACTOR_CAPABILITIES, "");
    }

    // TransaktSDK.service Methods
    @SuppressWarnings("deprecation")
    private void ping(final CallbackContext callbackContext, final String serviceId) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).ping(new PingCallback() {
                    @Override
                    public void onSuccess(Service service) {
                        JSONObject json = json(
                                Entry.get(PING, true),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void getEmCert(final CallbackContext callbackContext, final String serviceId) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                EmCert emCert = sdk.getService(serviceId).getEmCert();
                String emCertId = emCert.getEmCertId();
                if (emCertId != null && emCertId.length() > 0) {
                    JSONArray certificateChain = new JSONArray();
                    for (Certificate certificate : emCert.getCertificateChain()) {
                        try {
                            certificateChain.put(
                                    Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP));
                        } catch (CertificateEncodingException ignored) {}
                    }
                    JSONObject json = json(
                            Entry.get(EM_CERT_ID, emCertId),
                            Entry.get(CERTIFICATE_CHAIN, certificateChain),
                            Entry.get(SERVICE_ID, serviceId));
                    callbackContext.success(json);
                } else {
                    PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR, "No emCert");
                    callbackContext.sendPluginResult(pluginResult);
                }
            }
        });
    }

    private void isRegistered(final CallbackContext callbackContext, final String serviceId) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                JSONObject json = json(
                        Entry.get(REGISTERED, sdk.getService(serviceId).isRegistered()),
                        Entry.get(SERVICE_ID, serviceId));
                callbackContext.success(json);
            }
        });
    }

    private void getTrustToken(final CallbackContext callbackContext, final String serviceId) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).getTrustToken(new TrustTokenCallback() {
                    @Override
                    public void onSuccess(Service service, TrustToken trustToken) {
                        JSONObject json = json(
                                Entry.get(TOKEN, trustToken.getToken()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void isOtpPinEnabled(final CallbackContext callbackContext, final String serviceId) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).getOtp(new OtpCallback() {
                    @Override
                    public void onSuccess(Service service, Otp otp) {
                        JSONObject json = json(
                                Entry.get(PIN_ENABLED, otp.isPinEnabled()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void getOtp(final CallbackContext callbackContext, final String serviceId, JSONArray args) {
        final int PIN = 1;
        final String otpPin = args.optString(PIN, null);

        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).getOtp(new OtpCallback() {
                    @Override
                    public void onSuccess(Service service, Otp otp) {
                        String otpValue;
                        if (otpPin == null || otpPin.equals("null") || otpPin.equals("")) {
                            otpValue = otp.getValue();
                        } else {
                            otpValue = otp.getValue(otpPin);
                        }

                        JSONObject json = json(
                                Entry.get(VALUE, otpValue),
                                Entry.get(EXPIRES_IN_MILLIS, otp.expiresInMillis()),
                                Entry.get(TIMESTEP_SECONDS, otp.getTimestepSeconds()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void signup(final CallbackContext callbackContext, final String serviceId, JSONArray args) {
        final int CODE = 1;
        final int CREDENTIAL = 2;

        final Signup signup = new Signup();
        signup.setSignupCode(args.optString(CODE, ""));
        signup.setCredential(args.optString(CREDENTIAL, ""));

        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).signup(signup, new SignupCallback() {
                    @Override
                    public void onSuccess(Service service) {
                        JSONObject json = json(
                                Entry.get(SENT, true),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void sendTData(final CallbackContext callbackContext, final String serviceId, JSONArray args) {
        final int PAYLOAD = 1;

        String payload = args.optString(PAYLOAD, "");

        final TData tData = new TData();
        tData.setPayload(payload);

        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).sendTData(tData, new TDataCallback() {
                    @Override
                    public void onSuccess(Service service) {
                        JSONObject json = json(
                                Entry.get(SENT, true),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void getTrustedCertificates(final CallbackContext callbackContext, final String serviceId) {
        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).getCertificatePinner(new CertificatePinnerCallback() {
                    @Override
                    public void onSuccess(Service service, CertificatePinner certificatePinner) {
                        JSONArray certificateSet = new JSONArray();
                        for (Certificate certificate : certificatePinner.getTrustedCertificates()) {
                            try {
                                certificateSet.put(
                                        Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP));
                            } catch (CertificateEncodingException ignored) {}
                        }

                        JSONObject json = json(
                                Entry.get(TRUSTED_CERTIFICATES, certificateSet),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void secureDataLock(final CallbackContext callbackContext, final String serviceId, JSONArray args) {
        final int DATA_TO_LOCK = 1;
        final String dataToLock = args.optString(DATA_TO_LOCK, null);

        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).getSecureData(new SecureDataCallback() {
                    @Override
                    public void onSuccess(Service service, SecureData secureData) {
                        String lockedData = secureData.lock(dataToLock);
                        JSONObject json = json(
                                Entry.get(LOCKED_DATA, lockedData),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void secureDataUnlock(final CallbackContext callbackContext, final String serviceId, JSONArray args) {
        final int DATA_TO_UNLOCK = 1;
        final String dataToUnlock = args.optString(DATA_TO_UNLOCK, null);

        cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {
                sdk.getService(serviceId).getSecureData(new SecureDataCallback() {
                    @Override
                    public void onSuccess(Service service, SecureData secureData) {
                        String unlockedData = null;
                        try {
                            unlockedData = secureData.unlock(dataToUnlock);
                        } catch (SecureDataFailed ignored) {}

                        JSONObject json = json(
                                Entry.get(UNLOCKED_DATA, unlockedData),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }

                    @Override
                    public void onError(Service service, Error error) {
                        JSONObject json = json(
                                Entry.get(ERROR, error.name()),
                                Entry.get(ERROR_DESCRIPTION, error.toString()),
                                Entry.get(SERVICE_ID, service.getServiceId()));
                        callbackContext.success(json);
                    }
                });
            }
        });
    }

    private void enableDebug() {
        TransaktSDK.setLogger(new Logger() {
            @Override
            public void write(int logLevel, String arg0) {
                Log.println(logLevel, TRANSAKT_SDK, arg0);
            }

            @Override
            public boolean isDebug() {
                return true;
            }
        });
    }

    private JSONObject json(Entry... entries) {
        JSONObject json = new JSONObject();
        try {
            for (Entry entry : entries) {
                json.put(entry.key, entry.value);
            }
        } catch (JSONException ignored) {}
        return json;
    }

    private JSONArray authNameValuesToJson(Collection<NameValue> nameValues) {
        JSONArray nameValuesJson = new JSONArray();
        try {
            for (NameValue nameValue : nameValues) {
                JSONObject nameValueJson = new JSONObject();
                nameValueJson.put(NAME, nameValue.getName());
                nameValueJson.put(VALUE, nameValue.getValue());
                nameValuesJson.put(nameValueJson);
            }
        } catch (JSONException ignored) {}
        return nameValuesJson;
    }

    private JSONArray authButtonsToJson(Collection<Button> buttons) {
        JSONArray buttonsJson = new JSONArray();
        try {
            for (Button button : buttons) {
                JSONObject buttonJson = new JSONObject();
                buttonJson.put(LABEL, button.getLabel());
                buttonJson.put(ROLE, button.getRole());
                buttonJson.put(IS_PIN_REQUIRED, button.isPinRequired());
                buttonsJson.put(buttonJson);
            }
        } catch (JSONException ignored) {}
        return buttonsJson;
    }

    private JSONArray authTextBoxesToJson(Collection<TextBox> textBoxes) {
        JSONArray textBoxesJson = new JSONArray();
        try {
            for (TextBox textBox : textBoxes) {
                JSONArray constraintsJson = new JSONArray();
                for (String constraint : textBox.getConstraints()) {
                    constraintsJson.put(constraint);
                }

                JSONObject textBoxJson = new JSONObject();
                textBoxJson.put(LABEL, textBox.getLabel());
                textBoxJson.put(TEXT, textBox.getText());
                textBoxJson.put(MAX_SIZE, textBox.getMaxSize());
                textBoxJson.put(MIN_SIZE, textBox.getMinSize());
                textBoxJson.put(CONSTRAINTS, constraintsJson);
                textBoxesJson.put(textBoxJson);
            }
        } catch (JSONException ignored) {}
        return textBoxesJson;
    }

    private void setAuthAnswerFromJson(Auth auth,
                                       String buttonText,
                                       String pin,
                                       JSONArray textBoxesJson) {
        // Set button response
        for (Button button : auth.getButtons()) {
            if (button.getLabel().equals(buttonText)) {
                button.select();
                if (button.isPinRequired() && pin != null && !pin.equals("null")) {
                    button.setPin(pin);
                }
            }
        }

        // Set textBoxes response
        if (textBoxesJson != null) {
            List<TextBox> textBoxes = auth.getTextBoxes();
            for (int i = 0; i < auth.getTextBoxes().size(); i++) {
                String response = textBoxesJson.optString(i, "");
                textBoxes.get(i).setUserResponse(response);
            }
        }
    }

    private static class Entry {
        private final String key;
        private final Object value;

        static Entry get(String key, Object value) {
            return new Entry(key, value);
        }

        Entry(String key, Object value) {
            this.key = key;
            this.value = value;
        }
    }
}
