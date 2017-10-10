var TransaktSDK = function () {
};
/**
 *  SDK Failure logger
 *
 *  @param Function
 *
 *  @return Error message
 */
TransaktSDK.prototype.failure = function (msg) {
    console.log("TransaktSDK Error: " + msg)
}

TransaktSDK.prototype.enableDebug = function () {
    cordova.exec(null, this.failure, 'TransaktSDKPlugin', "enableDebug", []);
};

// TransaktSDK Methods
TransaktSDK.prototype.start = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "start", []);
};

TransaktSDK.prototype.connect = function () {
    cordova.exec(null, this.failure, 'TransaktSDKPlugin', "connect", []);
};

TransaktSDK.prototype.disconnect = function () {
    cordova.exec(null, this.failure, 'TransaktSDKPlugin', "disconnect", []);
};

TransaktSDK.prototype.getInfo = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "getInfo", []);
};

TransaktSDK.prototype.isConnected = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "isConnected", []);
};

TransaktSDK.prototype.getRegisteredServices = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "getRegisteredServices", []);
};

TransaktSDK.prototype.sendAuthAnswer = function (callback, userResponse, pin, textboxUserResponses) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "sendAuthAnswer", [userResponse, pin, textboxUserResponses]);
};

TransaktSDK.prototype.setPushId = function (pushId) {
    cordova.exec(null, this.failure, 'TransaktSDKPlugin', "setPushId", [pushId]);
};

// The "listeners" in the native code
// Note: the callback has been added as a parameter for the windows code, since it does not support calling the successCallback multiple times.
// See: http://blog.vjrantal.net/2015/03/12/building-a-cordova-plugin-including-native-code-for-windows-platform/
TransaktSDK.prototype.setAuthCallback = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "setAuthCallback", [callback]);
};

TransaktSDK.prototype.setNotifyCallback = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "setNotifyCallback", [callback]);
};

TransaktSDK.prototype.setTDataCallback = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "setTDataCallback", [callback]);
};

TransaktSDK.prototype.setRegisterCallback = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "setRegisterCallback", [callback]);
};

TransaktSDK.prototype.setConnectionCallback = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "setConnectionCallback", [callback]);
};

TransaktSDK.prototype.setFingerprintCallback = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "setFingerprintCallback", [callback]);
};

TransaktSDK.prototype.setAppMultifactorCapabilities = function (appMultifactorCapabilities) {
    cordova.exec(null, this.failure, 'TransaktSDKPlugin', "setAppMultifactorCapabilities",[appMultifactorCapabilities]);
};

// TransaktSDK.service Methods
TransaktSDK.prototype.ping = function (callback, serviceId) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "ping", [serviceId]);
};

TransaktSDK.prototype.getEmCert = function (callback, serviceId) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "getEmCert", [serviceId]);
};

TransaktSDK.prototype.isRegistered = function (callback, serviceId) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "isRegistered", [serviceId]);
};

TransaktSDK.prototype.getTrustToken = function (callback, serviceId) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "getTrustToken", [serviceId]);
};

TransaktSDK.prototype.getOtp = function (callback, serviceId, pin) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "getOtp", [serviceId, pin]);
};

TransaktSDK.prototype.isOtpPinEnabled = function (callback, serviceId) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "isOtpPinEnabled", [serviceId]);
};

TransaktSDK.prototype.signup = function (callback, serviceId, signupCode, signupCredential) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "signup", [serviceId, signupCode, signupCredential]);
};

TransaktSDK.prototype.sendTData = function (callback, serviceId, payload) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "sendTData", [serviceId, payload]);
};

/**
  * Returns:
  *
  * {
  *     "serviceId": "12345678",
  *     "trustedCertificates": ["abcef...ghijk", "lmnop...qrstu"]
  * }
  */
TransaktSDK.prototype.getTrustedCertificates = function (callback, serviceId) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "getTrustedCertificates", [serviceId]);
};

TransaktSDK.prototype.secureDataLock = function (callback, serviceId, dataToLock) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "secureDataLock", [serviceId, dataToLock]);
};

TransaktSDK.prototype.secureDataUnlock = function (callback, serviceId, dataToUnlock) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "secureDataUnlock", [serviceId, dataToUnlock]);
};

TransaktSDK.prototype.appMultifactorSuccess = function (callback, response) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "appMultifactorSuccess", [response]);
};

TransaktSDK.prototype.appMultifactorError = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "appMultifactorError", []);
};

TransaktSDK.prototype.setAppMultifactorCallback = function (callback) {
    cordova.exec(callback, this.failure, 'TransaktSDKPlugin', "setAppMultifactorCallback", [callback]);
};

var transaktSDK = new TransaktSDK();
module.exports = transaktSDK;
