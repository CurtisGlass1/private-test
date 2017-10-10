var arrayMatcher = new RegExp("\\[object .*Array\\]", 'i');

function MakeStringifiable(obj) {
    var typeInfo = Object.prototype.toString.call(obj);
    if (arrayMatcher.test(typeInfo)) {
        var array = new Array();
        for (var val in obj) {
            array[val] = typeof obj[val] === 'object' ? MakeStringifiable(obj[val]) : obj[val];
        }
        return array;
    } else {
        var result = new Object();
        for (var val in obj) {
            result[val] = typeof obj[val] === 'object' ? MakeStringifiable(obj[val]) : obj[val];
        }
        return result;
    }
}

cordova.commandProxy.add("TransaktSDKPlugin", {
    enableDebug: function (successCallback, errorCallback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.enableDebug();
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.onloggingevent = function (loggingInfo) {
            window.console.log(loggingInfo.level + ": " + loggingInfo.message);
        }
        successCallback();
    },

    start: function (successCallback, errorCallback) {
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.start();
        promise.done(function () {
            successCallback();
        },
        function () {
            errorCallback();
        });
    },

    connect: function (successCallback, errorCallback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.connect();
    },

    disconnect: function (successCallback, errorCallback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.disconnect();
    },

    getInfo: function (successCallback, errorCallback) {
        var info = TransaktSdkRuntimeComponent.TransaktSdkRuntime.getInfo();
        successCallback(MakeStringifiable(info));
    },

    isConnected: function (successCallback, errorCallback) {
        var connectionInfo = TransaktSdkRuntimeComponent.TransaktSdkRuntime.isConnected();
        successCallback(MakeStringifiable(connectionInfo));
    },

    setPushId: function (successCallback, errorCallback, pushId) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.setPushId(pushId[0]);
    },

    setConnectionCallback: function (successCallback, errorCallback, callback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.onconnectionevent = function (connectionInfo) {
            callback[0](MakeStringifiable(connectionInfo.detail[0]));
        }
    },

    setAuthCallback: function (successCallback, errorCallback, callback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.onauthevent = function (auth) {
            callback[0](MakeStringifiable(auth.detail[0]));
        }
    },

    setNotifyCallback: function (successCallback, errorCallback, callback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.onnotifyevent = function (notify) {
            callback[0](MakeStringifiable(notify.detail[0]));
        }
    },

    setTDataCallback: function (successCallback, errorCallback, callback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.ontdataevent = function (tdata) {
            callback[0](MakeStringifiable(tdata.detail[0]));
        }
    },

    setRegisterCallback: function (successCallback, errorCallback, callback) {
        TransaktSdkRuntimeComponent.TransaktSdkRuntime.onregisterevent = function (info) {
            callback[0](MakeStringifiable(info.detail[0]));
        }
    },

    getRegisteredServices: function (successCallback, errorCallback) {
        var servicesInfo = TransaktSdkRuntimeComponent.TransaktSdkRuntime.getRegisteredServices();
        successCallback(MakeStringifiable(servicesInfo));
    },

    ping: function (successCallback, errorCallback, serviceId) {
        var pingInfo = TransaktSdkRuntimeComponent.TransaktSdkRuntime.ping(serviceId[0]);
        successCallback(MakeStringifiable(pingInfo));
    },

    getEmCert: function (successCallback, errorCallback, serviceId) {
        var emCertInfo = TransaktSdkRuntimeComponent.TransaktSdkRuntime.getEmCert(serviceId[0]);
        successCallback(MakeStringifiable(emCertInfo));
    },

    isRegistered: function (successCallback, errorCallback, serviceId) {
        var registeredInfo = TransaktSdkRuntimeComponent.TransaktSdkRuntime.isRegistered(serviceId[0]);
        successCallback(MakeStringifiable(registeredInfo));
    },

    getTrustToken: function (successCallback, errorCallback, serviceId) {
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.getTrustToken(serviceId[0]);
        promise.done(function (trustTokenInfo) {
            successCallback(MakeStringifiable(trustTokenInfo));
        },
        function () {
            errorCallback();
        });
    },

    isOtpPinEnabled: function (successCallback, errorCallback, serviceId) {
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.isOtpPinEnabled(serviceId[0]);
        promise.done(function (otpPinInfo) {
            successCallback(MakeStringifiable(otpPinInfo));
        },
        function () {
            errorCallback();
        });
    },

    getOtp: function (successCallback, errorCallback, args) {
        var serviceId = args[0];
        var pin = args[1];
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.getOtp(serviceId, pin);
        promise.done(function (otpInfo) {
            successCallback(MakeStringifiable(otpInfo));
        },
        function () {
            errorCallback();
        });
    },

    signup: function (successCallback, errorCallback, args) {
        var serviceId = args[0];
        var signupCode = args[1];
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.signup(serviceId, signupCode);
        promise.done(function (signupInfo) {
            successCallback(MakeStringifiable(signupInfo));
        },
        function () {
            errorCallback();
        });
    },

    sendTData: function (successCallback, errorCallback, args) {
        var serviceId = args[0];
        var payload = args[1];
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.sendTData(serviceId, payload);
        promise.done(function (tDataInfo) {
            successCallback(MakeStringifiable(tDataInfo));
        },
        function () {
            errorCallback();
        });
    },

    sendAuthAnswer: function (successCallback, errorCallback, args) {
        var userResponse = args[0];
        var pin = args[1];
        var textboxUserResponses = args[2];
        if (pin == null) pin = "";
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.sendAuthAnswer(userResponse, pin, textboxUserResponses);
        promise.done(function (callbackInfo) {
            successCallback(MakeStringifiable(callbackInfo));
        },
        function () {
            errorCallback();
        });
    },

    getTrustedCertificates: function (successCallback, errorCallback, args) {
        var serviceId = args[0];
        var promise = TransaktSdkRuntimeComponent.TransaktSdkRuntime.getTrustedCertificates(serviceId);
        promise.done(function (callbackInfo) {
            successCallback(MakeStringifiable(callbackInfo));
        },
        function () {
            errorCallback();
        });
    }
});