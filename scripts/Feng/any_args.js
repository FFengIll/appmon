




Java.perform(function () {
    function hookOverloads(className, func, callback, before, after) {
        className = className.replace('/', '.')
        var clazz = Java.use(className);
        if (!clazz || !clazz[func]) {
            return
        }
        var overloads = clazz[func].overloads;
        for (var i in overloads) {
            if (overloads[i].hasOwnProperty('argumentTypes')) {
                var parameters = [];

                var curArgumentTypes = overloads[i].argumentTypes, args = [], argLog = '[';
                for (var j in curArgumentTypes) {
                    var cName = curArgumentTypes[j].className;
                    parameters.push(cName);
                    argLog += "'(" + cName + ") ' + v" + j + ",";
                    args.push('v' + j);
                }
                argLog += ']';

                // var script = "var ret = this." + func + '(' + args.join(',') + ") || '';\n"
                //     + "console.log(JSON.stringify(" + argLog + "));\n"
                //     + "return ret;"

                // args.push(script);

                /* --- Do real hook and call --- */
                // clazz[func].overload.apply(this, parameters).implementation = Function.apply(null, args);
                clazz[func].overload.apply(this, parameters).implementation = function () {
                    var res = null
                    var extra = null

                    if (before) {
                        try {
                            extra = before(arguments)
                        } catch (e) {
                            console.log(e);
                        }
                    }
                    
                    res = this[func].apply(this, arguments);
                    
                    if (after) {
                        try {
                            extra = after(res)
                        } catch (e) {
                            console.log(e);
                        }
                    }

                    callback(className, this, func, arguments, res, extra)
                    return res;
                }

            }
        }
    }

    function echoMethodArgs(cls, obj, func, args, res, extra) {

        /*   --- Message Header --- */
        var msg = {};
        msg.time = new Date();
        msg.txnType = "FFeng: method args & res";
        msg.lib = cls;
        msg.method = func;
        msg.artifact = [];


        /*   --- Message Payload Body --- */
        var payload = {};
        var args_data = []
        for (var i in args) {
            args_data.push(args[i] ? args[i].toString() : args[i])
        }
        payload.name = 'method args & res'
        payload.argSeq = 0;
        payload.value = {
            class: cls,
            method: func,
            args: args_data,
            obj: obj ? obj.toString() : null,
            result: res ? res.toString() : null,
            result_type: res,
            extra: extra,
            trace: getTraceBack()
        };

        /* --- Load --- */
        msg.artifact.push(payload);

        /* --- Send --- */
        // console.log(JSON.stringify(msg))
        send(JSON.stringify(msg));
    }

    function Where(stack) {
        var at = "";
        for (var i = 0; i < stack.length; ++i) {
            at += stack[i].toString() + "\n";
        }
        return at;
    }

    function getException(e) {
        try {
            var stack = e.getStackTrace();
            var full_call_stack = Where(stack);
            return full_call_stack;
        } catch (e) {
            return "";
        }
    }
    var ThreadDef = Java.use("java.lang.Thread");

    function getTraceBack() {
        try {
            var threadinstance = ThreadDef.$new();

            var stack = threadinstance.currentThread().getStackTrace();
            var full_call_stack = Where(stack);
            return full_call_stack;
        } catch (e) {
            console.log(e)
            return "";
        }
    }
    if (1) {
        // com.alibaba.android.security.activity
        // hookOverloads('com.aliwork.alilang.login.session.Session', 'getCertInfo', echoMethodArgs, true)
        // hookOverloads('com/aliwork/alilang/login/network/NetworkClient'.replace('/', '.'), 'execute', echoMethodArgs,  null,  null);
        // hookOverloads('com.aliwork.alilang.login.network.api.okhttp.OkHttpEngine', 'buildCall', echoMethodArgs,  null,  null);

        // hookOverloads('com.aliwork.network/NetworkResponse'.replace('/', '.'), 'getBytedata', echoMethodArgs,  null,  null);
        hookOverloads('com/aliwork/alilang/login/network/api/NetworkRequest'.replace('/', '.'), 'a', echoMethodArgs, null, null);

    }

    function changeRequest(req) {
        const path = req.getPath()
        if (path == '/auth/rpc/cert/apply.json') {
            req.addParam('dn', 'miPhone');
            req.addParam('osVersion', '13.5.1');
            req.addParam('account', 'wxm.wxm');
            req.addParam('device_id', 'T5ZLvUJLOitggTVzE+39jLysmvX9ii5u');
            req.addParam('macs', '84:73:03:4E:9D:9A');
            req.addParam('osType', 'ios_phone');

            console.log(req.toString());

        } else if (path == 'auth/rpc/identify/verify.json') {
            // req.addParam('device_id', 'LqxL39RLOpIrpTVy3O6HbJVdAyUnwTcd');
        }
    }

    if (1) {
        // com.alibaba.dw.phone
        hookOverloads('com.aliwork.alilang.login.common.LoginContext'.replace('/', '.'), 'getUmidFileSufix', echoMethodArgs, null, null);


        hookOverloads('Lcom/aliwork/alilang/login/certificate/CertificateRepository;', 'getDownloadCertRequest', echoMethodArgs,
            null,
            function (res) { return changeRequest(res) },
        )
        // hookOverloads('java.lang.StringBuilder', '$init', echoMethodArgs);
        // hookOverloads('java.lang.StringBuilder', '$init', echoMethodArgs);
        // hookOverloads('com.aliyun.sls.android.sdk.core.auth.PlainTextAKSKCredentialProvider', '$init', echoMethodArgs);
        // hookOverloads('com/aliyun/sls/android/sdk/b/b', '$init', echoMethodArgs);
        // hookOverloads('com/aliyun/sls/android/sdk/a/a/d', '$init', echoMethodArgs);

        // hookOverloads('com/aliwork/alilang/login/certificate/CertificateRepository'.replace('/', '.'), 'getDownloadCertRequest', echoMethodArgs, true);

        hookOverloads('com/aliwork/alilang/login/network/api/NetworkRequest'.replace('/', '.'), 'getPath', echoMethodArgs,
            null,
            null
        );

        // hookOverloads('com/aliwork/alilang/login/network/api/NetworkRequest'.replace('/', '.'), '$init', echoMethodArgs,  null,  null);
        hookOverloads('com/aliwork/alilang/login/network/NetworkClient'.replace('/', '.'), 'execute', echoMethodArgs,

            null,
            null
        );
        // hookOverloads('com.aliwork.alilang.login.network.api.okhttp.OkHttpEngine', 'buildCall', echoMethodArgs,  null,  null);

        hookOverloads('com/aliwork/alilang/login/network/api/NetworkResponse'.replace('/', '.'), 'getBody', echoMethodArgs,
            null,
            function (res) {
                return [res.content, res.password]
            }
        );
        // hookOverloads('com.aliwork.alilang.login.exchange.PublicAccountRepository', 'getLoginPublicAccountRequest', echoMethodArgs,  null,  null);
        // hookOverloads('com.aliwork.alilang.login.exchange.PublicAccountRepository', 'getPublicAccountListRequest', echoMethodArgs,  null,  null);
        // hookOverloads('com.aliwork.alilang.login.session.Session'.replace('/', '.'), 'getSecurityToken', echoMethodArgs, true);

        // hookOverloads('com.aliwork.alilang.login.network.api.httpurl.HttpUrlCall', 'doRequest', echoMethodArgs,  null,  null)
        // hookOverloads('com.aliwork.alilang.login.login.UmidHelper'.replace('/', '.'), 'getSecurityToken', echoMethodArgs, true);


        // // hookOverloads('com/alibaba/wireless/security/open/SecurityGuardManager'.replace('/', '.'), 'getInitializer', echoMethodArgs,  null,  null);
        // hookOverloads('com/taobao/dp/DeviceSecuritySDK'.replace('/', '.'), 'getSecurityToken', echoMethodArgs, true);




        // hookOverloads('com.aliwork.alilang.login.network.api.NetworkRequest', 'setUrl', echoMethodArgs, null,  null);
        // hookOverloads('com.aliwork.alilang.login.network.api.NetworkRequest', 'getUrl', echoMethodArgs, null,  null);
        // hookOverloads('com.aliwork.alilang.login.network.NetworkClient', 'execute', echoMethodArgs, null,  null);
        // hookOverloads('com.aliwork.alilang.login.network.api.httpurl.HttpUrlCall', 'doRequest', echoMethodArgs, null,  null);
        // hookOverloads('com.aliwork.alilang.login.network.api.okhttp.OkHttpCall', 'execute', echoMethodArgs, null,  null);
    }


})