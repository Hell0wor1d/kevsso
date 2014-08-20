/* author: Kev7n Wang
 * description: supports single sign on & single sign out
 * note： Need to reference jQuery Library.
 * version: beta v1.2.3
 */
var kevsso;
(function (kevsso) {
    //api Options default Options
    var apiOptions = {
        baseApiAddress: 'http://192.168.0.233:911',
        passportKeyName: 'passport'
    };

    /**
     * util
     */
    var util = (function () {
        /**
         * Creates a new util.
         * @constructor
         */
        function util() {
        }

        //isType
        //@param name
        /**
         * @return {boolean}
         */
        util.isType = function (obj, objTypeName, typeName) {
            return ( typeof obj == objTypeName) && obj.constructor == typeName;
        };

        //isArray
        //@param obj
        /**
         * @return {boolean}
         */
        util.isArray = function (obj) {
            return this.isType(obj, 'object', Array);
        };

        //isString
        //@param str
        /**
         * @return {boolean}
         */
        util.isString = function (str) {
            return this.isType(str, 'string', String);
        };

        //isNumber
        //@param obj
        /**
         * @return {boolean}
         */
        util.isNumber = function (obj) {
            return this.isType(obj, 'number', Number);
        };

        //isDate
        //@param obj
        /**
         * @return {boolean}
         */
        util.isDate = function (obj) {
            return this.isType(obj, 'object', Date);
        };

        //isFunction
        //@param obj
        /**
         * @return {boolean}
         */
        util.isFunction = function (obj) {
            return this.isType(obj, 'function', Function);
        };

        //isObject
        //@param obj
        /**
         * @return {boolean}
         */
        util.isObject = function (obj) {
            return this.isType(obj, 'object', Object);
        };

        //isURL
        //@param str
        /**
         * @return {boolean}
         */
        util.IsURL = function (str) {
            var strRegex = "^((https|http)?://)" + "(([0-9]{1,3}\.){3}[0-9]{1,3}"// IP URL- 199.194.52.184
                + "|"// allow IP and DOMAIN
                + "([0-9a-z_!~*'()-]+\.)*"// domain- www.
                + "([0-9a-z][0-9a-z-]{0,61})?[0-9a-z]\."// sub-domain
                + "[a-z]{2,6})"// first level domain- .com or .museum
                + "(:[0-9]{1,4})?"// port- :80
                + "((/?)|"// a slash isn't required if there is no file name
                + "(/[0-9a-z_!~*'().;?:@&amp;=+$,%#-]+)+/?)$";
            var re = new RegExp(strRegex);
            return re.test(str);
        };

        //delete cookies
        //@param name
        util.delCookie = function (name) {
            document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:01 GMT;';
        };

        //clear cookies
        //@param name
        util.clearCookie = function (name, domain, path) {
            var domain1 = domain || document.domain;
            var path1 = path || "/";
            document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:01 GMT;domain=' + domain1 + ';path=' + path1;
        };

        //get cookies
        //@param name
        util.getCookie = function (name) {
            var arr, reg = new RegExp('(^| )' + name + '=([^;]*)(;|$)');
            if (arr = document.cookie.match(reg))
                return unescape(arr[2]);
            else
                return null;
        };

        //set cookies
        //@param name
        //@param value
        util.setCookie = function (name, value) {
            var days = 30;
            var exp = new Date();
            //make it can be config. as argument?
            exp.setTime(exp.getTime() + days * 24 * 60 * 60 * 1000);
            document.cookie = name + '=' + escape(value) + ';expires=' + exp.toGMTString();
        };

        //parse queryString
        //@param query
        //@param name
        util.queryString = function (query, name) {
            var sValue = query.match(new RegExp("[\?\&]" + name + "=([^\&]*)(\&?)", "i"));
            return sValue ? sValue[1] : sValue;
        };

        return util;
    })();
    kevsso.util = util;

    /**
     * auth
     */
    kevsso.auth = (function () {
        /**
         * Creates a new auth.
         * @param baseApiAddress if not set, default value will be used.
         * @param passportKeyName
         * @constructor
         */
        function auth(baseApiAddress, passportKeyName) {
            if (util.isString(baseApiAddress)) {
                apiOptions.baseApiAddress = baseApiAddress;
            }
            if (util.isString(passportKeyName)) {
                apiOptions.passportKeyName = passportKeyName;
            }
            this.apiAddresses = {
                base: apiOptions.baseApiAddress,
                login: apiOptions.baseApiAddress + '/passport/login',
                logout: apiOptions.baseApiAddress + '/passport/logout',
                check: apiOptions.baseApiAddress + '/passport/check'
            };
        }

        /**
         * get api addresses
         */
        auth.prototype.getApiAddresses = function () {
            return this.apiAddresses;
        };

        /**
         * get Api Options
         */
        auth.prototype.getApiOptions = function () {
            return apiOptions;
        };

        /**
         * check login status
         * @return {boolean}
         */
        auth.prototype.isLogin = function () {
            var passport = util.getCookie(apiOptions.passportKeyName);
            return (passport != null && !(passport === ''));
        };

        /**
         * /login function
         * if arguments is null or empty, default api url will be used.
         * @param callback
         */
        auth.prototype.login = function (callback) {
            if (!( typeof callback === 'undefined') && !util.isFunction(callback)) {
                throw new Error('@param callback should be a function.');
            }

            var passport = util.getCookie(apiOptions.passportKeyName);
            if (passport != null) {
                //local passport already exist.
                //need to call passport api to check passport again?
                //for current requirement no need to check passport again, just delete cookie is ok.
                //console.log('local passport already exist.');
                return null;
            }

            return this.getScript(this.apiAddresses.login, function (data) {
                if (data.status === 1) {
                    if (data.passport === 'undefined') {
                        throw new Error('cant extract passport from data.');
                        //conlose.log('cant extract passport from data.');
                    } else {
                        //set passport
                        util.setCookie(apiOptions.passportKeyName, data.passport);
                        // util.setCookie('username', data[data.username]);
                        // util.setCookie('data', data[data.uid]);
                    }
                    return ( typeof callback === 'undefined') ? null : callback({
                        status: data.status,
                        data: data
                    });
                } else {
                    return {
                        status: data.status,
                        error: 'get passport failed. server: ' + data.error
                    };
                }
            });
        };

        /**
         * logout function
         * support Single Sign Out
         * @param domain
         * @param callback
         */
        auth.prototype.logout = function (domain, callback) {
            //always delete current domain passport cookie
            if (domain === 'undefined' || domain === '' || !util.isString(domain)) {
                util.delCookie(apiOptions.passportKeyName);
            } else {
                util.clearCookie(apiOptions.passportKeyName, domain);
            }
            this.getScript(this.apiAddresses.logout, function (data) {
                //sign out successful or already single sign out.
                if (data.status === 1 || data.status === 2) {
                    // Single-Sign-Out, sign out GEDU domain.
                    if (typeof callback === 'undefined') {
                        throw new Error('undefined callback function');
                    } else {
                        //needs to do more things? for now just callback is ok.
                        callback();
                    }
                }
                //remote server return error.
                else {
                    throw new Error('can not single sign out. error: ' + data.error);
                }
            });
        };

        /**
         * getScript function
         * @param url api url
         * @param callback
         */
        auth.prototype.getScript = function (url, callback) {
            //check url
            if (url === 'undefined' || !util.isString(url) || !util.IsURL(url)) {
                throw new Error('@param url, Invalid parameter.');
            }
            if (!( typeof callback === 'undefined') && !util.isFunction(callback)) {
                throw new Error('@param callback, Should be a function.');
            }
            $.getScript(url, function (response, status) {
                if (status === 'success') {
                    return callback(data);
                } else {
                    throw new Error('Get data failed.');
                }
            });
        };

        /**
         * check passport
         * @param passport
         * @return {boolean}
         */
        auth.prototype.check = function (passport) {
            if (typeof passport === "undefined" || !util.isString(passport)) {
                throw new Error('@param passport, Invalid parameter.');
            }
            return $.getJSON(this.apiAddresses.check + '?p=' + passport + '&callback=?', function (data) {
                return data.status === 0;
            });
        };

        return auth;
    })();

})(kevsso || ( kevsso = {}));
