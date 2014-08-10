"use strict";

var options = {
    debug: false,
    email: "",
    password: "",
    region: "us",
    npLanguage: "en"
}, regions = [ "us", "ca", "mx", "cl", "pe", "ar", "co", "br", "gb", "ie", "be", "lu", "nl", "fr", "de", "at", "ch", "it", "pt", "dk", "fi", "no", "se", "au", "nz", "es", "ru", "ae", "za", "pl", "gr", "sa", "cz", "bg", "hr", "ro", "si", "hu", "sk", "tr", "bh", "kw", "lb", "om", "qa", "il", "mt", "is", "cy", "in", "ua", "hk", "tw", "sg", "my", "id", "th", "jp", "kr" ], languages = [ "ja", "en", "en-GB", "fr", "es", "es-MX", "de", "it", "nl", "pt", "pt-BR", "ru", "pl", "fi", "da", "no", "sv", "tr", "ko", "zh-CN", "zh-TW" ], request = require("request").defaults({
    jar: true
}), debug = function(message) {
    if (options.debug) console.log("gPSN | " + message);
}, psnVars = {
    SENBaseURL: "https://auth.api.sonyentertainmentnetwork.com",
    redirectURL_oauth: "com.scee.psxandroid.scecompcall://redirect",
    client_id: "b0d0d7ad-bb99-4ab1-b25e-afa0c76577b0",
    scope: "sceapp",
    scope_psn: "psn:sceapp",
    csrfToken: "",
    authCode: "",
    client_secret: "Zo4y8eGIa3oazIEp",
    duid: "00000005006401283335353338373035333434333134313a433635303220202020202020202020202020202020",
    cltm: "1399637146935",
    service_entity: "urn:service-entity:psn"
}, psnURL = {
    SignIN: psnVars.SENBaseURL + "/2.0/oauth/authorize?response_type=code&service_entity=" + psnVars.service_entity + "&returnAuthCode=true&cltm=" + psnVars.cltm + "&redirect_uri=" + psnVars.redirectURL_oauth + "&client_id=" + psnVars.client_id + "&scope=" + psnVars.scope_psn,
    SignINPOST: psnVars.SENBaseURL + "/login.do",
    oauth: "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/token",
    profileData: "https://{{region}}-prof.np.community.playstation.net/userProfile/v1/users/{{id}}/profile?fields=%40default,relation,requestMessageFlag,presence,%40personalDetail,trophySummary",
    trophyData: "https://{{region}}-tpy.np.community.playstation.net/trophy/v1/trophyTitles?fields=%40default&npLanguage={{lang}}&iconSize={{iconsize}}&platform=PS3%2CPSVITA%2CPS4&offset={{offset}}&limit={{limit}}&comparedUser={{id}}",
    trophyDataList: "https://{{region}}-tpy.np.community.playstation.net/trophy/v1/trophyTitles/{{npCommunicationId}}/trophyGroups/{{groupId}}/trophies?fields=%40default,trophyRare,trophyEarnedRate&npLanguage={{lang}}",
    trophyGroupList: "https://{{region}}-tpy.np.community.playstation.net/trophy/v1/trophyTitles/{{npCommunicationId}}/trophyGroups/?npLanguage={{lang}}",
    trophyInfo: "https://{{region}}-tpy.np.community.playstation.net/trophy/v1/trophyTitles/{{npCommunicationId}}/trophyGroups/{{groupId}}/trophies/{{trophyID}}?fields=%40default,trophyRare,trophyEarnedRate&npLanguage={{lang}}"
}, accessToken = "", refreshToken = "", refreshInterval;

function initLogin(callback) {
    debug("Getting login");
    request.get({
        url: psnURL.SignIN,
        headers: {
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 4.3; " + options.npLanguage + "; C6502 Build/10.4.1.B.0.101) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30 PlayStation App/1.60.5/" + options.npLanguage + "/" + options.npLanguage
        }
    }, function(error, response, body) {
        typeof callback === "function" ? getLogin(callback, psnVars.SENBaseURL + response.req.path) : getLogin(undefined, psnVars.SENBaseURL + response.req.path);
    });
}

function getLogin(callback, url) {
    request.post(psnURL.SignINPOST, {
        headers: {
            Origin: "https://auth.api.sonyentertainmentnetwork.com",
            Referer: url
        },
        form: {
            params: "service_entity=psn",
            j_username: options.email,
            j_password: options.password
        }
    }, function(error, response, body) {
        request.get(response.headers.location, function(error, response, body) {
            if (!error) {
                var urlString = unescape(response.req.path);
                psnVars.authCode = urlString.substr(urlString.indexOf("authCode=") + 9, 6);
                debug("authCode obtained: " + psnVars.authCode);
                getAccessToken(psnVars.authCode, callback);
            } else {
                debug("ERROR: " + error);
            }
        });
    });
}

function getAccessToken(authCode, callback) {
    var responseJSON;
    if (refreshToken.length > 0) {
        request.post(psnURL.oauth, {
            form: {
                grant_type: "refresh_token",
                client_id: psnVars.client_id,
                client_secret: psnVars.client_secret,
                refresh_token: refreshToken,
                redirect_uri: psnVars.redirectURL_oauth,
                state: "x",
                scope: psnVars.scope_psn,
                duid: psnVars.duid
            }
        }, function(error, response, body) {
            responseJSON = JSON.parse(body);
            if (!error) {
                if ("access_token" in responseJSON && !("error" in responseJSON)) {
                    accessToken = responseJSON.access_token;
                    refreshToken = responseJSON.refresh_token;
                    debug("access_token obtained by using refresh_token: " + accessToken);
                    if (typeof callback === "function") callback();
                } else {
                    debug("ERROR: " + responseJSON);
                }
            } else {
                debug("ERROR: " + error);
            }
        });
    } else {
        debug("Login for the first time");
        request.post(psnURL.oauth, {
            form: {
                grant_type: "authorization_code",
                client_id: psnVars.client_id,
                client_secret: psnVars.client_secret,
                code: authCode,
                redirect_uri: psnVars.redirectURL_oauth,
                state: "x",
                scope: psnVars.scope_psn,
                duid: psnVars.duid
            }
        }, function(error, response, body) {
            responseJSON = JSON.parse(body);
            if (!error) {
                if ("access_token" in responseJSON && !("error" in responseJSON)) {
                    accessToken = responseJSON.access_token;
                    refreshToken = responseJSON.refresh_token;
                    clearInterval(refreshInterval);
                    refreshInterval = setInterval(function() {
                        getAccessToken("", function() {
                            debug("access_token refreshed after 59 minutes");
                        });
                    }, (responseJSON.expires_in - 60) * 1e3);
                    debug("access_token/refresh_token obtained: " + body);
                    if (typeof callback === "function") callback();
                } else {
                    debug("ERROR: " + JSON.stringify(responseJSON));
                }
            } else {
                debug("ERROR: " + JSON.stringify(error));
            }
        });
    }
}

function psnGETRequest(url, callback) {
    var reqOptions = {
        url: url,
        method: "GET",
        headers: {
            "Access-Control-Request-Method": "GET",
            Origin: "http://psapp.dl.playstation.net",
            "Access-Control-Request-Headers": "Origin, Accept-Language, Authorization, Content-Type, Cache-Control",
            "Accept-Language": options.npLanguage + "," + languages.join(","),
            Authorization: "Bearer " + accessToken,
            "Cache-Control": "no-cache",
            "X-Requested-With": "com.scee.psxandroid",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 4.3; " + options.npLanguage + "; C6502 Build/10.4.1.B.0.101) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30 PlayStation App/1.60.5/" + options.npLanguage + "/" + options.npLanguage
        }
    };
    request.get(reqOptions, function(error, response, body) {
        var responseJSON;
        responseJSON = JSON.parse(body);
        if (!error) {
            if (response.statusCode == 200) {
                callback(false, responseJSON);
            } else if (response.statusCode == 401) {
                if ("error" in responseJSON) {
                    if (responseJSON.error.code === 2105858 || responseJSON.error.code === 2138626) {
                        debug("Token has expired, asking for new one");
                        initLogin(function() {
                            psnGETRequest(url, callback);
                        });
                    } else {
                        callback(true, responseJSON);
                    }
                }
            } else {
                callback(true, responseJSON);
            }
        } else {
            callback(true, error);
        }
    });
}

function psnPOSTRequest(url, callback) {
    var reqOptions = {
        url: url,
        method: "POST",
        headers: {
            "Access-Control-Request-Method": "POST",
            Origin: "http://psapp.dl.playstation.net",
            "Access-Control-Request-Headers": "Origin, Accept-Language, Authorization, Content-Type, Cache-Control",
            "Accept-Language": options.npLanguage + "," + languages.join(","),
            Authorization: "Bearer " + accessToken,
            "Cache-Control": "no-cache",
            "X-Requested-With": "com.scee.psxandroid",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 4.3; " + options.npLanguage + "; C6502 Build/10.4.1.B.0.101) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30 PlayStation App/1.60.5/" + options.npLanguage + "/" + options.npLanguage
        }
    };
    request.post(reqOptions, function(error, response, body) {
        var responseJSON;
        responseJSON = JSON.parse(body);
        if (!error) {
            if (response.statusCode == 200) {
                callback(false, responseJSON);
            } else if (response.statusCode == 401) {
                if ("error" in responseJSON) {
                    if (responseJSON.error.code === 2105858 || responseJSON.error.code === 2138626) {
                        debug("Token has expired, asking for new one");
                        initLogin(function() {
                            psnGETRequest(url, callback);
                        });
                    } else {
                        callback(true, responseJSON);
                    }
                }
            } else {
                callback(true, responseJSON);
            }
        } else {
            callback(true, error);
        }
    });
}

exports.init = function(params, callback) {
    if (typeof params === "object" && ("email" in params && "password" in params)) {
        if (params.debug) options.debug = true;
        options.email = params.email;
        options.password = params.password;
        if (languages.indexOf(params.npLanguage) >= 0) options.npLanguage = params.npLanguage; else debug('Invalid "' + params.npLanguage + '" npLanguage value, using "en" instead');
        if (regions.indexOf(params.region) >= 0) options.region = params.region; else debug('Invalid "' + params.region + '" region value, using "us" instead');
        Object.keys(psnURL).forEach(function(key) {
            if (psnURL.hasOwnProperty(key)) {
                psnURL[key] = psnURL[key].replace("{{lang}}", options.npLanguage).replace("{{region}}", options.region);
            }
        });
        initLogin(callback);
    } else {
        throw new Error("Cannot start without user or password");
    }
};

exports.getProfile = function(psnid, callback) {
    if (accessToken.length > 1) {
        debug("Asking profile data for: " + psnid);
        psnGETRequest(psnURL.profileData.replace("{{id}}", psnid), callback);
    } else {
        debug("Asking for new token");
        getAccessToken("", function() {
            psnGETRequest(psnURL.profileData.replace("{{id}}", psnid), callback);
        });
    }
};

exports.getTrophies = function(psnid, iconsize, offset, limit, callback) {
    if (accessToken.length > 1) {
        debug("Asking trophies info for: " + psnid);
        psnGETRequest(psnURL.trophyData.replace("{{iconsize}}", iconsize).replace("{{id}}", psnid).replace("{{offset}}", offset).replace("{{limit}}", limit), callback);
    } else {
        debug("Asking for new token");
        initLogin(function() {
            psnGETRequest(psnURL.trophyData.replace("{{iconsize}}", iconsize).replace("{{id}}", psnid).replace("{{offset}}", offset).replace("{{limit}}", limit), callback);
        });
    }
};

exports.getGameTrophyGroups = function(psnid, npCommID, callback) {
    if (accessToken.length > 1) {
        debug("Asking trophy group for: " + psnid);
        psnGETRequest(psnURL.trophyGroupList.replace("{{npCommunicationId}}", npCommID) + (psnid.length > 1 ? "&comparedUser=" + psnid : ""), callback);
    } else {
        debug("Asking for new token");
        initLogin(function() {
            psnGETRequest(psnURL.trophyGroupList.replace("{{npCommunicationId}}", npCommID) + (psnid.length > 1 ? "&comparedUser=" + psnid : ""), callback);
        });
    }
};

exports.getGameTrophies = function(psnid, npCommID, groupId, callback) {
    if (accessToken.length > 1) {
        debug("Asking trophy list of: " + npCommID);
        psnGETRequest(psnURL.trophyDataList.replace("{{npCommunicationId}}", npCommID).replace("{{groupId}}", groupId.length > 1 ? groupId : "all") + (psnid.length > 1 ? "&comparedUser=" + psnid : ""), callback);
    } else {
        debug("Asking for new token");
        initLogin(function() {
            psnGETRequest(psnURL.trophyDataList.replace("{{npCommunicationId}}", npCommID).replace("{{groupId}}", groupId.length > 1 ? groupId : "all") + (psnid.length > 1 ? "&comparedUser=" + psnid : ""), callback);
        });
    }
};

exports.getTrophy = function(psnid, npCommID, groupId, trophyID, callback) {
    if (accessToken.length > 1) {
        debug("Asking trophy info for: " + trophyID + " for npCommID " + npCommID);
        psnGETRequest(psnURL.trophyInfo.replace("{{npCommunicationId}}", npCommID).replace("{{trophyID}}", trophyID).replace("{{groupId}}", groupId.length > 1 ? groupId : "all") + (psnid.length > 1 ? "&comparedUser=" + psnid : ""), callback);
    } else {
        debug("Asking for new token");
        initLogin(function() {
            psnGETRequest(psnURL.trophyInfo.replace("{{npCommunicationId}}", npCommID).replace("{{trophyID}}", trophyID).replace("{{groupId}}", groupId.length > 1 ? groupId : "all") + (psnid.length > 1 ? "&comparedUser=" + psnid : ""), callback);
        });
    }
};

function psnGETRequestDEBUG(url, callback) {
    var options = {
        url: url,
        method: "GET",
        headers: {
            Authorization: "Bearer " + accessToken
        }
    };
    console.log("GET " + url);
    request.get(options, function(error, response, body) {
        callback(body);
    });
}

exports.GET = function(url, callback) {
    psnGETRequestDEBUG(url, callback);
};