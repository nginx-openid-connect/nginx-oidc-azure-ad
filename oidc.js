/**
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 * 
 * Copyright (C) 2021 Nginx, Inc.
 */

// Constants for common error message. These will be cleaned up.
var ERR_CFG_VARS      = 'OIDC missing configuration variables';
var ERR_AC_TOKEN      = 'OIDC Access Token validation error';
var ERR_ID_TOKEN      = 'OIDC ID Token validation error';
var ERR_IDP_AUTH      = 'OIDC unexpected response from IdP in code exchange';
var ERR_TOKEN_RES     = 'OIDC AuthZ code sent but token response is not JSON';
var ERR_CLIENT_ID     = 'Check if cookie is removed, and client_id is there';
var ERR_IDP_APP_NAME  = 'IdP app is not set in $oidc_app_name';
var WRN_SESSION       = 'OIDC session is invalid';
var INF_SESSION       = 'OIDC session is valid';
var INF_REFRESH_TOKEN = 'OIDC refresh success, updating tokens for ';
var INF_REPLACE_TOKEN = 'OIDC replacing previous refresh token';

// Flag to check if there is still valid session cookie. It is used by auth()
// and validateIdToken().
var newSession = false; 

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *   1. Export Functions: called by `oidc_server.conf` or any location block.  *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
export default {
    auth,
    codeExchange,
    logout,
    redirectPostLogin,
    redirectPostLogout,
    tokenEncoder,
    validateIdToken,
    validateAccessToken,
    validateSession
};

// Start OIDC with either intializing new session or refershing token:
//
// 1. Validate client_id
//  - Check if client_id is provided in the cookie of /login endpoint if the
//    variable of `$client_id_validation_enable` is true.
//  - Otherwise, default IdP's application can be used.
//  - `$x_client_id` is for customer to identity one of applications so that this
//    mechanism supports multiple IdPs.
//
// 2. Start IdP authorization:
//  - Check all necessary configuration variables (referenced only by NJS).
//  - Redirect client to the IdP login page w/ the cookies we need for state.
//
// 3. Refresh ID / access token:
//  - Pass the refresh token to the /_refresh location so that it can be
//    proxied to the IdP in exchange for a new id_token and access_token.
//
function auth(r) {
    if (!isValidXClientId(r)) {
        return;
    }
    if (!r.variables.refresh_token || r.variables.refresh_token == '-' ||
        !isValidSession(r)) {
        r.log('start IdP authorization')
        startIdPAuthZ(r);
        return;
    }
    r.log('start refreshing token')
    refershToken(r);
}

// Request OIDC token, and handle IDP response (error or successful token).
// This function is called by the IdP after successful authentication:
//
// 1. Request OIDC token:
//  - http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
//  - Pass the AuthZ code to the /_token location so that it can be proxied to
//    the IdP in exchange for a JWT.
//
// 2. Handle IDP response:
//  1) Error Response:
//   - https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
//
//  2) Successful Token Response:
//   - https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
//
function codeExchange(r) {
    if (!isValidAuthZCode(r)) {
        return
    }
    setTokenParams(r)
    r.subrequest('/_token', getTokenArgs(r),
        function(res) {
            var isErr = handleTokenErrorResponse(r, res)
            if (isErr) {
                clearTokenParams(r)
                return
            }
            handleSuccessfulTokenResponse(r, res)
        }
    );
}

// Validate ID token which is received from IdP (fresh or refresh token):
//
// - https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// - This function is called by the location of `_id_token_validation` which is
//   called by either OIDC code exchange or refersh token request.
// - The clients MUST validate the ID Token in the Token Response from the IdP.
//
function validateIdToken(r) {
    var missingClaims = []
    if (r.variables.jwt_audience.length == 0) missingClaims.push('aud');
    if (!isValidRequiredClaims(r, ERR_ID_TOKEN, missingClaims)) {
        r.return(403);
        return;
    }
    if (!isValidIatClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    if (!isValidAudClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    if (!isValidNonceClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    r.return(204);
}

// Validate access token:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
// - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
//
// - This function is called by the location of `_access_token_validation` which
//   is called by either OIDC code exchange or refersh token request.
//
// - The 'aud' claim isn't contained in general ID token from Amazon Cognito,
//   although we can add it. Hence, the claim isn't part of this validation.
//
// - This function is for the case when you want to validate the token within
//   NGINX layer to following the spec. of OpenID Connect Core 1.0. 
//
// - But, this token is mostly validated by using one of following options.
//
//   + Option 1. validate a token (assumtion: JWT format) by using
//               a NGINX auth_jwt directive to validate it via IdP URI.
//     auth_jwt "" token=$access_token;
//     auth_jwt_key_request /_jwks_uri;
//
//   + Option 2. validate a token by using IdP token introspection endpoint.
//
function validateAccessToken(r) {
    var missingClaims = []
    if (!isValidRequiredClaims(r, ERR_AC_TOKEN, missingClaims)) {
        r.return(403);
        return false;
    }
    if (!isValidIatClaim(r, ERR_AC_TOKEN)) {
        r.return(403);
        return false;
    }
    r.return(204);
    return true;
}

// RP-Initiated or Custom Logout w/ IDP:
// 
// - An RP requests that the IDP log out the end-user by redirecting the
//   end-user's User Agent to the IDP's Logout endpoint.
// - TODO: Handle custom logout parameters if IDP doesn't support standard spec
//         of 'OpenID Connect RP-Initiated Logout 1.0'.
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
function logout(r) {
    r.log('OIDC logout for ' + r.variables.cookie_session_id);
    var logout_endpoint = generateCustomEndpoint(r,
        r.variables.oidc_logout_endpoint,
        r.variables.oidc_logout_path_params_enable,
        r.variables.oidc_logout_path_params
    );
    var queryParams = '';
    var idToken = r.variables.id_token;

    // OIDC RP-initiated logout.
    if (r.variables.oidc_logout_query_params_enable == 0) {
        queryParams = getRPInitiatedLogoutArgs(r, idToken);

    // Call the IDP logout endpoint with custom query parameters
    // if the IDP doesn't support RP-initiated logout.
    } else {
        queryParams = '?' + generateQueryParams(
            r.variables.oidc_logout_query_params);
    }
    r.variables.session_id    = '-';
    r.variables.id_token      = '-';
    r.variables.access_token  = '-';
    r.variables.refresh_token = '-';
    r.return(302, logout_endpoint + queryParams);
}

// Generate custom endpoint using path parameters if the option is enable.
// Otherwise, return the original endpoint.
//
// [Example 1]
// - Input : "https://{my-app}.okta.com/oauth2/{version}/logout"
//   + {my-app}  -> 'dev-9590480'
//   + {version} -> 'v1'
// - Result: "https://dev-9590480.okta.okta.com/oauth2/v1/logout"
//
// [Example 2]
// - Input : "https://{my-app}.okta.com/oauth2/{version}/authorize"
//   + {my-app}  -> 'dev-9590480'
//   + {version} -> 'v1'
// - Result: "https://dev-9590480.okta.okta.com/oauth2/v1/authorize"
//
function generateCustomEndpoint(r, uri, isEnableCustomPath, paths) {
    if (isEnableCustomPath == 0) {
        return uri;
    }
    var res   = '';
    var key   = '';
    var isKey = false;
    var items = JSON.parse(paths);
    for (var i = 0; i < uri.length; i++) {
        switch (uri[i]) {
            case '{': 
                isKey = true; 
                break;
            case '}': 
                res  += items[key]
                key   = '';
                isKey = false; 
                break;
            default : 
                if (!isKey) {
                    res += uri[i];
                } else {
                    key += uri[i];
                }
        }
    }
    r.log('generated an endpoint using path params: ' + res)
    return res;
}

// Redirect URI after logging in the IDP.
function redirectPostLogin(r) {
    r.return(302, r.variables.redirect_base + getIDTokenArgsAfterLogin(r));
}

// Redirect URI after logged-out from the IDP.
function redirectPostLogout(r) {
    r.return(302, r.variables.post_logout_return_uri);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *                   2. Common Functions for OIDC Workflows                    *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Start Identity Provider (IdP) authorization:
//
// - Check all necessary configuration variables (referenced only by NJS).
// - Redirect the client to the IdP login page w/ the cookies we need for state.
//
function startIdPAuthZ(r) {
    newSession = true;

    var configs = ['authz_endpoint', 'scopes', 'hmac_key', 'cookie_flags'];
    var missingConfig = [];
    var authz_endpoint = generateCustomEndpoint(r,
        r.variables.oidc_authz_endpoint,
        r.variables.oidc_authz_path_params_enable,
        r.variables.oidc_authz_path_params
    );

    for (var i in configs) {
        var oidcCfg = r.variables['oidc_' + configs[i]]
        if (!oidcCfg || oidcCfg == '') {
            missingConfig.push(configs[i]);
        }
    }
    if (missingConfig.length) {
        r.error(ERR_CFG_VARS + ': $oidc_' + missingConfig.join(' $oidc_'));
        r.return(500, r.variables.internal_error_message);
        return;
    }
    r.return(302, authz_endpoint + getAuthZArgs(r));
}

// Handle error response regarding the referesh token received from IDP:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
// - If the Refresh Request is invalid or unauthorized, the AuthZ Server returns
//   the Token Error Response as defined in OAuth 2.0 [RFC6749].
//
function handleRefershErrorResponse(r, res) {
    var msg = 'OIDC refresh failure';
    switch(res.status) {
        case 504:
            msg += ', timeout waiting for IdP';
            break;
        case 400:
            try {
                var errset = JSON.parse(res.responseBody);
                msg += ': ' + errset.error + ' ' + errset.error_description;
            } catch (e) {
                msg += ': ' + res.responseBody;
            }
            break;
        default:
            msg += ' '  + res.status;
    }
    r.error(msg);
    clearRefreshTokenAndReturnErr(r);
}

// Clear refersh token, and respond token error.
function clearRefreshTokenAndReturnErr(r) {
    r.variables.refresh_token = '-';
    r.return(302, r.variables.request_uri);
}

// Handle successful response regarding the referesh token:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
// - Upon successful validation of Refresh Token, the response body is the Token
//   Response of Section 3.1.3.3 except that it might not contain an id_token.
// - Successful Token Response except that it might not contain an id_token.
//
function handleSuccessfulRefreshResponse(r, res) {
    try {
        var tokenset = JSON.parse(res.responseBody);
        var isErr = isValidTokenSet(r, tokenset);
        if (isErr) {
            clearRefreshTokenAndReturnErr(r);
            return;
        }

        // Update opaque ID token and access token to key/value store.
        r.variables.session_id   = r.variables.cookie_session_id
        r.variables.id_token     = tokenset.id_token;
        r.variables.access_token = tokenset.access_token;

        // Update new refresh token to key/value store if we got a new one.
        r.log(INF_REFRESH_TOKEN + r.variables.cookie_session_id);
        if (r.variables.refresh_token != tokenset.refresh_token) {
            r.log(INF_REPLACE_TOKEN + ' (' + r.variables.refresh_token + 
                    ') with new value: ' + tokenset.refresh_token);
            r.variables.refresh_token = tokenset.refresh_token;
        }

        // Remove the evidence of original failed `auth_jwt`, and continue to
        // process the original request.
        delete r.headersOut['WWW-Authenticate'];
        r.internalRedirect(r.variables.request_uri);
    } catch (e) {
        clearRefreshTokenAndReturnErr(r);
    }
}

// Pass the refresh token to the /_refresh location so that it can be proxied to
// the IdP in exchange for a new id_token and access_token:
//
// 1. Request refresh token:
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
//  - To refresh an Access Token, the Client MUST authenticate to the Token
//    Endpoint using the authentication method registered for its client_id.
//
// 2. Handle IDP response(error or successful refresh token):
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
//
function refershToken(r) {
    setTokenParams(r)
    r.subrequest('/_refresh', 'token=' + r.variables.refresh_token, respHandler);
    function respHandler(res) {
        if (res.status != 200) {
            handleRefershErrorResponse(r, res);
            clearTokenParams(r)
            return;
        }
        handleSuccessfulRefreshResponse(r, res);
    }
}

// Set query/path parameters to the IDP token endpoint if customization option 
// for query or path param is enable.
function setTokenParams(r) {
    clearTokenParams(r)
    if (r.variables.oidc_token_query_params_enable == 1) {
        r.variables.token_query_params = '?' + generateQueryParams(
            r.variables.oidc_token_query_params
        );
    }
    r.variables.oidc_token_endpoint = generateCustomEndpoint(r,
        r.variables.oidc_token_endpoint,
        r.variables.oidc_token_path_params_enable,
        r.variables.oidc_token_path_params
    );
}

// Generate and return token encoder based on token header params.
function tokenEncoder(r) {
    if (r.variables.oidc_token_header_params_enable == 1) {
        return generateCustomHeaders(r, r.variables.oidc_token_header_params)
    }
    return "";
}

// Clear query parameters of the temporary stroage for the NGINX if OIDC's token
// endpoint returns error.
function clearTokenParams(r) {
    r.variables.token_query_params = '';
}

// Handle error response regarding the token received from IDP token endpoint:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
// - If the Token Request is invalid or unauthorized, the Authorization Server
//   constructs the error response.
// - The HTTP response body uses the application/json media type with HTTP 
//   response code of 400.
//
function handleTokenErrorResponse(r, res) {
    var isErr = true
    if (res.status == 504) {
        r.error('OIDC timeout connecting to IdP when sending AuthZ code');
        r.return(504);
        return isErr;
    }
    if (res.status != 200) {
        var statusMsg = '(' + res.status + '). ';
        try {
            var errset = JSON.parse(res.responseBody);
            if (errset.error) {
                r.error('OIDC error from IdP when sending AuthZ code: ' +
                    errset.error + ', ' + errset.error_description);
            } else {
                r.error(ERR_IDP_AUTH + statusMsg + res.responseBody);
            }
        } catch (e) {
            r.error(ERR_IDP_AUTH + statusMsg + res.responseBody);
        }
        r.return(502);
        return isErr;
    }
    return !isErr;
}

// Handle tokens after getting successful token response from the IdP:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
// - After receiving and validating a valid and authorized Token Request from
//   the Client, the Authorization Server returns a successful response that 
//   includes an ID Token and an Access Token.
//
function handleSuccessfulTokenResponse(r, res) {
    try {
        var tokenset = JSON.parse(res.responseBody);
        var isErr = isValidTokenSet(r, tokenset);
        if (isErr) {
             r.return(500);
             return;
        }

        // Generate session ID, and add opaque ID/access token to key/value store
        r.variables.session_id       = generateSession(r)
        r.variables.new_id_token     = tokenset.id_token;
        r.variables.new_access_token = tokenset.access_token;

        // Add new refresh token to key/value store
        if (tokenset.refresh_token) {
            r.variables.new_refresh = tokenset.refresh_token;
            r.log('OIDC refresh token stored');
        } else {
            r.warn('OIDC no refresh token');
        }
        // Set cookie with session ID that is the key of each ID/access token,
        // and continue to process the original request.
        r.log('OIDC success, creating session '    + r.variables.session_id);
        r.headersOut['Set-Cookie'] = 'session_id=' + r.variables.session_id + 
                                     '; ' + r.variables.oidc_cookie_flags;
        r.return(302, r.variables.redirect_base + r.variables.cookie_auth_redir);
    } catch (e) {
        r.error(ERR_TOKEN_RES + ' ' + res.responseBody);
        r.return(502);
    }
}

// Check if token is valid using `auth_jwt` directives and Node.JS functions:
//
// - ID     token validation: uri('/_id_token_validation'    )
// - Access token validation: uri('/_access_token_validation')
//
function isValidToken(r, uri, token) {
    if (!token) {
        return false
    }
    var isValid = true
    r.subrequest(uri, 'token=' + token, function(res) {
        if (res.status != 204) {
            isValid = false
        }
    });
    return isValid;
}

// Generate cookie and query parameters using the OIDC config in the nginx.conf:
//
// - Both are used when calling the API endpoint of IdP authorization for the
//   first time when starting Open ID Connect handshaking.
// - Choose a nonce for this flow for the client, and hash it for the IdP.
//
function getAuthZArgs(r) {
    var noncePlain = r.variables.session_id;
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash   = h.digest('base64url');
    var redirectURI = r.variables.redirect_base + r.variables.redir_location;
    var authZArgs   = '?response_type=code&scope=' + r.variables.oidc_scopes +
                      '&client_id='                + r.variables.oidc_client + 
                      '&redirect_uri='             + redirectURI + 
                      '&nonce='                    + nonceHash;
    var cookieFlags = r.variables.oidc_cookie_flags;
    r.headersOut['Set-Cookie'] = [
        'auth_redir=' + r.variables.request_uri + '; ' + cookieFlags,
        'auth_nonce=' + noncePlain + '; ' + cookieFlags
    ];
    r.headersOut['Origin'] = r.variables.host;
    r.variables.nonce_hash = nonceHash;

    if (r.variables.oidc_pkce_enable == 1) {
        var pkce_code_verifier  = c.createHmac('sha256', r.variables.oidc_hmac_key).
                                    update(randomStr()).digest('hex');
        r.variables.pkce_id     = c.createHash('sha256').
                                    update(randomStr()).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256').
                                    update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += '&code_challenge_method=S256&code_challenge=' + 
                     pkce_code_challenge + '&state=' + r.variables.pkce_id;
    } else {
        authZArgs += '&state=0';
    }

    if (r.variables.oidc_authz_query_params_enable == 1) {
        return authZArgs += '&' + generateQueryParams(
            r.variables.oidc_authz_query_params);
    }
    return authZArgs;
}

// Generate custom query parameters from JSON object
function generateQueryParams(obj) {
    var items = JSON.parse(obj);
    var args = ''
    for (var key in items) {
        args += key + '=' + items[key] + '&'
    }
    return args.slice(0, -1)
}

// Generate custom headers from JSON object
function generateCustomHeaders(r, obj) {
    var items = JSON.parse(obj);
    for (var key in items) {
        if (key == 'Accept-Encoding') {
            return items[key]
        }
    }
}

// Generate and return random string.
function randomStr() {
    return String(Math.random())
}

// Get query parameter of ID token after sucessful login:
//
// - For the variable of `returnTokenToClientOnLogin` of the APIM, this config
//   is only effective for /login endpoint. By default, our implementation MUST
//   not return any token back to the client app. 
// - If its configured it can send id_token in the request uri as 
//   `?id_token=sdfsdfdsfs` after successful login. 
//
function getIDTokenArgsAfterLogin(r) {
    if (r.variables.return_token_to_client_on_login == 'id_token') {
        return '?id_token=' + r.variables.id_token;
    }
    return '';
}

// Get query params for RP-initiated logout:
//
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
//
function getRPInitiatedLogoutArgs(r, idToken) {
    return '?post_logout_redirect_uri=' + r.variables.redirect_base
                                        + r.variables.oidc_logout_redirect +
           '&id_token_hint='            + idToken;
}

// Set PKCE ID and generate query parameters for OIDC token endpoint:
//
// - If PKCE is enabled, then we have to use the code_verifier.
// - Otherwise, we use client secret.
//
function getTokenArgs(r) {
    if (r.variables.oidc_pkce_enable == 1) {
        r.variables.pkce_id = r.variables.arg_state;
        return 'code='           + r.variables.arg_code + 
               '&code_verifier=' + r.variables.pkce_code_verifier;
    } else {
        return 'code='           + r.variables.arg_code + 
               '&client_secret=' + r.variables.oidc_client_secret;
    }
}

// Validate authorization code if it is correctly received from the IdP.
function isValidAuthZCode(r) {
    if (r.variables.arg_code == undefined || r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error('OIDC error receiving AuthZ code from IdP: ' +
                r.variables.arg_error_description);
        } else {
            r.error('OIDC expected AuthZ code from IdP but received: ' + r.uri);
        }
        r.return(502);
        return false;
    }
    return true;
}

// Validate 'iat' claim to see if it is valid:
//
// - Check if `iat` is a positive integer.
// - TODO if needed:
//   + It can be used to reject tokens that were issued too far away from
//     the current time, limiting the amount of time that nonces need to be
//     stored to prevent attacks. The acceptable range is Client specific.
//
function isValidIatClaim(r, msgPrefix) {
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error(msgPrefix + 'iat claim is not a valid number');
        return false;
    }
    return true;
}

// Validate 'aud (audience)' claim to see if it is valid:
//
// - The client MUST validate that `aud` claim contains its client_id value
//   registered at the Issuer identified by `iss` claim as an audience.
// - The ID Token MUST be rejected if the ID Token does not list the client
//   as a valid audience, or if it contains additional audiences not trusted
//   by the client.
//
function isValidAudClaim(r, msgPrefix) {
    var aud = r.variables.jwt_audience.split(',');
    if (!aud.includes(r.variables.oidc_client)) {
        r.error(msgPrefix + 'aud claim (' + r.variables.jwt_audience +
            ') does not include configured $oidc_client (' + 
            r.variables.oidc_client + ')');
            return false;
    }
    return true;
}

// Validate `nonce` claim to mitigate replay attacks:
//
// - nonce: a string value used to associate a client session & an ID token. 
//   The value is used to mitigate replay attacks and is present only if 
//   passed during the authorization request.
// - If we receive a nonce in the ID Token then we will use the auth_nonce 
//   cookies to check that JWT can be validated as being directly related to
//   the original request by this client. 
function isValidNonceClaim(r, msgPrefix) {
    if (newSession) {
        var clientNonceHash = '';
        if (r.variables.cookie_auth_nonce) {
            var c = require('crypto');
            var h = c.createHmac('sha256', r.variables.oidc_hmac_key).
                        update(r.variables.cookie_auth_nonce);
            clientNonceHash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != clientNonceHash) {
            r.error(msgPrefix + 'nonce from token (' + 
                r.variables.jwt_claim_nonce + ') does not match client (' + 
                clientNonceHash + ')');
            return false;
        }
    }
    return true;
}

// Validate if received token from the IdP contains mandatory claims:
//
// - For ID     token: 'iat', 'iss', 'sub', 'aud'
// - For Access token: 'iat', 'iss', 'sub'
// - Given the RFC7519, the above claims are OPTIONAL. But, we validate them
//   as required claims for several purposes such as mitigating replay attacks.
//
function isValidRequiredClaims(r, msgPrefix, missingClaims) {
    var required_claims = ['iat', 'iss', 'sub'];
    try {
        for (var i in required_claims) {
            if (r.variables['jwt_claim_' + required_claims[i]].length == 0 ) {
                missingClaims.push(required_claims[i]);
            }
        }
        if (missingClaims.length) {
            r.error(msgPrefix + ': missing claim(s) ' + missingClaims.join(' '));
            return false;
        }
    } catch (e) {
        r.error("required claims or missing claims do not exist.")
        return false
    }
    return true
}

// Check if (fresh or refresh) token set (ID token, access token) is valid.
function isValidTokenSet(r, tokenset) {
    var isErr = true;
    if (tokenset.error) {
        r.error('OIDC ' + tokenset.error + ' ' + tokenset.error_description);
        return isErr;
    }
    if (!tokenset.id_token) {
        r.error('OIDC response did not include id_token');
        return isErr;
    }
    if (!tokenset.access_token) {
        r.error('OIDC response did not include access_token');
        return isErr;
    }
    if (!isValidToken(r, '/_id_token_validation', tokenset.id_token)) {
        // The validateIdToken() logs error so that r.error() isn't used.
        return isErr;
    }
    // The access token is mostly validated by IdP using auth_jwt directive.
    // This can be used when you want to validate the token set in NGINX.
    if (r.variables.access_token_validation_enable == 1 &&
        !isValidToken(r, '/_access_token_validation', tokenset.access_token)) {
        // The validateAccessToken() logs error so that r.error() isn't used.
        return isErr;
    }
    return !isErr;
}

// Extract ID/access token from the request header.
function extractToken(r, key, is_bearer, validation_uri, msg) {
    var token = '';
    try {
        var headers = r.headersIn[key].split(' ');
        if (is_bearer) {
            if (headers[0] === 'Bearer') {
                token = headers[1]
            } else {
                msg += `, "` + key + `": "N/A"`;
                return [true, msg];
            }
        } else {
            token = headers[0]
        }
        if (!isValidToken(r, validation_uri, token)) {
            msg += `, "` + key + `": "invalid"}\n`;
            r.return(401, msg);
            return [false, msg];
        } else {
            msg += `, "` + key + `": "` + token + `"`;
        }
    } catch (e) {
        msg += `, "` + key + `": "N/A"`;
    }
    return [true, msg];
}

// Generate session ID using remote address, user agent, and client ID.
function generateSession(r) {
    var time = new Date(Date.now());
    var jsonSession = {
        'remoteAddr': r.variables.remote_addr,
        'userAgent' : r.variables.http_user_agent,
        'clientID'  : r.variables.oidc_client
    };
    if (r.variables.session_id_time_enable == 1) {
        jsonSession['timestamp'] = time.getHours() + ":" + time.getMinutes()
    }
    var data = JSON.stringify(jsonSession);
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(data);
    var session_id = h.digest('base64url');
    return session_id;
}

// Check if session cookie is valid, and generate new session id otherwise.
function isValidSession(r) {
    if (r.variables.session_validation_enable == 0) {
        return true;
    }
    r.log('Start checking if there is an existing valid session...')
    var valid_session_id = generateSession(r);
    if (r.variables.cookie_session_id != valid_session_id) {
        return false;
    }
    return true;
}

// Check if session is valid to mitigate a security issue that anyone who holds 
// the session cookie could play from any client (browsers or command line).
//
function validateSession(r) {
    if (!isValidSession(r)) {
        r.warn(WRN_SESSION)
        r.return(403, '{"message": "' + WRN_SESSION + '"}\n')
        return false;
    }
    r.return(200, '{"message": "' + INF_SESSION + '"}\n') 
    return true;
}

// Check if `X-Client-Id` is in query params of HTTP request, and if the name of
// IdP's app is matched with the `$x_client_id` so that we can validate it is
// valid when logging-in if `client_id_validation_enable` is enabled.
//
function isValidXClientId(r) {
    if (r.variables.client_id_validation_enable == 1) {
        if (!r.variables.cookie_client_id) {
            r.warn(ERR_CLIENT_ID)
            r.return(400, '{"message": "' + ERR_CLIENT_ID + '"}\n')
            return false
        }
        if (r.variables.oidc_app_name == '') {
            r.warn(ERR_IDP_APP_NAME)
            r.return(404, '{"message": "' + ERR_IDP_APP_NAME + '"}\n')
            return false
        }
    }
    return true
}
