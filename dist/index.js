"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Authenticator = void 0;
const aws_jwt_verify_1 = require("aws-jwt-verify");
const axios_1 = require("axios");
const pino_1 = require("pino");
const querystring_1 = require("querystring");
const cookie_1 = require("./util/cookie");
class Authenticator {
    _region;
    _userPoolId;
    _userPoolAppId;
    _userPoolAppSecret;
    _userPoolDomain;
    _cookieExpirationDays;
    _allowCookieSubdomains;
    _httpOnly;
    _sameSite;
    _cookieBase;
    _cookiePath;
    _apiVersion;
    _logger;
    _jwtVerifier;
    constructor(params) {
        this._verifyParams(params);
        this._region = params.region;
        this._userPoolId = params.userPoolId;
        this._userPoolAppId = params.userPoolAppId;
        this._userPoolAppSecret = params.userPoolAppSecret;
        this._userPoolDomain = params.userPoolDomain;
        this._cookieExpirationDays = params.cookieExpirationDays || 365;
        this._allowCookieSubdomains =
            "allowCookieSubdomains" in params &&
                params.allowCookieSubdomains === true;
        this._httpOnly = "httpOnly" in params && params.httpOnly === true;
        this._sameSite = params.sameSite;
        this._cookieBase = `CognitoIdentityServiceProvider.${params.userPoolAppId}`;
        this._cookiePath = params.cookiePath;
        this._apiVersion = params.apiVersion;
        this._logger = (0, pino_1.default)({
            level: params.logLevel || "silent",
            base: null, //Remove pid, hostname and name logging as not usefull for Lambda
        });
        this._jwtVerifier = aws_jwt_verify_1.CognitoJwtVerifier.create({
            userPoolId: params.userPoolId,
            clientId: params.userPoolAppId,
            tokenUse: "id",
        });
    }
    /**
     * Verify that constructor parameters are corrects.
     * @param  {object} params constructor params
     * @return {void} throw an exception if params are incorects.
     */
    _verifyParams(params) {
        if (typeof params !== "object") {
            throw new Error("Expected params to be an object");
        }
        ["region", "userPoolId", "userPoolAppId", "userPoolDomain"].forEach((param) => {
            if (typeof params[param] !== "string") {
                throw new Error(`Expected params.${param} to be a string`);
            }
        });
        if (params.cookieExpirationDays &&
            typeof params.cookieExpirationDays !== "number") {
            throw new Error("Expected params.cookieExpirationDays to be a number");
        }
        if ("allowCookieSubdomains" in params &&
            typeof params.allowCookieSubdomains !== "boolean") {
            throw new Error("Expected params.allowCookieSubdomains to be a boolean");
        }
        if ("httpOnly" in params && typeof params.httpOnly !== "boolean") {
            throw new Error("Expected params.httpOnly to be a boolean");
        }
        if ("sameSite" in params && !cookie_1.SAME_SITE_VALUES.includes(params.sameSite)) {
            throw new Error("Expected params.sameSite to be a Strict || Lax || None");
        }
        if ("cookiePath" in params && typeof params.cookiePath !== "string") {
            throw new Error("Expected params.cookiePath to be a string");
        }
        if ("apiVersion" in params && typeof params.apiVersion !== "string") {
            throw new Error("Expected params.apiVersion to be a string");
        }
    }
    /**
     * Exchange authorization code for tokens.
     * @param  {String} redirectURI Redirection URI.
     * @param  {String} code        Authorization code.
     * @return {Promise} Authenticated user tokens.
     */
    _fetchTokensFromCode(redirectURI, code) {
        const authorization = this._userPoolAppSecret &&
            Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString("base64");
        const request = {
            url: `https://${this._userPoolDomain}/oauth2/token`,
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data: (0, querystring_1.stringify)({
                client_secret: this._userPoolAppSecret,
                client_id: this._userPoolAppId,
                code: code,
                grant_type: "authorization_code",
                redirect_uri: redirectURI,
            }),
        };
        this._logger.debug({
            msg: "Fetching tokens from grant code...",
            request,
            code,
        });
        return axios_1.default
            .request(request)
            .then((resp) => {
            this._logger.debug({ msg: "Fetched tokens", tokens: resp.data });
            return {
                idToken: resp.data.id_token,
                accessToken: resp.data.access_token,
                refreshToken: resp.data.refresh_token,
            };
        })
            .catch((err) => {
            this._logger.error({
                msg: "Unable to fetch tokens from grant code",
                request,
                code,
            });
            throw err;
        });
    }
    /**
     * Fetch accessTokens from refreshToken.
     * @param  {String} redirectURI Redirection URI.
     * @param  {String} refreshToken Refresh token.
     * @return {Promise<Tokens>} Refreshed user tokens.
     */
    _fetchTokensFromRefreshToken(redirectURI, refreshToken) {
        const authorization = this._userPoolAppSecret &&
            Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString("base64");
        const request = {
            url: `https://${this._userPoolDomain}/oauth2/token`,
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                ...(authorization && { Authorization: `Basic ${authorization}` }),
            },
            data: (0, querystring_1.stringify)({
                client_id: this._userPoolAppId,
                refresh_token: refreshToken,
                grant_type: "refresh_token",
                redirect_uri: redirectURI,
            }),
        };
        this._logger.debug({
            msg: "Fetching tokens from refreshToken...",
            request,
            refreshToken,
        });
        return axios_1.default
            .request(request)
            .then((resp) => {
            this._logger.debug({ msg: "Fetched tokens", tokens: resp.data });
            return {
                idToken: resp.data.id_token,
                accessToken: resp.data.access_token,
            };
        })
            .catch((err) => {
            this._logger.error({
                msg: "Unable to fetch tokens from refreshToken",
                request,
                refreshToken,
            });
            throw err;
        });
    }
    /**
     * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
     * @param  {Object} tokens   Cognito User Pool tokens.
     * @param  {String} domain   Website domain.
     * @param  {String} location Path to redirection.
     * @return Lambda@Edge response.
     */
    async _getRedirectResponse(tokens, domain, location) {
        const decoded = await this._jwtVerifier.verify(tokens.idToken);
        const username = decoded["cognito:username"];
        const usernameBase = `${this._cookieBase}.${username}`;
        const parts = domain.split(".");
        const baseDomain = parts.length > 1
            ? `.${parts[parts.length - 2]}.${parts[parts.length - 1]}`
            : domain;
        const cookieAttributes = {
            domain: this._allowCookieSubdomains ? baseDomain : domain,
            expires: new Date(Date.now() + this._cookieExpirationDays * 864e5),
            secure: true,
            httpOnly: this._httpOnly,
            sameSite: this._sameSite,
            path: this._cookiePath,
        };
        const cookies = [
            cookie_1.Cookies.serialize(`${usernameBase}.accessToken`, tokens.accessToken, cookieAttributes),
            cookie_1.Cookies.serialize(`${usernameBase}.idToken`, tokens.idToken, cookieAttributes),
            ...(tokens.refreshToken
                ? [
                    cookie_1.Cookies.serialize(`${usernameBase}.refreshToken`, tokens.refreshToken, cookieAttributes),
                ]
                : []),
            cookie_1.Cookies.serialize(`${usernameBase}.tokenScopesString`, "phone email profile openid aws.cognito.signin.user.admin", cookieAttributes),
            cookie_1.Cookies.serialize(`${this._cookieBase}.LastAuthUser`, username, cookieAttributes),
        ];
        const response = {
            status: "302",
            headers: {
                "api-version": [
                    {
                        key: "api-version",
                        value: this._apiVersion,
                    },
                ],
                location: [
                    {
                        key: "Location",
                        value: location,
                    },
                ],
                "cache-control": [
                    {
                        key: "Cache-Control",
                        value: "no-cache, no-store, max-age=0, must-revalidate",
                    },
                ],
                pragma: [
                    {
                        key: "Pragma",
                        value: "no-cache",
                    },
                ],
                "set-cookie": cookies.map((c) => ({ key: "Set-Cookie", value: c })),
            },
        };
        this._logger.debug({ msg: "Generated set-cookie response", response });
        return response;
    }
    /**
     * Extract value of the authentication token from the request cookies.
     * @param  {Array}  cookieHeaders 'Cookie' request headers.
     * @return {Tokens} Extracted id token or access token. Null if not found.
     */
    _getTokensFromCookie(cookieHeaders, authHeader) {
        let tokens = {};
        if (authHeader && authHeader.startsWith("Bearer ")) {
            this._logger.debug("Extracting authentication token from Authorization header");
            tokens.idToken = authHeader.slice(7); // Remove 'Bearer ' prefix
        }
        else if (cookieHeaders) {
            this._logger.debug({
                msg: "Extracting authentication token from request cookie",
                cookieHeaders,
            });
            const cookies = cookieHeaders.flatMap((h) => cookie_1.Cookies.parse(h.value));
            const tokenCookieNamePrefix = `${this._cookieBase}.`;
            const idTokenCookieNamePostfix = ".idToken";
            const refreshTokenCookieNamePostfix = ".refreshToken";
            for (const { name, value } of cookies) {
                if (name.startsWith(tokenCookieNamePrefix) &&
                    name.endsWith(idTokenCookieNamePostfix)) {
                    tokens.idToken = value;
                }
                if (name.startsWith(tokenCookieNamePrefix) &&
                    name.endsWith(refreshTokenCookieNamePostfix)) {
                    tokens.refreshToken = value;
                }
            }
        }
        else {
            this._logger.debug("Neither Authorization header nor cookies were present in the request");
            throw new Error("Neither Authorization header nor cookies were present in the request");
        }
        if (!tokens.idToken) {
            this._logger.debug("idToken not present in request headers or cookies");
            throw new Error("idToken not present in request headers or cookies");
        }
        this._logger.debug({ msg: "Found tokens", tokens });
        return tokens;
    }
    /**
     * Get redirect to cognito userpool response
     * @param  {CloudFrontRequest}  request The original request
     * @param  {string}  redirectURI Redirection URI.
     * @return {CloudFrontRequestResult} Redirect response.
     */
    _getRedirectToCognitoUserPoolResponse(request, redirectURI) {
        let redirectPath = request.uri;
        if (request.querystring && request.querystring !== "") {
            redirectPath += encodeURIComponent("?" + request.querystring);
        }
        const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${redirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${redirectPath}`;
        this._logger.debug(`Redirecting user to Cognito User Pool URL ${userPoolUrl}`);
        return {
            status: "302",
            headers: {
                "api-version": [
                    {
                        key: "api-version",
                        value: this._apiVersion,
                    },
                ],
                location: [
                    {
                        key: "Location",
                        value: userPoolUrl,
                    },
                ],
                "cache-control": [
                    {
                        key: "Cache-Control",
                        value: "no-cache, no-store, max-age=0, must-revalidate",
                    },
                ],
                pragma: [
                    {
                        key: "Pragma",
                        value: "no-cache",
                    },
                ],
            },
        };
    }
    /**
     * Handle Lambda@Edge event:
     *   * if authentication cookie is present and valid: forward the request
     *   * if authentication cookie is invalid, but refresh token is present: set cookies with refreshed tokens
     *   * if ?code=<grant code> is present: set cookies with new tokens
     *   * else redirect to the Cognito UserPool to authenticate the user
     * @param  {Object}  event Lambda@Edge event.
     * @return {Promise} CloudFront response.
     */
    async handle(event) {
        this._logger.debug({ msg: "Handling Lambda@Edge event", event });
        const { request } = event.Records[0].cf;
        const requestParams = (0, querystring_1.parse)(request.querystring);
        const cfDomain = request.headers.host[0].value;
        const redirectURI = `https://${cfDomain}`;
        try {
            const authHeader = request.headers["authorization"]
                ? request.headers["authorization"][0].value
                : undefined;
            const tokens = this._getTokensFromCookie(request.headers.cookie, authHeader);
            this._logger.debug({ msg: "Verifying token...", tokens });
            try {
                const user = await this._jwtVerifier.verify(tokens.idToken);
                this._logger.info({
                    msg: "Forwarding request",
                    path: request.uri,
                    user,
                });
                return request;
            }
            catch (err) {
                if (authHeader) {
                    const response = {
                        status: "401",
                        statusDescription: `Unauthorized: ${err.message}`,
                        headers: {
                            "www-authenticate": [
                                { key: "WWW-Authenticate", value: "Bearer" },
                            ],
                            "api-version": [
                                {
                                    key: "api-version",
                                    value: this._apiVersion,
                                },
                            ],
                        },
                    };
                    return response;
                }
                if (tokens.refreshToken) {
                    this._logger.debug({
                        msg: "Verifying idToken failed, verifying refresh token instead...",
                        tokens,
                        err,
                    });
                    return await this._fetchTokensFromRefreshToken(redirectURI, tokens.refreshToken).then((tokens) => this._getRedirectResponse(tokens, cfDomain, request.uri));
                }
                else {
                    throw err;
                }
            }
        }
        catch (err) {
            this._logger.debug("User isn't authenticated: %s", err);
            if (requestParams.code) {
                return this._fetchTokensFromCode(redirectURI, requestParams.code).then((tokens) => this._getRedirectResponse(tokens, cfDomain, requestParams.state));
            }
            else {
                return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
            }
        }
    }
}
exports.Authenticator = Authenticator;
