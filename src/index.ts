import { CognitoJwtVerifier } from "aws-jwt-verify";
import {
  CloudFrontRequest,
  CloudFrontRequestEvent,
  CloudFrontRequestResult,
} from "aws-lambda";
import axios from "axios";
import pino from "pino";
import { parse, stringify } from "querystring";
import {
  CookieAttributes,
  Cookies,
  SameSite,
  SAME_SITE_VALUES,
} from "./util/cookie";

interface AuthenticatorParams {
  region: string;
  userPoolId: string;
  userPoolAppId: string;
  userPoolAppSecret?: string;
  userPoolDomain: string;
  cookieExpirationDays?: number;
  allowCookieSubdomains?: boolean;
  httpOnly?: boolean;
  sameSite?: SameSite;
  logLevel?: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
  cookiePath?: string;
}

interface Tokens {
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
}

export class Authenticator {
  _region: string;
  _userPoolId: string;
  _userPoolAppId: string;
  _userPoolAppSecret: string;
  _userPoolDomain: string;
  _cookieExpirationDays: number;
  _allowCookieSubdomains: boolean;
  _httpOnly: boolean;
  _sameSite?: SameSite;
  _cookieBase: string;
  _cookiePath?: string;
  _logger;
  _jwtVerifier;

  constructor(params: AuthenticatorParams) {
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
    this._logger = pino({
      level: params.logLevel || "silent", // Default to silent
      base: null, //Remove pid, hostname and name logging as not usefull for Lambda
    });
    this._jwtVerifier = CognitoJwtVerifier.create({
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
    ["region", "userPoolId", "userPoolAppId", "userPoolDomain"].forEach(
      (param) => {
        if (typeof params[param] !== "string") {
          throw new Error(`Expected params.${param} to be a string`);
        }
      }
    );
    if (
      params.cookieExpirationDays &&
      typeof params.cookieExpirationDays !== "number"
    ) {
      throw new Error("Expected params.cookieExpirationDays to be a number");
    }
    if (
      "allowCookieSubdomains" in params &&
      typeof params.allowCookieSubdomains !== "boolean"
    ) {
      throw new Error("Expected params.allowCookieSubdomains to be a boolean");
    }
    if ("httpOnly" in params && typeof params.httpOnly !== "boolean") {
      throw new Error("Expected params.httpOnly to be a boolean");
    }
    if ("sameSite" in params && !SAME_SITE_VALUES.includes(params.sameSite)) {
      throw new Error("Expected params.sameSite to be a Strict || Lax || None");
    }
    if ("cookiePath" in params && typeof params.cookiePath !== "string") {
      throw new Error("Expected params.cookiePath to be a string");
    }
  }

  /**
   * Exchange authorization code for tokens.
   * @param  {String} redirectURI Redirection URI.
   * @param  {String} code        Authorization code.
   * @return {Promise} Authenticated user tokens.
   */
  _fetchTokensFromCode(redirectURI, code): Promise<Tokens> {
    const authorization =
      this._userPoolAppSecret &&
      Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString(
        "base64"
      );
    const request = {
      url: `https://${this._userPoolDomain}/oauth2/token`,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(authorization && { Authorization: `Basic ${authorization}` }),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        code: code,
        grant_type: "authorization_code",
        redirect_uri: redirectURI,
      }),
    } as const;
    this._logger.debug({
      msg: "Fetching tokens from grant code...",
      request,
      code,
    });
    return axios
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
  _fetchTokensFromRefreshToken(
    redirectURI: string,
    refreshToken: string
  ): Promise<Tokens> {
    const authorization =
      this._userPoolAppSecret &&
      Buffer.from(`${this._userPoolAppId}:${this._userPoolAppSecret}`).toString(
        "base64"
      );
    const request = {
      url: `https://${this._userPoolDomain}/oauth2/token`,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(authorization && { Authorization: `Basic ${authorization}` }),
      },
      data: stringify({
        client_id: this._userPoolAppId,
        refresh_token: refreshToken,
        grant_type: "refresh_token",
        redirect_uri: redirectURI,
      }),
    } as const;
    this._logger.debug({
      msg: "Fetching tokens from refreshToken...",
      request,
      refreshToken,
    });
    return axios
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
  async _getRedirectResponse(
    tokens: Tokens,
    domain: string,
    location: string
  ): Promise<CloudFrontRequestResult> {
    const decoded = await this._jwtVerifier.verify(tokens.idToken);
    const username = decoded["cognito:username"] as string;
    const usernameBase = `${this._cookieBase}.${username}`;
    const parts = domain.split(".");
    const baseDomain =
      parts.length > 1
        ? `.${parts[parts.length - 2]}.${parts[parts.length - 1]}`
        : domain;
    const cookieAttributes: CookieAttributes = {
      domain: this._allowCookieSubdomains ? baseDomain : domain,
      expires: new Date(Date.now() + this._cookieExpirationDays * 864e5),
      secure: true,
      httpOnly: this._httpOnly,
      sameSite: this._sameSite,
      path: this._cookiePath,
    };
    const cookies = [
      Cookies.serialize(
        `${usernameBase}.accessToken`,
        tokens.accessToken,
        cookieAttributes
      ),
      Cookies.serialize(
        `${usernameBase}.idToken`,
        tokens.idToken,
        cookieAttributes
      ),
      ...(tokens.refreshToken
        ? [
            Cookies.serialize(
              `${usernameBase}.refreshToken`,
              tokens.refreshToken,
              cookieAttributes
            ),
          ]
        : []),
      Cookies.serialize(
        `${usernameBase}.tokenScopesString`,
        "phone email profile openid aws.cognito.signin.user.admin",
        cookieAttributes
      ),
      Cookies.serialize(
        `${this._cookieBase}.LastAuthUser`,
        username,
        cookieAttributes
      ),
    ];

    const response: CloudFrontRequestResult = {
      status: "302",
      headers: {
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
  _getTokensFromCookie(
    cookieHeaders: Array<{ key?: string | undefined; value: string }>,
    authHeader: string | undefined
  ): Tokens {
    let tokens: Tokens = {};

    if (authHeader && authHeader.startsWith("Bearer ")) {
      this._logger.debug(
        "Extracting authentication token from Authorization header"
      );
      tokens.idToken = authHeader.slice(7); // Remove 'Bearer ' prefix
    } else if (cookieHeaders) {
      this._logger.debug({
        msg: "Extracting authentication token from request cookie",
        cookieHeaders,
      });

      const cookies = cookieHeaders.flatMap((h) => Cookies.parse(h.value));

      const tokenCookieNamePrefix = `${this._cookieBase}.`;
      const idTokenCookieNamePostfix = ".idToken";
      const refreshTokenCookieNamePostfix = ".refreshToken";

      for (const { name, value } of cookies) {
        if (
          name.startsWith(tokenCookieNamePrefix) &&
          name.endsWith(idTokenCookieNamePostfix)
        ) {
          tokens.idToken = value;
        }
        if (
          name.startsWith(tokenCookieNamePrefix) &&
          name.endsWith(refreshTokenCookieNamePostfix)
        ) {
          tokens.refreshToken = value;
        }
      }
    } else {
      this._logger.debug(
        "Neither Authorization header nor cookies were present in the request"
      );
      throw new Error(
        "Neither Authorization header nor cookies were present in the request"
      );
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
  _getRedirectToCognitoUserPoolResponse(
    request: CloudFrontRequest,
    redirectURI: string
  ): CloudFrontRequestResult {
    let redirectPath = request.uri;
    if (request.querystring && request.querystring !== "") {
      redirectPath += encodeURIComponent("?" + request.querystring);
    }
    const userPoolUrl = `https://${this._userPoolDomain}/authorize?redirect_uri=${redirectURI}&response_type=code&client_id=${this._userPoolAppId}&state=${redirectPath}`;
    this._logger.debug(
      `Redirecting user to Cognito User Pool URL ${userPoolUrl}`
    );
    return {
      status: "302",
      headers: {
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
  async handle(
    event: CloudFrontRequestEvent
  ): Promise<CloudFrontRequestResult> {
    this._logger.debug({ msg: "Handling Lambda@Edge event", event });

    const { request } = event.Records[0].cf;
    const requestParams = parse(request.querystring);
    const cfDomain = request.headers.host[0].value;
    const redirectURI = `https://${cfDomain}`;

    try {
      const authHeader = request.headers['authorization'] ? request.headers['authorization'][0].value : undefined;
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
      } catch (err) {
        if (tokens.refreshToken) {
          this._logger.debug({
            msg: "Verifying idToken failed, verifying refresh token instead...",
            tokens,
            err,
          });
          return await this._fetchTokensFromRefreshToken(
            redirectURI,
            tokens.refreshToken
          ).then((tokens) =>
            this._getRedirectResponse(tokens, cfDomain, request.uri)
          );
        } else {
          throw err;
        }
      }
    } catch (err) {
      this._logger.debug("User isn't authenticated: %s", err);
      if (requestParams.code) {
        return this._fetchTokensFromCode(redirectURI, requestParams.code).then(
          (tokens) =>
            this._getRedirectResponse(
              tokens,
              cfDomain,
              requestParams.state as string
            )
        );
      } else {
        return this._getRedirectToCognitoUserPoolResponse(request, redirectURI);
      }
    }
  }
}
