import { CloudFrontRequest, CloudFrontRequestEvent, CloudFrontRequestResult } from 'aws-lambda';
import { SameSite } from './util/cookie';
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
    logLevel?: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
    cookiePath?: string;
}
interface Tokens {
    accessToken?: string;
    idToken?: string;
    refreshToken?: string;
}
export declare class Authenticator {
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
    _logger: any;
    _jwtVerifier: any;
    constructor(params: AuthenticatorParams);
    /**
     * Verify that constructor parameters are corrects.
     * @param  {object} params constructor params
     * @return {void} throw an exception if params are incorects.
     */
    _verifyParams(params: any): void;
    /**
     * Exchange authorization code for tokens.
     * @param  {String} redirectURI Redirection URI.
     * @param  {String} code        Authorization code.
     * @return {Promise} Authenticated user tokens.
     */
    _fetchTokensFromCode(redirectURI: any, code: any): Promise<Tokens>;
    /**
     * Fetch accessTokens from refreshToken.
     * @param  {String} redirectURI Redirection URI.
     * @param  {String} refreshToken Refresh token.
     * @return {Promise<Tokens>} Refreshed user tokens.
     */
    _fetchTokensFromRefreshToken(redirectURI: string, refreshToken: string): Promise<Tokens>;
    /**
     * Create a Lambda@Edge redirection response to set the tokens on the user's browser cookies.
     * @param  {Object} tokens   Cognito User Pool tokens.
     * @param  {String} domain   Website domain.
     * @param  {String} location Path to redirection.
     * @return Lambda@Edge response.
     */
    _getRedirectResponse(tokens: Tokens, domain: string, location: string): Promise<CloudFrontRequestResult>;
    /**
     * Extract value of the authentication token from the request cookies.
     * @param  {Array}  cookieHeaders 'Cookie' request headers.
     * @return {Tokens} Extracted id token or access token. Null if not found.
     */
    _getTokensFromCookie(cookieHeaders: Array<{
        key?: string | undefined;
        value: string;
    }> | undefined): Tokens;
    /**
     * Get redirect to cognito userpool response
     * @param  {CloudFrontRequest}  request The original request
     * @param  {string}  redirectURI Redirection URI.
     * @return {CloudFrontRequestResult} Redirect response.
     */
    _getRedirectToCognitoUserPoolResponse(request: CloudFrontRequest, redirectURI: string): CloudFrontRequestResult;
    /**
     * Handle Lambda@Edge event:
     *   * if authentication cookie is present and valid: forward the request
     *   * if authentication cookie is invalid, but refresh token is present: set cookies with refreshed tokens
     *   * if ?code=<grant code> is present: set cookies with new tokens
     *   * else redirect to the Cognito UserPool to authenticate the user
     * @param  {Object}  event Lambda@Edge event.
     * @return {Promise} CloudFront response.
     */
    handle(event: CloudFrontRequestEvent): Promise<CloudFrontRequestResult>;
}
export {};
