/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.apache.jackrabbit.oak.spi.security.authentication.credentials.CredentialsSupport;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityProvider;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.LoginCookieManager;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component(
        service = AuthenticationHandler.class,
        immediate = true
)

@Designate(ocd = OidcAuthenticationHandler.Config.class, factory = true)
public class OidcAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

    public static final String REDIRECT_ATTRIBUTE_NAME = "sling.redirect";

    private static final Logger logger = LoggerFactory.getLogger(OidcAuthenticationHandler.class);
    private static final String AUTH_TYPE = "oidc";

    private final SlingRepository repository;

    private final Map<String, ClientConnection> connections;
    private final OAuthStateManager stateManager;

    private final String idp;

    private  final String callbackUri;

    private final LoginCookieManager loginCookieManager;

    private final String defaultConnectionName;

    private final UserInfoProcessor userInfoProcessor;

    private final boolean userInfoEnabled;

    private final boolean pkceEnabled;

    private final String[] path;

    private final boolean checkNonce;

    @ObjectClassDefinition(
            name = "Apache Sling Oidc Authentication Handler",
            description = "Apache Sling Oidc Authentication Handler Service"
    )

    @interface Config {
        @AttributeDefinition(name = "Path",
                description = "Repository path for which this authentication handler should be used by Sling. If this is " +
                        "empty, the authentication handler will be disabled. By default this is set to \"/\".")
        String[] path() default {"/"};

        @AttributeDefinition(name = "Sync Handler Configuration Name",
                description = "Name of Sync Handler Configuration")
        String idp() default "oidc";

        @AttributeDefinition(name = "Callback URI",
                description = "Callback URI")
        String callbackUri() default "callbackUri";

        @AttributeDefinition(name = "Default Connection Name",
                description = "Default Connection Name")
        String defaultConnectionName() default "";

        @AttributeDefinition(name = "PKCE Enabled",
                description = "PKCE Enabled")
        boolean pkceEnabled() default false;

        @AttributeDefinition(name = "UserInfo Enabled",
                description = "UserInfo Enabled")
        boolean userInfoEnabled() default true;

        @AttributeDefinition(name = "Check Nonce",
                description = "Check Nonce")
        boolean checkNonce() default true;
    }

    @Activate
    public OidcAuthenticationHandler(@Reference(policyOption = ReferencePolicyOption.GREEDY) @NotNull SlingRepository repository,
                                     @NotNull BundleContext bundleContext, @Reference List<ClientConnection> connections,
                                     @Reference OAuthStateManager stateManager,
                                     Config config,
                                     @Reference(cardinality = ReferenceCardinality.OPTIONAL, policyOption = ReferencePolicyOption.GREEDY) LoginCookieManager loginCookieManager,
                                     @Reference(policyOption = ReferencePolicyOption.GREEDY) UserInfoProcessor userInfoProcessor
    ) {

        this.repository = repository;
        this.connections = connections.stream()
                .collect(Collectors.toMap( ClientConnection::name, Function.identity()));
        this.stateManager = stateManager;
        this.idp = config.idp();
        this.callbackUri = config.callbackUri();
        this.loginCookieManager = loginCookieManager;
        this.defaultConnectionName = config.defaultConnectionName();
        this.userInfoProcessor = userInfoProcessor;
        this.userInfoEnabled = config.userInfoEnabled();
        this.checkNonce = config.checkNonce();
        this.pkceEnabled = config.pkceEnabled();
        this.path = config.path();

        logger.debug("activate: registering ExternalIdentityProvider");
        bundleContext.registerService(
                new String[]{ExternalIdentityProvider.class.getName(), CredentialsSupport.class.getName()}, new OidcIdentityProvider(idp),
                null);

        logger.info("OidcAuthenticationHandler successfully activated");

    }



    @Override
    public AuthenticationInfo extractCredentials(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        logger.debug("inside extractCredentials");

        // Check if the request is authenticated by an oidc login token
        AuthenticationInfo authInfo = loginCookieManager.verifyLoginCookie(request);
        if (authInfo != null) {
            // User has a login token
            return authInfo;
        }

        //The request is not authenticated.
        // 1. Extract nonce cookie and state cookie from the request
        StringBuffer requestURL = request.getRequestURL();
        if ( request.getQueryString() != null )
            requestURL.append('?').append(request.getQueryString());

        Optional<OAuthState> clientState; //state returned by the idp in the redirect request
        String authCode; //authorization code returned by the idp in the redirect request
        Cookie stateCookie;
        Cookie nonceCookie;
        Cookie codeVerifierCookie = null;
        AuthorizationResponse authResponse;
        try {
            authResponse = AuthorizationResponse.parse(new URI(requestURL.toString()));
            clientState = extractClientState(authResponse);
        } catch (ParseException | URISyntaxException | IllegalStateException e) {
            // If we fail parsing the response, we consider the request not for this authentication handler
            //The request may have some parameters that are not relevant for this authentication handler
            return null;
        }
        authCode = extractAuthCode(authResponse);
        stateCookie = extractCookie(request, OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        if (pkceEnabled) {
            codeVerifierCookie = extractCookie(request, OAuthStateManager.COOKIE_NAME_CODE_VERIFIER);
        }

        //2. Check if the State cookie match with the state in the request received from the idp
        String stateFromAuthServer = clientState.get().perRequestKey();
        String stateFromClient = stateCookie.getValue();
        if (!stateFromAuthServer.equals(stateFromClient)) {
            throw new IllegalStateException("Failed state check: request keys from client and server are not the same");
        }

        // 3. The state cookie is valid, we can exchange an authorization code for an access token
        Optional<String> redirect = Optional.ofNullable(clientState.get().redirect());
        // TODO: find a better way to pass it?
        request.setAttribute(REDIRECT_ATTRIBUTE_NAME,redirect);

        String desiredConnectionName = clientState.get().connectionName();
        ClientConnection connection = connections.get(desiredConnectionName);
        if (connection == null) {
            throw new IllegalArgumentException(String.format("Requested unknown connection '%s'", desiredConnectionName));
        }
        ResolvedConnection conn = ResolvedOidcConnection.resolve(connection);

        // 4. Exchange the authorization code for an access token, id token and possibly refresh token
        TokenResponse tokenResponse = extractTokenResponse(authCode, conn, callbackUri, codeVerifierCookie);

        // 5. Validate the ID token
        Nonce nonce = null;
        if (checkNonce) {
            nonceCookie = extractCookie(request, OAuthStateManager.COOKIE_NAME_NONCE);
            nonce = new Nonce(nonceCookie.getValue());
        }
        IDTokenClaimsSet claims = validateIdToken(tokenResponse, (ResolvedOidcConnection) conn, nonce );

        // 6. Make the request to userInfo
        String subject = claims.getSubject().getValue();
        OidcAuthCredentials credentials = extractCredentials((OidcConnectionImpl) connection, subject, tokenResponse);

        // 7. create authInfo
        authInfo = new AuthenticationInfo(AUTH_TYPE, subject);
        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);

        logger.info("User {} authenticated", subject);
        return authInfo;
    }

    private @NotNull OidcAuthCredentials extractCredentials(@NotNull OidcConnectionImpl connection, @NotNull String subject, @NotNull TokenResponse tokenResponse) {
        if (userInfoEnabled) {
            HTTPResponse httpResponseUserInfo;
            UserInfoResponse userInfoResponse;
            try {
                httpResponseUserInfo = new UserInfoRequest(new URI(connection.userInfoUrl()), tokenResponse.toSuccessResponse().getTokens().getAccessToken())
                        .toHTTPRequest()
                        .send();
                userInfoResponse = UserInfoResponse.parse(httpResponseUserInfo);
                if (!userInfoResponse.indicatesSuccess()) {
                    // The request failed, e.g. due to invalid or expired token
                    logger.debug("UserInfo error. Received code: {}, message: {}", userInfoResponse.toErrorResponse().getErrorObject().getCode(), userInfoResponse.toErrorResponse().getErrorObject().getDescription());
                    throw new RuntimeException(toErrorMessage("Error in userinfo response", userInfoResponse.toErrorResponse()));
                }

                // Extract the claims
                UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();

                //process credentials
                return userInfoProcessor.process(userInfo.toJSONObject().toJSONString(), tokenResponse.toSuccessResponse().toJSONObject().toJSONString(), subject, idp);

            } catch (IOException | URISyntaxException | ParseException e) {
                logger.error("Error while processing UserInfo: {}", e.getMessage(), e);
                throw new RuntimeException(e);
            }
        } else {
            return userInfoProcessor.process(null, tokenResponse.toSuccessResponse().toSuccessResponse().toJSONObject().toJSONString(), subject, idp);
        }
    }

    private @NotNull Optional<OAuthState> extractClientState(@NotNull AuthorizationResponse authResponse) {
        Optional<OAuthState> clientState = stateManager.toOAuthState(authResponse.getState());
        if (!clientState.isPresent())  {
            // Do not return null to indicate that the handler cannot extract credentials
            throw new IllegalStateException("No state found in authorization response");
        }
        return clientState;
    }

    private static @NotNull String extractAuthCode(@NotNull AuthorizationResponse authResponse) {
        if (authResponse.indicatesSuccess()) {
            AuthorizationCode authCode = authResponse.toSuccessResponse().getAuthorizationCode();
            if (authCode == null) {
                throw new IllegalStateException("No authorization code found in authorization response");
            }
            return authCode.getValue();
        }
        throw new IllegalStateException(authResponse.toErrorResponse().getErrorObject().getDescription());
    }


    private @NotNull TokenResponse extractTokenResponse(@NotNull String authCode, @NotNull ResolvedConnection conn,
                                                               @NotNull String callbackUri, Cookie codeVerifierCookie) {
        if (pkceEnabled && codeVerifierCookie == null) {
            //This line of code should never be executed.
            throw new IllegalStateException("PKCE is enabled but no code verifier cookie found");
        }

        try {
            URI tokenEndpoint = new URI(conn.tokenEndpoint());

            ClientID clientId = new ClientID(conn.clientId());
            AuthorizationCode code = new AuthorizationCode(authCode);

            TokenRequest tokenRequest;
            if (pkceEnabled && conn.clientSecret() != null) {
                // Make the token request, with PKCE
                Secret clientSecret = new Secret(conn.clientSecret());
                ClientSecretBasic clientCredentials = new ClientSecretBasic(clientId, clientSecret);

                tokenRequest = new TokenRequest.Builder(
                        tokenEndpoint,
                        clientCredentials,
                        new AuthorizationCodeGrant(code, new URI(callbackUri), new CodeVerifier(codeVerifierCookie.getValue()))
                ).build();

            } else if (pkceEnabled) {
                tokenRequest = new TokenRequest.Builder(
                        tokenEndpoint,
                        clientId,
                        new AuthorizationCodeGrant(code, new URI(callbackUri), new CodeVerifier(codeVerifierCookie.getValue()))
                ).build();
            } else {
                Secret clientSecret = new Secret(conn.clientSecret());

                ClientSecretBasic clientCredentials = new ClientSecretBasic(clientId, clientSecret);

                tokenRequest = new TokenRequest.Builder(
                        tokenEndpoint,
                        clientCredentials,
                        new AuthorizationCodeGrant(code, new URI(callbackUri))
                ).build();
            }

            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            // GitHub requires an explicitly set Accept header, otherwise the response is url encoded
            // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#2-users-are-redirected-back-to-your-site-by-github
            // see also https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/107/support-application-x-www-form-urlencoded
            httpRequest.setAccept("application/json");
            HTTPResponse httpResponse = httpRequest.send();

            // extract id token from the response
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

            if (!tokenResponse.indicatesSuccess()) {
                logger.debug("Token error. Received code: {}, message: {}", tokenResponse.toErrorResponse().getErrorObject().getCode(), tokenResponse.toErrorResponse().getErrorObject().getDescription());
                throw new RuntimeException(toErrorMessage("Error in token response", tokenResponse.toErrorResponse()));
            }
            return tokenResponse.toSuccessResponse();
        } catch (URISyntaxException e) {
            logger.error("Token Endpoint is not a valid URI: {} Error: {}", conn.tokenEndpoint(), e.getMessage());
            throw new RuntimeException(String.format("Token Endpoint is not a valid URI: %s", conn.tokenEndpoint()));
        } catch (IOException e) {
            logger.error("Failed to exchange authorization code for access token: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            logger.error("Failed to parse token response: {}", e.getMessage(), e);
            throw new RuntimeException(e.getMessage());
        }

    }
    private static @NotNull Cookie extractCookie(@NotNull HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new IllegalStateException("Failed state check: No cookies found");
        }
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie;
            }
        }
        throw new IllegalStateException(String.format("Failed state check: No request cookie named %s found", cookieName));
    }

    /**
     * Validates the ID token received from the OpenID provider.
     * According to this documentation: <a href="https://connect2id.com/blog/how-to-validate-an-openid-connect-id-token">https://connect2id.com/blog/how-to-validate-an-openid-connect-id-token</a>
     * it perform following validations:
     * <ul>
     *  <li> Checks if the ID token JWS algorithm matches the expected one.</li>
     *  <li> Checks the ID token signature (or HMAC) using the provided key material (from the JWK set URL or the client secret).</li>
     *  <li> Checks if the ID token issuer (iss) and audience (aud) match the expected IdP and client_id.</li>
     *  <li> Checks if the ID token is within the specified validity window (between the given issue time and expiration time, given a 1 minute leeway to accommodate clock skew).</li>
     *  <li> Check the nonce value if one is expected.</li>
     * </ul>
     *
     * @param tokenResponse The token response containing the ID token.
     * @param conn         The resolved OIDC connection.
     * @return The validated ID token claims set.
     */
    private static @NotNull IDTokenClaimsSet validateIdToken(@NotNull TokenResponse tokenResponse,
                                                             @NotNull ResolvedOidcConnection conn, Nonce nonce) {
        Issuer issuer = new Issuer(conn.issuer());
        ClientID clientID = new ClientID(conn.clientId());
        try {
            JWSAlgorithm jwsAlg = JWSAlgorithm.RS256; //TODO: Read from config
            URL jwkSetURL = conn.jwkSetURL().toURL();

            IDTokenValidator validator = new IDTokenValidator(issuer, clientID, jwsAlg, jwkSetURL);
            return validator.validate(tokenResponse.toSuccessResponse().getTokens().toOIDCTokens().getIDToken(), nonce);
        } catch (BadJOSEException | JOSEException | MalformedURLException e) {
            logger.error("Failed to validate token: {}", e.getMessage(), e);
            throw new RuntimeException(e.getMessage());
        }
    }

    private static @NotNull String toErrorMessage(@NotNull String context, @NotNull ErrorResponse error) {

        ErrorObject errorObject = error.getErrorObject();
        StringBuilder message = new StringBuilder();

        message.append(context)
                .append(": ")
                .append(errorObject.getCode());

        message.append(". Status code: ").append(errorObject.getHTTPStatusCode());

        String description = errorObject.getDescription();
        if ( description != null )
            message.append(". ").append(description);

        return message.toString();
    }

    @Override
    public boolean requestCredentials(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        logger.debug("inside requestCredentials");

        AuthenticationInfo authInfo = loginCookieManager.verifyLoginCookie(request);
        if (authInfo != null) {
            // User has a valid sling login token
            return true;
        }

        String desiredConnectionName = request.getParameter("c");
        if ( desiredConnectionName == null ) {
            logger.debug("Missing mandatory request parameter 'c' using default connection");
            desiredConnectionName = defaultConnectionName;
        }
        try {
            ClientConnection connection = connections.get(desiredConnectionName);
            if ( connection == null ) {
                logger.debug("Client requested unknown connection");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Client requested unknown connection");
                return false;
            }

            var redirect = getAuthenticationRequestUri(connection, request, URI.create(callbackUri));
            // add all the cookies to the response
            if (!redirect.cookies().isEmpty()) {
                redirect.cookies().forEach(response::addCookie);
            } else {
                logger.warn("No cookies available in the redirect target.");
            }
            response.sendRedirect(redirect.uri().toString());
            return true;
        } catch (IOException e) {
            logger.error("Error while redirecting to default redirect: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private @NotNull RedirectTarget getAuthenticationRequestUri(@NotNull ClientConnection connection,
                                                                @NotNull HttpServletRequest request,
                                                                @NotNull URI redirectUri) {

        ResolvedConnection conn = ResolvedOidcConnection.resolve(connection);

        // The client ID provisioned by the OpenID provider when
        // the client was registered is stored in the connection.

        String redirect = request.getParameter(OAuthStateManager.PARAMETER_NAME_REDIRECT);
        String perRequestKey = new Identifier().getValue();

        String originalRequestUri = request.getRequestURI();
        if (checkNonce) {
            Nonce nonce = new Nonce(new Identifier().getValue());
            State state = stateManager.toNimbusState(new OAuthState(perRequestKey, connection.name(), redirect, nonce.getValue()));
            return RedirectHelper.buildRedirectTarget(path, originalRequestUri, conn, state, perRequestKey, redirectUri, pkceEnabled, nonce.getValue());
        } else {
            State state = stateManager.toNimbusState(new OAuthState(perRequestKey, connection.name(), redirect, null));
            return RedirectHelper.buildRedirectTarget(path, originalRequestUri, conn, state, perRequestKey, redirectUri, pkceEnabled, null);
        }
    }

    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) {
        // TODO: perform logout from Sling and redirect?
    }
    
    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {

        if (loginCookieManager == null) {
            logger.debug("TokenUpdate service is not available");
            return super.authenticationSucceeded(request, response, authInfo);
        }

        if (loginCookieManager.getLoginCookie(request) !=null) {
            // A valid login cookie has been sent
            // According to AuthenticationFeedbackHandler javadoc we send because we did not send a redirect to the user
            deleteAuthenticationCookies(request.getRequestURI(), response);
            return false;
        }

        Object creds = authInfo.get(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS);
        if (creds instanceof OidcAuthCredentials) {
            OidcAuthCredentials oidcAuthCredentials = (OidcAuthCredentials) creds;
            Object tokenValueObject = oidcAuthCredentials.getAttribute(".token");
            if (tokenValueObject != null && !tokenValueObject.toString().isEmpty()) {
                String token = tokenValueObject.toString();
                if (!token.isEmpty()) {
                    logger.debug("Calling TokenUpdate service to update token cookie");
                    loginCookieManager.setLoginCookie(request, response, repository, oidcAuthCredentials);
                }
            }

            Cookie redirectCookie = extractCookie(request, OAuthStateManager.COOKIE_NAME_REDIRECT_URI);
            String redirectUrl = redirectCookie.getValue();

            deleteAuthenticationCookies(request.getRequestURL().toString(), response);
            try {
                response.sendRedirect(redirectUrl);
            } catch (IOException e) {
                logger.error("Error while redirecting to redirect url '{}': {}", redirectUrl, e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }
        return true;
    }

    private void deleteAuthenticationCookies(@NotNull String requestUri, @NotNull HttpServletResponse response) {
        deleteCookie(requestUri, response, OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        deleteCookie(requestUri, response, OAuthStateManager.COOKIE_NAME_REDIRECT_URI);
        if (pkceEnabled) {
            deleteCookie(requestUri, response, OAuthStateManager.COOKIE_NAME_CODE_VERIFIER);
        }
        if (checkNonce) {
            deleteCookie(requestUri, response, OAuthStateManager.COOKIE_NAME_NONCE);
        }
    }

    private void deleteCookie(@NotNull String requestUri, @NotNull HttpServletResponse response, @NotNull String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0); // Marks the cookie for deletion
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(RedirectHelper.findLongestPathMatching(path, requestUri));
        response.addCookie(cookie);
    }
}
