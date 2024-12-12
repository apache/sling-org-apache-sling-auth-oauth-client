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

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.jackrabbit.oak.spi.security.authentication.credentials.CredentialsSupport;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityProvider;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.OAuthTokenStore;
import org.apache.sling.auth.oauth_client.OAuthTokens;
import org.apache.sling.auth.oauth_client.TokenUpdate;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
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
import java.net.URI;
import java.net.URISyntaxException;
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


    private static final Logger logger = LoggerFactory.getLogger(OidcAuthenticationHandler.class);
    private static final String AUTH_TYPE = "oidc";
    public static final String REDIRECT_ATTRIBUTE_NAME = "sling.redirect";

    private final SlingRepository repository;

    private final Map<String, ClientConnection> connections;
    private final OAuthStateManager stateManager;

    private String idp = "oidc";

    private final OAuthTokenStore tokenStore;

    private  final String callbackUri;

    private TokenUpdate tokenUpdate;

    private String defaultRedirect;
    private static final long serialVersionUID = 1L;

    // We don't want leave the cookie lying around for a long time because it it not needed.
    // At the same time, some OAuth user authentication flows take a long time due to
    // consent, account selection, 2FA, etc so we cannot make this too short.
    protected static final int COOKIE_MAX_AGE_SECONDS = 300;

    @ObjectClassDefinition(
            name = "Apache Sling Oidc Authentication Handler",
            description = "Apache Sling Oidc Authentication Handler Service"
    )

    @interface Config {
        @AttributeDefinition(name = "Path",
                description = "Repository path for which this authentication handler should be used by Sling. If this is " +
                        "empty, the authentication handler will be disabled. By default this is set to \"/\".")
        String path() default "/";

        @AttributeDefinition(name = "Sync Handler Configuration Name",
                description = "Name of Sync Handler Configuration")
        String idp() default "oidc";

        @AttributeDefinition(name = "Callback URI",
                description = "Callback URI")
        String callbackUri() default "callbackUri";

        @AttributeDefinition(name = "Default Redirect",
                description = "Default Redirect")
        String defaultRedirect() default "/";


    }

    @Activate
    public OidcAuthenticationHandler(@Reference(policyOption = ReferencePolicyOption.GREEDY) @NotNull SlingRepository repository,
                                     @NotNull BundleContext bundleContext, @Reference List<ClientConnection> connections,
                                     @Reference OAuthStateManager stateManager,
                                     @Reference OAuthTokenStore tokenStore, Config config,
                                     @Reference TokenUpdate tokenUpdate) {
        this.repository = repository;
        this.connections = connections.stream()
                .collect(Collectors.toMap( ClientConnection::name, Function.identity()));
        this.stateManager = stateManager;
        this.tokenStore = tokenStore;
        this.idp = config.idp();
        this.callbackUri = config.callbackUri();
        this.defaultRedirect = config.defaultRedirect();
        this.tokenUpdate = tokenUpdate;

        logger.debug("activate: registering ExternalIdentityProvider");
        bundleContext.registerService(
                new String[]{ExternalIdentityProvider.class.getName(), CredentialsSupport.class.getName()}, new OidcIdentityProvider(idp),
                null);

    }

    @Override
    public AuthenticationInfo extractCredentials(@Nullable HttpServletRequest request, @Nullable HttpServletResponse response) {
        logger.debug("inside extractCredentials");

        StringBuffer requestURL = request.getRequestURL();
        if ( request.getQueryString() != null )
            requestURL.append('?').append(request.getQueryString());

        AuthorizationResponse authResponse;
        Optional<OAuthState> clientState;
        Cookie stateCookie = null;
        try {
            authResponse = AuthorizationResponse.parse(new URI(requestURL.toString()));

            clientState = stateManager.toOAuthState(authResponse.getState());
            if ( !clientState.isPresent() )  {
                logger.debug("No state found in authorization response");
                // Return null to indicate that the handler cannot extract credentials
                return null;
            }

            Cookie[] cookies = request.getCookies();
            // iterate over the cookie and get the one with name OAuthStateManager.COOKIE_NAME_REQUEST_KEY
            for (Cookie cookie : cookies) {
                if (OAuthStateManager.COOKIE_NAME_REQUEST_KEY.equals(cookie.getName())) {
                    stateCookie = cookie;
                    break;
                }
            }
            if ( stateCookie == null ) {
                logger.debug("Failed state check: No request cookie named '{}' found", OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return AuthenticationInfo.FAIL_AUTH;
            }

        } catch (ParseException | URISyntaxException e) {
            logger.debug("Failed to parse authorization response");
            return null;
        }

        try {
            String stateFromAuthServer = clientState.get().perRequestKey();
            String stateFromClient = stateCookie.getValue();
            if ( ! stateFromAuthServer.equals(stateFromClient) )
                throw new IllegalStateException("Failed state check: request keys from client and server are not the same");

            if ( !authResponse.indicatesSuccess() ) {
                AuthorizationErrorResponse errorResponse = authResponse.toErrorResponse();
                throw new OAuthCallbackException("Authentication failed", new RuntimeException(toErrorMessage("Error in authentication response", errorResponse)));
            }

            Optional<String> redirect = Optional.ofNullable(clientState.get().redirect());
            // TODO: find a better pass to pass it?
            request.setAttribute(REDIRECT_ATTRIBUTE_NAME,redirect);

            String authCode = authResponse.toSuccessResponse().getAuthorizationCode().getValue();

            String desiredConnectionName = clientState.get().connectionName();
            if ( desiredConnectionName == null || desiredConnectionName.isEmpty() )
                throw new IllegalArgumentException("No connection found in clientState");

            ClientConnection connection = connections.get(desiredConnectionName);
            if ( connection == null )
                throw new IllegalArgumentException(String.format("Requested unknown connection '%s'", desiredConnectionName));

            ResolvedOAuthConnection conn = ResolvedOAuthConnection.resolve(connection);

            ClientID clientId = new ClientID(conn.clientId());
            Secret clientSecret = new Secret(conn.clientSecret());
            ClientSecretBasic clientCredentials = new ClientSecretBasic(clientId, clientSecret);

            AuthorizationCode code = new AuthorizationCode(authCode);

            URI tokenEndpoint = new URI(conn.tokenEndpoint());

            TokenRequest tokenRequest = new TokenRequest.Builder(
                    tokenEndpoint,
                    clientCredentials,
                    new AuthorizationCodeGrant(code, new URI(callbackUri))
            ).build();

            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            // GitHub requires an explicitly set Accept header, otherwise the response is url encoded
            // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#2-users-are-redirected-back-to-your-site-by-github
            // see also https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/107/support-application-x-www-form-urlencoded
            httpRequest.setAccept("application/json");
            HTTPResponse httpResponse = httpRequest.send();

            // extract oid token from the response
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);
            if ( !tokenResponse.indicatesSuccess() ) {
                logger.debug("Token error. Received code: {}, message: {}", tokenResponse.toErrorResponse().getErrorObject().getCode(), tokenResponse.toErrorResponse().getErrorObject().getDescription());
                throw new OAuthCallbackException("Token exchange error", new RuntimeException(toErrorMessage("Error in token response", tokenResponse.toErrorResponse())));
            }
            // Make the request to userInfo
            // TODO: fix the cast and manage OAuthConnections as well?
            HTTPResponse httpResponseUserInfo = new UserInfoRequest(new URI(((OidcConnectionImpl)connection).userInfoUrl()), tokenResponse.toSuccessResponse().getTokens().getAccessToken())
                    .toHTTPRequest()
                    .send();

            UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponseUserInfo);
            if (! userInfoResponse.indicatesSuccess()) {
                // The request failed, e.g. due to invalid or expired token
                logger.debug("UserInfo error. Received code: {}, message: {}",userInfoResponse.toErrorResponse().getErrorObject().getCode(), userInfoResponse.toErrorResponse().getErrorObject().getDescription());
                throw new OAuthCallbackException("Token exchange error", new RuntimeException(toErrorMessage("Error in token response", tokenResponse.toErrorResponse())));

            }

            // Extract the claims
            UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
            logger.debug("Subject: " + userInfo.getSubject());
            logger.debug("Email: " + userInfo.getEmailAddress());
            logger.debug("Name: " + userInfo.getGivenName());
            logger.debug("FamilyName: " + userInfo.getFamilyName());
            OAuthTokens tokens = Converter.toSlingOAuthTokens(tokenResponse.toSuccessResponse().getTokens());

            // Create AuthenticationInfo object
            OidcAuthCredentials credentials = new OidcAuthCredentials(userInfo.getSubject().getValue(), idp);
            credentials.setAttribute(".token", "");
            credentials.setAttribute("profile/email", userInfo.getEmailAddress());
            credentials.setAttribute("profile/givenName", userInfo.getGivenName());
            credentials.setAttribute("profile/familyName", userInfo.getFamilyName());
            //TODO: Add more attributes
            //Store the Access Token on user node
            credentials.setAttribute(JcrUserHomeOAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN, tokens.accessToken());

            AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, userInfo.getSubject().getValue());
            authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);

            logger.info("User {} authenticated", userInfo.getSubject());
            return authInfo;


        } catch (IllegalStateException | IllegalArgumentException | OAuthCallbackException e) {
            logger.error("State check failed", e);
            return AuthenticationInfo.FAIL_AUTH;
        } catch (Exception e) {
            logger.error("Unknown error", e);
            return AuthenticationInfo.FAIL_AUTH;
        }

    }

    private static String toErrorMessage(String context, ErrorResponse error) {

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
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) {
        try {
            String desiredConnectionName = request.getParameter("c");
            if ( desiredConnectionName == null ) {
                logger.debug("Missing mandatory request parameter 'c'");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return false;
            }

            ClientConnection connection = connections.get(desiredConnectionName);
            if ( connection == null ) {
                if ( logger.isDebugEnabled() )
                    logger.debug("Client requested unknown connection '{}'; known: '{}'", desiredConnectionName, connections.keySet());
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return false;
            }

            var redirect = getAuthenticationRequestUri(connection, request, URI.create(callbackUri));
            response.addCookie(redirect.cookie());
            response.sendRedirect(redirect.uri().toString());
            return true;
        } catch (Exception e) {
            logger.error("Internal error", e);
            return false;
        }
    }

    private OAuthEntryPointServlet.RedirectTarget getAuthenticationRequestUri(ClientConnection connection, HttpServletRequest request, URI redirectUri) {

        ResolvedOAuthConnection conn = ResolvedOAuthConnection.resolve(connection);

        // The client ID provisioned by the OpenID provider when
        // the client was registered
        ClientID clientID = new ClientID(conn.clientId());

        String connectionName = connection.name();
        String redirect = request.getParameter(OAuthStateManager.PARAMETER_NAME_REDIRECT);
        String perRequestKey = new Identifier().getValue();

        Cookie cookie = new Cookie(OAuthStateManager.COOKIE_NAME_REQUEST_KEY, perRequestKey);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(COOKIE_MAX_AGE_SECONDS);

        State state = stateManager.toNimbusState(new OAuthState(perRequestKey, connectionName, redirect));

        URI authorizationEndpointUri = URI.create(conn.authorizationEndpoint());

        // Compose the OpenID authentication request (for the code flow)
        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                ResponseType.CODE,
                clientID)
                .scope(new Scope(conn.scopes().toArray(new String[0])))
                .endpointURI(authorizationEndpointUri)
                .redirectionURI(redirectUri)
                .state(state);

        if ( conn.additionalAuthorizationParameters() != null ) {
            conn.additionalAuthorizationParameters().stream()
                    .map( s -> s.split("=") )
                    .filter( p -> p.length == 2 )
                    .forEach( p -> authRequestBuilder.customParameter(p[0], p[1]));
        }

        return new OAuthEntryPointServlet.RedirectTarget(authRequestBuilder.build().toURI(), cookie);
    }

    record RedirectTarget(URI uri, Cookie cookie) {}

    @Override
    public void dropCredentials(HttpServletRequest request, HttpServletResponse response) {
        // TODO: perform logout from Sling and redirect?
    }
    
    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {

        if (tokenUpdate == null) {
            logger.debug("TokenUpdate service is not available");
            return super.authenticationSucceeded(request, response, authInfo);
        }


        Object creds = authInfo.get(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS);
        if (creds instanceof OidcAuthCredentials) {
            OidcAuthCredentials sc = (OidcAuthCredentials) creds;
            Object tokenValueObject = sc.getAttribute(".token");
            if (tokenValueObject != null && !tokenValueObject.toString().isEmpty()) {
                String token = tokenValueObject.toString();
                if (!token.isEmpty()) {
                    logger.debug("Calling TokenUpdate service to update token cookie");
                    tokenUpdate.setToken(request, response, repository, token, true);
                }
            }

            try {
                Object redirect = request.getAttribute("sling.redirect");
                if ( redirect != null && redirect instanceof String ) {
                    response.sendRedirect(redirect.toString());
                } else {
                    response.sendRedirect(defaultRedirect);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return true;
    }

}
