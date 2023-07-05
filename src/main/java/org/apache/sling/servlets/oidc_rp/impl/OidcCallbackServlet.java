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
package org.apache.sling.servlets.oidc_rp.impl;

import static org.osgi.service.component.annotations.ReferencePolicyOption.GREEDY;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.apache.sling.servlets.oidc_rp.OidcConnection;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

@Component(service = { Servlet.class },
    property = { AuthConstants.AUTH_REQUIREMENTS +"=" + OidcCallbackServlet.PATH }
)
@SlingServletPaths(OidcCallbackServlet.PATH)
public class OidcCallbackServlet extends SlingAllMethodsServlet {

    static final String PATH = "/system/sling/oidc/callback";

    private static final long serialVersionUID = 1L;

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Map<String, OidcConnection> connections;
    private final OidcConnectionPersister persister;
    private final OidcProviderMetadataRegistry metadataRegistry;

    static String getCallbackUri(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + PATH;
    }

    @Activate
    public OidcCallbackServlet(@Reference(policyOption = GREEDY) List<OidcConnection> connections, @Reference OidcConnectionPersister persister,
            @Reference OidcProviderMetadataRegistry metadataRegistry) {
        this.connections = connections.stream()
                .collect(Collectors.toMap( OidcConnection::name, Function.identity()));
        this.metadataRegistry = metadataRegistry;
        this.persister = persister;
    }

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {
        try {
            StringBuffer requestURL = request.getRequestURL();
            if ( request.getQueryString() != null )
                requestURL.append('?').append(request.getQueryString());

            AuthenticationResponse authResponse = AuthenticationResponseParser.parse(new URI(requestURL.toString()));
            OidcStateManager stateManager = OidcStateManager.stateFor(request);
            if ( authResponse.getState() == null || !stateManager.isValidState(authResponse.getState()))
                throw new ServletException("Failed state check");

            if ( response instanceof AuthenticationErrorResponse )
                throw new ServletException(authResponse.toErrorResponse().getErrorObject().toString());

            Optional<String> redirect = stateManager.getStateAttribute(authResponse.getState(), OidcStateManager.PARAMETER_NAME_REDIRECT);
            
            String authCode = authResponse.toSuccessResponse().getAuthorizationCode().getValue();
            
            Optional<String> desiredConnectionName = stateManager.getStateAttribute(authResponse.getState(), OidcStateManager.PARAMETER_NAME_CONNECTION);
            stateManager.unregisterState(authResponse.getState());
            if ( desiredConnectionName.isEmpty() ) {
                logger.warn("Did not find any connection in stateManager");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);  
                return;
            }
            OidcConnection connection = connections.get(desiredConnectionName.get());
            if ( connection == null ) {
                logger.warn("Requested unknown connection {}", desiredConnectionName.get());
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            if ( connection.baseUrl() == null )
                throw new ServletException("Misconfigured baseUrl");
            
            ClientID clientId = new ClientID(connection.clientId());
            Secret clientSecret = new Secret(connection.clientSecret());
            ClientSecretBasic clientCredentials = new ClientSecretBasic(clientId, clientSecret);
            
            AuthorizationCode code = new AuthorizationCode(authCode);
            
            OIDCProviderMetadata providerMetadata = metadataRegistry.getProviderMetadata(connection.baseUrl());
            
            TokenRequest tokenRequest = new TokenRequest(
                providerMetadata.getTokenEndpointURI(),
                clientCredentials,
                new AuthorizationCodeGrant(code, new URI(getCallbackUri(request)))
            );
            
            OIDCTokenResponse tokenResponse = OIDCTokenResponse.parse(tokenRequest.toHTTPRequest().send());
            
            if ( !tokenResponse.indicatesSuccess() ) {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                logger.warn("Error returned when trying to obtain access token : {}, {}", 
                        errorResponse.getErrorObject().getCode(), errorResponse.getErrorObject().getDescription());
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            // TODO - additional validations for the id_token
            // - does the 'aud' claim match the client id of our connection
            // - nonce validation (?)
            // - iat/exp validation (?)

            persister.persistTokens(connection, request.getResourceResolver(), tokenResponse.getOIDCTokens());

            if ( redirect.isEmpty() ) {
                response.setStatus(HttpServletResponse.SC_OK);
                response.addHeader("Content-Type", "text/plain");
                response.getWriter().write("OK");
                response.getWriter().flush();
                response.getWriter().close();
            } else {
                response.sendRedirect(URLDecoder.decode(redirect.get(), StandardCharsets.UTF_8));
            }
        } catch (ParseException | URISyntaxException | IOException e) {
            throw new ServletException(e);
        }
    }

}
