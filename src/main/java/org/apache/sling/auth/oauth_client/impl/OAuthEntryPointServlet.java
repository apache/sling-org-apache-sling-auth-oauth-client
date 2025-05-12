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

import static org.osgi.service.component.annotations.ReferencePolicyOption.GREEDY;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.State;

@Component(service = { Servlet.class },
    property = { AuthConstants.AUTH_REQUIREMENTS +"=" + OAuthEntryPointServlet.PATH }
)
@SlingServletPaths(OAuthEntryPointServlet.PATH)
public class OAuthEntryPointServlet extends SlingAllMethodsServlet {

    private static final long serialVersionUID = 1L;


    public static final String PATH = "/system/sling/oauth/entry-point"; // NOSONAR
    
    private final Logger logger = LoggerFactory.getLogger(getClass());
    
    private final Map<String, ClientConnection> connections;
    private final OAuthStateManager stateManager;

    @Activate
    public OAuthEntryPointServlet(@Reference(policyOption = GREEDY) List<ClientConnection> connections,
            @Reference OAuthStateManager stateManager) {
        this.connections = connections.stream()
                .collect(Collectors.toMap( ClientConnection::name, Function.identity()));
        this.stateManager = stateManager;
    }

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {
        
        try {
            String desiredConnectionName = request.getParameter("c");
            if ( desiredConnectionName == null ) {
                logger.debug("Missing mandatory request parameter 'c'");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            ClientConnection connection = connections.get(desiredConnectionName);
            if ( connection == null ) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Client requested unknown connection '{}'; known: '{}'", desiredConnectionName, connections.keySet());
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
                
            var redirect = getAuthenticationRequestUri(connection, request, URI.create(OAuthCallbackServlet.getCallbackUri(request)));
            response.addCookie(redirect.cookies()[0]);
            response.sendRedirect(redirect.uri().toString());
        } catch (Exception e) {
            throw new OAuthEntryPointException("Internal error", e);
        }
    }
    
    private RedirectTarget getAuthenticationRequestUri(ClientConnection connection, SlingHttpServletRequest request, URI redirectUri) {
        
        ResolvedOAuthConnection conn = ResolvedOAuthConnection.resolve(connection);

        // The client ID provisioned by the OpenID provider when
        // the client was registered
        ClientID clientID = new ClientID(conn.clientId());

        String redirect = request.getParameter(OAuthStateManager.PARAMETER_NAME_REDIRECT);
        String perRequestKey = new Identifier().getValue();
        State state = stateManager.toNimbusState(new OAuthState(perRequestKey, connection.name(), redirect));

        return RedirectHelper.buildRedirectTarget(clientID, conn.authorizationEndpoint(), conn.scopes(), conn.additionalAuthorizationParameters(), state, perRequestKey, redirectUri, false);
    }
}
