/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.id.Identifier;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.core.AuthConstants;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.jetbrains.annotations.NotNull;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.osgi.service.component.annotations.ReferencePolicyOption.GREEDY;

@Component(
        service = {Servlet.class},
        property = {AuthConstants.AUTH_REQUIREMENTS + "=" + OAuthEntryPointServlet.PATH})
@Designate(ocd = OAuthEntryPointServlet.Config.class)
@SlingServletPaths(OAuthEntryPointServlet.PATH)
public class OAuthEntryPointServlet extends SlingAllMethodsServlet {

    private static final long serialVersionUID = 1L;

    public static final String PATH = "/system/sling/oauth/entry-point"; // NOSONAR

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final Map<String, ClientConnection> connections;

    private final CryptoService cryptoService;

    private final int requestKeyCookieMaxAgeSeconds;

    @ObjectClassDefinition(
            name = "Apache Sling OAuth Entry Point Servlet",
            description = "OAuth entry point servlet for initiating the OAuth authentication flow.")
    @interface Config {
        @AttributeDefinition(
                name = "Request key cookie max age (seconds)",
                description = "Max age in seconds for the sling.oauth-request-key cookie used during the OAuth "
                        + "authentication flow. The cookie holds state between the redirect to the IdP and the "
                        + "callback. Default is 300 (5 minutes). Use a higher value if users often take longer "
                        + "(e.g. consent, 2FA).")
        int requestKeyCookieMaxAgeSeconds() default RedirectHelper.DEFAULT_REQUEST_KEY_COOKIE_MAX_AGE_SECONDS;
    }

    @Activate
    public OAuthEntryPointServlet(
            @Reference(policyOption = GREEDY) List<ClientConnection> connections,
            @Reference CryptoService cryptoService,
            Config config) {
        this.connections = connections.stream().collect(Collectors.toMap(ClientConnection::name, Function.identity()));
        this.cryptoService = cryptoService;
        this.requestKeyCookieMaxAgeSeconds = config.requestKeyCookieMaxAgeSeconds();
    }

    @Override
    protected void doGet(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response)
            throws ServletException {

        try {
            String desiredConnectionName = request.getParameter("c");
            if (desiredConnectionName == null) {
                logger.debug("Missing mandatory request parameter 'c'");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            ClientConnection connection = connections.get(desiredConnectionName);
            if (connection == null) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                            "Client requested unknown connection '{}'; known: '{}'",
                            desiredConnectionName,
                            connections.keySet());
                }
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }

            var redirect = getAuthenticationRequestUri(
                    connection, request, URI.create(OAuthCallbackServlet.getCallbackUri(request)));
            response.addCookie(redirect.cookie());

            response.sendRedirect(redirect.uri().toString());
        } catch (Exception e) {
            throw new OAuthEntryPointException("Internal error", e);
        }
    }

    private @NotNull RedirectTarget getAuthenticationRequestUri(
            @NotNull ClientConnection connection, @NotNull SlingHttpServletRequest request, @NotNull URI callbackUri)
            throws OAuthEntryPointException {
        ResolvedConnection conn = ResolvedOAuthConnection.resolve(connection);

        // TODO: Should we redirect to the target url when redirect is null?
        String redirect = request.getParameter(RedirectHelper.PARAMETER_NAME_REDIRECT);
        RedirectHelper.validateRedirect(redirect);

        String perRequestKey = new Identifier().getValue();
        OAuthCookieValue oAuthCookieValue = new OAuthCookieValue(perRequestKey, connection.name(), redirect);

        return RedirectHelper.buildRedirectTarget(
                new String[] {PATH},
                callbackUri,
                conn,
                oAuthCookieValue,
                cryptoService,
                null,
                requestKeyCookieMaxAgeSeconds);
    }
}
