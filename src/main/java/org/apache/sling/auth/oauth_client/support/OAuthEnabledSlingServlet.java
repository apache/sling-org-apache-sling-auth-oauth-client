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
package org.apache.sling.auth.oauth_client.support;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.OAuthToken;
import org.apache.sling.auth.oauth_client.OAuthTokenAccess;
import org.apache.sling.auth.oauth_client.OAuthTokenResponse;
import org.apache.sling.auth.oauth_client.TokenState;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public abstract class OAuthEnabledSlingServlet extends SlingSafeMethodsServlet {

	private static final long serialVersionUID = 1L;
	
	private final Logger logger = LoggerFactory.getLogger(getClass());

    private final ClientConnection connection;

    private final OAuthTokenAccess tokenAccess;
	
    protected OAuthEnabledSlingServlet(ClientConnection connection, OAuthTokenAccess tokenAccess) {
        this.connection = Objects.requireNonNull(connection, "connection may not null");
        this.tokenAccess = Objects.requireNonNull(tokenAccess, "tokenAccess may not null");
    }

	@Override
	protected void doGet(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response)
			throws ServletException, IOException {
	    
	    if ( request.getUserPrincipal() == null ) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User is not authenticated");
            return;
	    }

	    String redirectPath = Objects.requireNonNull(getRedirectPath(request), "getRedirectPath() may not return null");
	    
	    if ( logger.isDebugEnabled() )
	        logger.debug("Configured with connection (name={}) and redirectPath={}", connection.name(), redirectPath);
	    
	    OAuthTokenResponse tokenResponse = tokenAccess.getAccessToken(connection, request, redirectPath);
	    if (tokenResponse.hasValidToken() ) {
	        doGetWithPossiblyInvalidToken(request, response, new OAuthToken(TokenState.VALID, tokenResponse.getTokenValue()), redirectPath);
	    } else {
	        response.sendRedirect(tokenResponse.getRedirectUri().toString());
	    }
	}
	
	private void doGetWithPossiblyInvalidToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, 
											   @NotNull OAuthToken token, @NotNull String redirectPath) throws ServletException, IOException {
	    try {
            doGetWithToken(request, response, token);
        } catch (ServletException | IOException e) {
            if (isInvalidAccessTokenException(e)) {
                logger.warn("Invalid access token, clearing restarting OAuth flow", e);
                OAuthTokenResponse tokenResponse = tokenAccess.clearAccessToken(connection, request, getRedirectPath(request));
                response.sendRedirect(tokenResponse.getRedirectUri().toString());
            } else {
                throw e;
            }
        }
    }
	
	// TODO - do we need this as a protected method?
	protected @NotNull String getRedirectPath(@NotNull SlingHttpServletRequest request) {
	    return request.getRequestURI();
	}

	protected abstract void doGetWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, @NotNull OAuthToken token)
	        throws ServletException, IOException;
	
    protected boolean isInvalidAccessTokenException(Exception e) {
        return false;
    }
}
