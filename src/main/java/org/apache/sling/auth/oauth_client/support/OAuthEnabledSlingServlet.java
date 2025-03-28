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

import static org.apache.sling.api.servlets.HttpConstants.METHOD_DELETE;
import static org.apache.sling.api.servlets.HttpConstants.METHOD_GET;
import static org.apache.sling.api.servlets.HttpConstants.METHOD_POST;
import static org.apache.sling.api.servlets.HttpConstants.METHOD_PUT;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.OAuthTokenAccess;
import org.apache.sling.auth.oauth_client.OAuthTokenResponse;
import org.apache.sling.auth.oauth_client.impl.OAuthToken;
import org.apache.sling.auth.oauth_client.impl.TokenState;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Support class for implementing OAuth-enabled servlets
 * 
 * <p>Features:</p>
 * 
 * <ul> 
 *  <li>Handles OAuth token retrieval and refresh</li>
 *  <li>Starts the authentication flow if no token is available</li>
 *  <li>Handles invalid access tokens ( {@link #isInvalidAccessTokenException(Exception)} )</li>
 * </ul>
 */
public abstract class OAuthEnabledSlingServlet extends SlingAllMethodsServlet {

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
        handleRequestWithToken(request, response, METHOD_GET);
    }

    @Override
    protected void doPost(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response)
            throws ServletException, IOException {
        handleRequestWithToken(request, response, METHOD_POST);
    }
    
    @Override
    protected void doDelete(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response)
            throws ServletException, IOException {
        handleRequestWithToken(request, response, METHOD_DELETE);
    }
    
    @Override
    protected void doPut(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response)
            throws ServletException, IOException {
        handleRequestWithToken(request, response, METHOD_PUT);
    }
    
    @Override
    protected void doGeneric(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response)
            throws ServletException, IOException {
        handleRequestWithToken(request, response, request.getMethod());
    }
    
	private void handleRequestWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, String method)
			throws ServletException, IOException {
	    
	    if ( request.getRemoteUser() == null ) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User is not authenticated");
            return;
	    }

	    String redirectPath = Objects.requireNonNull(getRedirectPath(request), "getRedirectPath() may not return null");
	    
	    if ( logger.isDebugEnabled() )
	        logger.debug("Configured with connection (name={}) and redirectPath={}", connection.name(), redirectPath);
	    
	    OAuthTokenResponse tokenResponse = tokenAccess.getAccessToken(connection, request, redirectPath);
	    if (tokenResponse.hasValidToken() ) {
	        OAuthToken token = new OAuthToken(TokenState.VALID, tokenResponse.getTokenValue());
	        try {
	        switch ( method ) {
                case METHOD_GET:
                    doGetWithToken(request, response, token.getValue());
                    break;
                case METHOD_POST:
                    doPostWithToken(request, response, token.getValue());
                    break;
                case METHOD_PUT:
                    doPutWithToken(request, response, token.getValue());
                    break;
                case METHOD_DELETE:
                    doDeleteWithToken(request, response, token.getValue());
                    break;
                default:
                    doGenericWithToken(request, response, token.getValue());
                    break;
	        }
        } catch (IOException | ServletException e) {
            if (isInvalidAccessTokenException(e)) {
                logger.warn("Invalid access token, clearing exiting token and restarting OAuth flow", e);
                OAuthTokenResponse newTokenResponse = tokenAccess.clearAccessToken(connection, request, redirectPath);
                response.sendRedirect(newTokenResponse.getRedirectUri().toString());
            } else {
                throw e;
            }
        }
	    } else {
	        response.sendRedirect(tokenResponse.getRedirectUri().toString());
	    }
	}

	// TODO - do we need this as a protected method?
	protected @NotNull String getRedirectPath(@NotNull SlingHttpServletRequest request) {
	    return request.getRequestURI();
	}

	protected void doGetWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, String accessToken)
	        throws IOException, ServletException {
	    handleMethodNotImplemented(request, response);
	}

	protected void doPostWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, String accessToken)
	        throws IOException, ServletException {
	    handleMethodNotImplemented(request, response);
	}

	protected void doPutWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, String accessToken)
	        throws IOException, ServletException {
	    handleMethodNotImplemented(request, response);
	}

	protected void doDeleteWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, String accessToken)
	        throws IOException, ServletException {
	    handleMethodNotImplemented(request, response);
	}
	
    protected void doGenericWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, String accessToken)
            throws IOException, ServletException {
        handleMethodNotImplemented(request, response);
    }
	
    protected boolean isInvalidAccessTokenException(Exception e) {
        return false;
    }
}
