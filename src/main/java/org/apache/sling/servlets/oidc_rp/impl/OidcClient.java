package org.apache.sling.servlets.oidc_rp.impl;

import java.io.IOException;
import java.net.URI;

import org.apache.sling.servlets.oidc_rp.OidcConnection;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;

@Component(service = OidcClient.class)
public class OidcClient {

    private final OidcProviderMetadataRegistry providerMetadataRegistry;

    @Activate
    public OidcClient(@Reference OidcProviderMetadataRegistry providerMetadataRegistry) {
        this.providerMetadataRegistry = providerMetadataRegistry;
    }

    public Tokens refreshAccessToken(OidcConnection connection, String refreshToken2) throws ParseException, IOException {

     // Construct the grant from the saved refresh token
     RefreshToken refreshToken = new RefreshToken(refreshToken2);
     AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(refreshToken);

     // The credentials to authenticate the client at the token endpoint
     ClientID clientID = new ClientID(connection.clientId());
     Secret clientSecret = new Secret(connection.clientSecret());
     ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

     // The token endpoint
     URI tokenEndpoint = providerMetadataRegistry.getProviderMetadata(connection.baseUrl()).getTokenEndpointURI();

     // Make the token request
     TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, refreshTokenGrant);

     TokenResponse response = TokenResponse.parse(request.toHTTPRequest().send());

     if (! response.indicatesSuccess()) {
         // We got an error response...
         TokenErrorResponse errorResponse = response.toErrorResponse();
         throw new RuntimeException("Failed refreshing the access token " + errorResponse.getErrorObject().getCode() + " : " + errorResponse.getErrorObject().getDescription());
     }

     AccessTokenResponse successResponse = response.toSuccessResponse();

     // Get the access token, the refresh token may be updated
     return successResponse.getTokens();
    }
}
