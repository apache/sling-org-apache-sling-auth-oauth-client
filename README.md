[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-oauth-client/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-oauth-client/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-oauth-client/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-auth-oauth-client/job/master/test/?width=800&height=600)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-auth-oauth-client&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-auth-oauth-client)&#32;[![auth](https://sling.apache.org/badges/group-auth.svg)](https://github.com/apache/sling-aggregator/blob/master/docs/groups/auth.md) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling OAuth 2.0 client with OIDC support

> [!IMPORTANT]
> The Java APIs exported by this bundle are considered **experimental** and are marked as
> `@ProviderType`. The APIs may change in an incompatible way in future minor releases.

This bundle adds support for Sling-based applications to function as an OAuth 2.0 client
([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) and as an
[OpenID Connect](https://openid.net/developers/how-connect-works/) relying party.

It focuses on secure access to OAuth/OIDC tokens and supports authorization code flow for both OAuth 2.0 and OIDC.

## Build and test

- Build bundle and run tests: `mvn clean install`
- Unit tests only: `mvn test`
- Full build including integration tests: `mvn verify`
- Skip integration tests: `mvn install -DskipITs`
- Disable Keycloak-based ITs explicitly: `mvn verify -Dit.keycloak.enabled=false`

## Usage

### Models and other Java APIs

The `OAuthTokenAccess` OSGi service exposes methods to retrieve and clear access tokens. These methods encapsulate
persistence concerns and handle refresh tokens transparently, when present.

```java
@Model(adaptables = SlingHttpServletRequest.class)
public class MyModel {

    @SlingObject private SlingHttpServletRequest request;

    @OSGiService(filter = "(name=foo)") private ClientConnection connection;

    @OSGiService private OAuthTokenAccess tokenAccess;

    private OAuthTokenResponse tokenResponse;

    @PostConstruct
    public void initToken() {
        tokenResponse = tokenAccess.getAccessToken(connection, request, request.getRequestURI());
    }

    public MyView getResponse() {
        if (tokenResponse.hasValidToken()) {
            return doQuery(tokenResponse.getTokenValue());
        }
        return null;
    }

    public String getRedirectLink() {
        if (!tokenResponse.hasValidToken()) {
            return tokenResponse.getRedirectUri().toString();
        }
        return null;
    }
}
```

### Servlets

The bundle exposes an abstract `OAuthEnabledSlingServlet` that handles token retrieval/refresh and redirects to the OAuth/OIDC flow when needed.

```java
import java.io.IOException;
import javax.servlet.Servlet;
import javax.servlet.ServletException;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.OAuthTokenAccess;
import org.apache.sling.auth.oauth_client.support.OAuthEnabledSlingServlet;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.jetbrains.annotations.NotNull;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

@Component(service = Servlet.class)
@SlingServletPaths("/bin/myservlet")
public class MySlingServlet extends OAuthEnabledSlingServlet {

    private final MyRemoteService svc;

    @Activate
    public MySlingServlet(
            @Reference ClientConnection connection,
            @Reference OAuthTokenAccess tokenAccess,
            @Reference MyRemoteService svc) {
        super(connection, tokenAccess);
        this.svc = svc;
    }

    @Override
    protected void doGetWithToken(
            @NotNull SlingHttpServletRequest request,
            @NotNull SlingHttpServletResponse response,
            String accessToken) throws IOException, ServletException {
        this.svc.query("my-query", accessToken).writeResponseTo(response.getOutputStream());
    }
}
```

### OIDC authentication handler

This bundle also ships `OidcAuthenticationHandler` for Sling Auth Core integration.

Notable capabilities:

- `redirect` request parameter support to return users to a specific local path after authentication
- Resource Indicators support (`resource`) for RFC 8707
- Configurable max age for the transient `sling.oauth-request-key` cookie (`requestKeyCookieMaxAgeSeconds`)
- Optional SP-initiated logout support (`enableSPInitiatedSingleLogout`) with host allow-list enforcement (`logoutRedirectAllowedHosts`)

### Clearing access tokens

If an access token response contains an expiry date, the bundle makes sure expired tokens are not returned by APIs.
This does not cover out-of-band invalidation at the provider, so clients still need provider-specific invalid-token handling.

#### When the request/response are available

This is generally recommended because it can return a redirect URI that starts a new OAuth authorization flow.

```java
@Model(adaptables = SlingHttpServletRequest.class)
public class MySlingModel {
    @OSGiService private OAuthTokenAccess tokenAccess;
    @SlingObject SlingHttpServletRequest request;
    @OSGiService(filter = "(name=foo)") private ClientConnection connection;

    public String getLink() {
        // code elided
        if (accessTokenIsInvalid()) {
            OAuthTokenResponse response = tokenAccess.clearAccessToken(connection, request, request.getRequestURI());
            return response.getRedirectUri().toString();
        }
        return null;
    }
}
```

#### When request/response are not available

Use this for background or non-interactive invalidation where no redirect URI is needed.

```java
@Component
public class MyComponent {
    @Reference private OAuthTokenAccess tokenAccess;

    public void execute(@Reference ClientConnection connection, ResourceResolver resolver) {
        // code elided
        if (accessTokenIsInvalid()) {
            tokenAccess.clearAccessToken(connection, resolver);
        }
    }
}
```

#### When extending `OAuthEnabledSlingServlet`

For subclasses of `OAuthEnabledSlingServlet`, override `isInvalidAccessTokenException`. If it returns `true`, the token is cleared and a new OAuth flow starts.

```java
@Component(service = Servlet.class)
@SlingServletPaths("/bin/myservlet")
public class MySlingServlet extends OAuthEnabledSlingServlet {

    // other methods elided

    @Override
    protected boolean isInvalidAccessTokenException(Exception e) {
        return e.getCause() instanceof InvalidAccessTokenException;
    }
}
```

### Error handling

Top-level OAuth servlets validate required parameters and return HTTP 400 for missing/invalid inputs.

For other OAuth flow problems, these servlets throw specific `ServletException` subclasses with user-safe messages and nested root causes for logging:

- `org.apache.sling.auth.oauth_client.impl.OAuthCallbackException`
- `org.apache.sling.auth.oauth_client.impl.OAuthEntryPointException`
- `org.apache.sling.auth.oauth_client.impl.OAuthFlowException` (superclass)

It is recommended to install dedicated error handlers for these exceptions. See
[Apache Sling error handling documentation](https://sling.apache.org/documentation/the-sling-engine/errorhandling.html).

### Client registration

Client registration is provider-specific. At minimum:

- Register callback URL as `$HOST/system/sling/oauth/callback` (for local development typically `http://localhost:8080/system/sling/oauth/callback`)
- Capture provider client ID and client secret
- Define scopes your application needs

Validated providers include:

- Google (OIDC) via `https://accounts.google.com`
- GitHub (OAuth 2.0) via `https://github.com/login/oauth/authorize` and `https://github.com/login/oauth/access_token`
- Keycloak
- Microsoft (OIDC) via `https://login.microsoftonline.com/$TENANT_ID/v2.0`
- Adobe IMS (OAuth 2.0) via `https://ims-na1.adobelogin.com/ims/authorize/v3` and `https://ims-na1.adobelogin.com/ims/token/v1`

## Deployment

Base bundle dependencies (on top of Sling Starter) are defined in `src/main/features/main.json`.
Additional dependencies for Redis token storage are in `src/main/features/redis.json`.

### CryptoService configuration

Because OAuth state values are encrypted/signed, `CryptoService` must be configured:

```json
"org.apache.sling.commons.crypto.internal.FilePasswordProvider~oauth": {
    "path": "secrets/encrypt/password",
    "fix.posixNewline": true
},
"org.apache.sling.commons.crypto.jasypt.internal.JasyptRandomIvGeneratorRegistrar~oauth": {
    "algorithm": "SHA1PRNG"
},
"org.apache.sling.commons.crypto.jasypt.internal.JasyptStandardPbeStringCryptoService~oauth": {
    "names": ["sling-oauth"],
    "algorithm": "PBEWITHHMACSHA512ANDAES_256"
}
```

The `sling-oauth` name is required because this bundle selects the crypto service by that name.

### Client connection configuration

Configure one (or more) client connections:

#### OIDC variant (`OidcConnectionImpl`)

You can configure OIDC either with `baseUrl` metadata discovery **or** by explicitly setting all endpoints (`authorizationEndpoint`, `tokenEndpoint`, `userInfoUrl`, `jwkSetURL`, `issuer`).

```json
"org.apache.sling.auth.oauth_client.impl.OidcConnectionImpl~provider": {
    "name": "provider",
    "baseUrl": "https://example.com",
    "clientId": "$[secret:provider/clientId]",
    "clientSecret": "$[secret:provider/clientSecret]",
    "scopes": ["openid"],
    "additionalAuthorizationParameters": ["prompt=consent"]
}
```

For SP-initiated logout, `endSessionEndpoint` can also be configured (or discovered from OIDC metadata when available).

#### OAuth variant (`OAuthConnectionImpl`)

```json
"org.apache.sling.auth.oauth_client.impl.OAuthConnectionImpl~provider": {
    "name": "provider",
    "authorizationEndpoint": "https://example.com/login/oauth/authorize",
    "tokenEndpoint": "https://example.com/login/oauth/access_token",
    "clientId": "$[secret:provider/clientId]",
    "clientSecret": "$[secret:provider/clientSecret]",
    "scopes": ["user:email"],
    "additionalAuthorizationParameters": ["allow_signup=false"]
}
```

Start the OAuth entry-point flow at:

`http://localhost:8080/system/sling/oauth/entry-point?c=provider`

### OIDC Authentication Handler configuration (optional)

If you use `OidcAuthenticationHandler` as your auth mechanism, configure at least:

```json
"org.apache.sling.auth.oauth_client.impl.OidcAuthenticationHandler~provider": {
    "path": ["/"],
    "idp": "oidc",
    "callbackUri": "http://localhost:8080/system/sling/oauth/callback",
    "defaultConnectionName": "provider",
    "pkceEnabled": true,
    "userInfoEnabled": true,
    "resource": ["https://api.example.com"],
    "requestKeyCookieMaxAgeSeconds": 300,
    "enableSPInitiatedSingleLogout": false,
    "logoutRedirectPath": "/",
    "logoutRedirectAllowedHosts": ["localhost"]
}
```

When `enableSPInitiatedSingleLogout=true`, `logoutRedirectAllowedHosts` is mandatory for open-redirect protection.

## Token storage

Tokens can be stored in JCR (under user home) or Redis.

### JCR storage

Tokens are stored at `oauth-tokens/$PROVIDER_NAME` under the user home.

```json
"org.apache.sling.auth.oauth_client.impl.JcrUserHomeOAuthTokenStore": {}
```

### Redis storage

```json
"org.apache.sling.auth.oauth_client.impl.RedisOAuthTokenStore": {
    "redisUrl": "redis://localhost:6379"
}
```

## Local development setup

### Quickstart

1. Start Keycloak with the prebuilt test realm:
   - `make keycloak-run-import`
2. Build once:
   - `mvn clean install -DskipITs`
3. Start Sling:
   - `mvn feature-launcher:start feature-launcher:stop -Dfeature-launcher.waitForInput`
4. Create OIDC connection config in Sling:
   - `make sling-create-config`

Then:

- Keycloak: `http://localhost:8081`
- Sling: `http://localhost:8080`
- OAuth entry point: `http://localhost:8080/system/sling/oauth/entry-point?c=keycloak-dev`

### Integration test notes

- Integration tests use Testcontainers (Keycloak + Redis) and require Docker.
- To skip only Keycloak-based integration tests, use `-Dit.keycloak.enabled=false`.
