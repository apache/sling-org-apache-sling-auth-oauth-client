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
package org.apache.sling.auth.oauth_client;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.SignedJWT;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.cookie.Cookie;
import org.apache.http.cookie.CookieOrigin;
import org.apache.http.impl.cookie.DefaultCookieSpec;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.sling.auth.oauth_client.impl.JcrUserHomeOAuthTokenStore;
import org.apache.sling.auth.oauth_client.impl.OAuthConnectionImpl;
import org.apache.sling.auth.oauth_client.impl.OAuthCookieValue;
import org.apache.sling.auth.oauth_client.impl.OidcConnectionImpl;
import org.apache.sling.auth.oauth_client.impl.SlingUserInfoProcessorImpl;
import org.apache.sling.auth.oauth_client.itbundle.SupportBundle;
import org.apache.sling.commons.crypto.internal.EnvironmentVariablePasswordProvider;
import org.apache.sling.commons.crypto.jasypt.internal.JasyptRandomIvGeneratorRegistrar;
import org.apache.sling.commons.crypto.jasypt.internal.JasyptStandardPbeStringCryptoService;
import org.apache.sling.testing.clients.ClientException;
import org.apache.sling.testing.clients.SlingClient;
import org.apache.sling.testing.clients.SlingHttpResponse;
import org.apache.sling.testing.clients.osgi.OsgiConsoleClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationCodeFlowIT {

    private static final String IV_GENERATOR_REGISTRAR_PID = JasyptRandomIvGeneratorRegistrar.class.getName();
    private static final String PASSWORD_PROVIDER_PID = EnvironmentVariablePasswordProvider.class.getName();
    private static final String CRYPTO_SERVICE_PID = JasyptStandardPbeStringCryptoService.class.getName();

    private static final String OIDC_CONFIG_PID = OidcConnectionImpl.class.getName();
    private static final String OAUTH_CONFIG_PID = OAuthConnectionImpl.class.getName();
    private static final int MAX_RETRY = 10;
    private static SupportBundle supportBundle;

    private static final String OIDC_AUTHENTICATION_HANDLER_PID =
            "org.apache.sling.auth.oauth_client.impl.OidcAuthenticationHandler";
    private static final String SLING_AUTHENTICATOR_PID = "org.apache.sling.engine.impl.auth.SlingAuthenticator";
    private static final String SYNC_HANDLER_PID =
            "org.apache.jackrabbit.oak.spi.security.authentication.external.impl.DefaultSyncHandler";
    private static final String EXTERNAL_LOGIN_MODULE_FACTORY_PID =
            "org.apache.jackrabbit.oak.spi.security.authentication.external.impl.ExternalLoginModuleFactory";
    public static final String TEST_PATH = "/content/test-1";
    private KeycloakContainer keycloak;
    private SlingClient sling;
    private SlingClient slingUser;

    private int keycloakPort;

    private final List<String> configPidsToCleanup = new ArrayList<>();
    private int slingPort;

    @BeforeAll
    static void createSupportBundle(@TempDir Path tempDir) throws IOException {

        supportBundle = new SupportBundle(tempDir);
        supportBundle.generate();
    }

    @BeforeEach
    @SuppressWarnings("resource")
    void initKeycloak() {
        // support using an existing Keycloak instance by setting
        // KEYCLOAK_URL=http://localhost:24098/
        // this is most usually done in an IDE, with both Keycloak and Sling running
        String existingKeyCloakUrl = System.getenv("KEYCLOAK_URL");
        if (existingKeyCloakUrl == null) {
            keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:20.0.3")
                    .withRealmImportFile("keycloak-import/sling.json");
            keycloak.start();
            keycloakPort = keycloak.getHttpPort();
        } else {
            keycloakPort = URI.create(existingKeyCloakUrl).getPort();
        }
    }

    @BeforeEach
    void initSling() throws ClientException, InterruptedException, TimeoutException {

        slingPort = Integer.getInteger("sling.http.port", 8080);
        sling = SlingClient.Builder.create(URI.create("http://localhost:" + slingPort), "admin", "admin")
                .disableRedirectHandling()
                .build();
        slingUser = SlingClient.Builder.create(URI.create("http://localhost:" + slingPort), null, null)
                .disableRedirectHandling()
                .build();

        // ensure all previous connections are cleaned up
        sling.adaptTo(OsgiConsoleClient.class).deleteConfiguration(OIDC_CONFIG_PID + ".keycloak");

        // install the support bundle
        supportBundle.install(sling.adaptTo(OsgiConsoleClient.class));
    }

    @AfterEach
    void shutdownKeycloak() {
        if (keycloak != null) keycloak.close();
    }

    @AfterEach
    void cleanupOsgiConfigs() throws ClientException {

        // the Sling testing clients do not offer a way of listing configurations, as assigned PIDs
        // are not predictable. So instead of running deleting test configs when the test starts
        // we fall back to cleaning after, which is hopefully reliable enough
        for (String pid : configPidsToCleanup)
            sling.adaptTo(OsgiConsoleClient.class).deleteConfiguration(pid);
    }

    @AfterEach
    void uninstallBundle() throws ClientException {
        supportBundle.uninstall(sling.adaptTo(OsgiConsoleClient.class));
    }

    @Test
    void accessTokenIsPresentOnSuccessfulLogin() throws Exception {

        // configure Commons Crypto, see https://sling.apache.org/documentation/bundles/commons-crypto.html
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        IV_GENERATOR_REGISTRAR_PID + ".sling-oauth",
                        IV_GENERATOR_REGISTRAR_PID,
                        Map.of("algorithm", "SHA1PRNG")));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        PASSWORD_PROVIDER_PID + ".sling-oauth",
                        PASSWORD_PROVIDER_PID,
                        Map.of("name", "IT_ENCRYPTION_PASSWORD")));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        CRYPTO_SERVICE_PID + ".sling-oauth",
                        CRYPTO_SERVICE_PID,
                        Map.of("algorithm", "PBEWITHHMACSHA512ANDAES_256", "names", "sling-oauth")));

        // configure token store
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(JcrUserHomeOAuthTokenStore.class.getName(), null, Map.of("unused", "unused")));

        String oidcConnectionName = "keycloak";

        // configure connection to keycloak
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        OAUTH_CONFIG_PID + ".keycloak",
                        OIDC_CONFIG_PID,
                        Map.of(
                                "name", oidcConnectionName,
                                "baseUrl", "http://localhost:" + keycloakPort + "/realms/sling",
                                "clientId", "oidc-test",
                                "clientSecret", "wM2XIbxBTLJAac2rJSuHyKaoP8IWvSwJ",
                                "scopes", "openid")));

        // clean up any existing tokens
        String userPath = getUserPath(sling, sling.getUser());
        sling.deletePath(userPath + "/oauth-tokens/" + oidcConnectionName, 200);
        sling.doGet(userPath + "/oauth-tokens/" + oidcConnectionName, 404);

        // kick off oidc auth
        SlingHttpResponse entryPointResponse = sling.doGet(
                "/system/sling/oauth/entry-point", List.of(new BasicNameValuePair("c", oidcConnectionName)), 302);
        Header locationHeader = entryPointResponse.getFirstHeader("location");
        assertThat(locationHeader.getElements())
                .as("Location header value from entry-point request")
                .singleElement()
                .asString()
                .startsWith("http://localhost:" + keycloakPort);
        String locationHeaderValue = locationHeader.getValue();

        DefaultCookieSpec cookieSpec = new DefaultCookieSpec();
        List<Cookie> cookies = cookieSpec.parse(
                entryPointResponse.getFirstHeader("set-cookie"), new CookieOrigin("localhost", slingPort, "/", true));
        Optional<Cookie> oauthCookie = cookies.stream()
                .filter(c -> c.getName().equals("sling.oauth-request-key"))
                .findFirst();

        assertThat(oauthCookie).as("OAuth cookie set by entry point servlet").isPresent();
        String oauthRequestKey = oauthCookie.get().getValue();

        // load login form from keycloak
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpRequest renderLoginFormRequest =
                HttpRequest.newBuilder().uri(URI.create(locationHeaderValue)).build();
        HttpResponse<Stream<String>> renderLoginFormResponse =
                httpClient.send(renderLoginFormRequest, BodyHandlers.ofLines());
        List<String> matchingFormLines = renderLoginFormResponse
                .body()
                .filter(line -> line.contains("id=\"kc-form-login\""))
                .collect(Collectors.toList());
        assertThat(matchingFormLines).as("lines matching form id").singleElement();
        String formLine = matchingFormLines.get(0);
        int actionAttrStart = formLine.indexOf("action=\"") + "action=\"".length();
        int actionAttrEnd = formLine.indexOf('"', actionAttrStart);

        String actionAttr = formLine.substring(actionAttrStart, actionAttrEnd).replace("&amp;", "&");

        List<String> authFormRequestCookies = renderLoginFormResponse.headers().allValues("set-cookie");

        Map<String, String> authData = Map.of("username", "test", "password", "test", "credentialId", "");
        String requestBody = authData.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));

        HttpRequest.Builder authenticateRequest = HttpRequest.newBuilder(URI.create(actionAttr))
                .POST(BodyPublishers.ofString(requestBody))
                .header("content-type", "application/x-www-form-urlencoded");
        authFormRequestCookies.forEach(cookie -> authenticateRequest.header("cookie", cookie));

        HttpResponse<String> authenticateResponse =
                httpClient.send(authenticateRequest.build(), BodyHandlers.ofString());
        System.out.println(authenticateResponse.body());
        Optional<String> authResponseLocationHeader =
                authenticateResponse.headers().firstValue("location");
        assertThat(authResponseLocationHeader)
                .as("Authentication response header")
                .isPresent();

        URI redirectUri = URI.create(authResponseLocationHeader.get());
        System.out.println(redirectUri.getRawPath() + "?" + redirectUri.getRawQuery());
        List<NameValuePair> params = Arrays.stream(redirectUri.getRawQuery().split("&"))
                .map(s -> {
                    String[] parts = s.split("=");
                    return new BasicNameValuePair(parts[0], URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
                })
                .collect(Collectors.toList());

        List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader("Cookie", "sling.oauth-request-key=" + oauthRequestKey));
        sling.doGet(redirectUri.getRawPath(), params, headers, 204);

        JsonNode keycloakToken = sling.doGetJson(userPath + "/oauth-tokens/" + oidcConnectionName, 0, 200);
        String accesToken = keycloakToken.get("access_token").asText();

        // decrypt the token since it's stored encrypted in the user's home
        HttpEntity postBody = new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("token", accesToken),
                new BasicNameValuePair("cryptoServiceName", "sling-oauth")));

        System.err.println(format("Decrypting %s ...", accesToken));

        String decryptedToken =
                sling.doPost("/system/sling/decrypt", postBody, 200).getContent();
        // validate that the JWT is valid; we trust what keycloak has returned but just want to ensure that
        // the token was stored correctly
        SignedJWT.parse(decryptedToken);
    }

    @Test
    void accessTokenIsPresentOnSuccessfulAuthenticationHandlerLoginWithPkceWithNonce() throws Exception {
        accessTokenIsPresentOnSuccessfulAuthenticationHandlerLogin(true);
    }

    @Test
    void accessTokenIsPresentOnSuccessfulAuthenticationHandlerLoginWithoutPkceWithNonce() throws Exception {
        accessTokenIsPresentOnSuccessfulAuthenticationHandlerLogin(false);
    }

    void accessTokenIsPresentOnSuccessfulAuthenticationHandlerLogin(boolean withPkce) throws Exception {

        // Create a sample content with the word "Hello word"
        Map<String, String> properties = Map.of("text", "Hello World");

        // Convert Map to List<NameValuePair>
        List<NameValuePair> helloWorld = properties.entrySet().stream()
                .map(entry -> new BasicNameValuePair(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());

        // Create HttpEntity
        HttpEntity entity = new UrlEncodedFormEntity(helloWorld, StandardCharsets.UTF_8);

        // Use the doPost method with the correct parameters
        sling.doPost(TEST_PATH, entity, 200, 201);

        // configure Commons Crypto, see https://sling.apache.org/documentation/bundles/commons-crypto.html
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        IV_GENERATOR_REGISTRAR_PID + ".sling-oauth",
                        IV_GENERATOR_REGISTRAR_PID,
                        Map.of("algorithm", "SHA1PRNG")));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        PASSWORD_PROVIDER_PID + ".sling-oauth",
                        PASSWORD_PROVIDER_PID,
                        Map.of("name", "IT_ENCRYPTION_PASSWORD")));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        CRYPTO_SERVICE_PID + ".sling-oauth",
                        CRYPTO_SERVICE_PID,
                        Map.of("algorithm", "PBEWITHHMACSHA512ANDAES_256", "names", "sling-oauth")));

        // configure token store
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(JcrUserHomeOAuthTokenStore.class.getName(), null, Map.of("unused", "unused")));

        String oidcConnectionName = "keycloak";

        // configure connection to keycloak
        if (withPkce) {
            configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                    .editConfiguration(
                            OIDC_CONFIG_PID + ".keycloak",
                            OIDC_CONFIG_PID,
                            Map.of(
                                    "name",
                                    oidcConnectionName,
                                    "baseUrl",
                                    "http://localhost:" + keycloakPort + "/realms/sling",
                                    "clientId",
                                    "oidc-pkce",
                                    "pkceEnabled",
                                    "true",
                                    "scopes",
                                    new String[] {"openid"})));
        } else {
            configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                    .editConfiguration(
                            OIDC_CONFIG_PID + ".keycloak",
                            OIDC_CONFIG_PID,
                            Map.of(
                                    "name",
                                    oidcConnectionName,
                                    "baseUrl",
                                    "http://localhost:" + keycloakPort + "/realms/sling",
                                    "clientId",
                                    "oidc-test",
                                    "clientSecret",
                                    "wM2XIbxBTLJAac2rJSuHyKaoP8IWvSwJ",
                                    "scopes",
                                    new String[] {"openid"})));
        }
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        SLING_AUTHENTICATOR_PID,
                        null,
                        Map.of(
                                "auth.annonymous", true,
                                "auth.sudo.cookie", "sling.sudo",
                                "sling.auth.requirements",
                                        new String[] {"+/libs/granite/oauth/content/authorization", "+" + TEST_PATH},
                                "auth.http.realm", "Sling (Development)",
                                "auth.http", "preemptive",
                                "auth.sudo.parameter", "sudo")));

        Map<String, Object> syncHandlerConfig = Map.ofEntries(
                Map.entry("user.expirationTime", "1s"),
                Map.entry("group.expirationTime", "1s"),
                Map.entry("user.membershipExpTime", "1s"),
                Map.entry("user.propertyMapping", new String[] {
                    "profile/familyName=profile/given_name",
                    "profile/givenName=profile/name",
                    "rep:fullname=cn",
                    "profile/email=profile/email",
                    "oauth-tokens"
                }),
                Map.entry("user.pathPrefix", "oidc"),
                Map.entry("group.pathPrefix", "oidc"),
                Map.entry("user.membershipNestingDepth", "1"),
                Map.entry("handler.name", "oidc"));
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(SYNC_HANDLER_PID + ".keycloak", SYNC_HANDLER_PID, syncHandlerConfig));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        EXTERNAL_LOGIN_MODULE_FACTORY_PID + ".keycloak",
                        EXTERNAL_LOGIN_MODULE_FACTORY_PID,
                        Map.of(
                                "sync.handlerName", "oidc",
                                "idp.name", "oidc")));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        SlingUserInfoProcessorImpl.class.getName(),
                        null,
                        Map.of(
                                "storeAccessToken", "true",
                                "storeRefreshToken", "true")));

        HashMap<String, Object> authenticationHandlerConfig = new HashMap<>();
        authenticationHandlerConfig.put("path", TEST_PATH);
        authenticationHandlerConfig.put("defaultConnectionName", oidcConnectionName);
        authenticationHandlerConfig.put("defaultRedirect", TEST_PATH + ".html");
        authenticationHandlerConfig.put(
                "callbackUri", "http://localhost:" + slingPort + TEST_PATH + "/j_security_check");

        authenticationHandlerConfig.put("pkceEnabled", Boolean.toString(withPkce));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        OIDC_AUTHENTICATION_HANDLER_PID + ".keycloak",
                        OIDC_AUTHENTICATION_HANDLER_PID,
                        authenticationHandlerConfig));
        // clean up any existing tokens
        String userPath = getUserPath(sling, sling.getUser());
        sling.deletePath(userPath + "/oauth-tokens/" + oidcConnectionName, 200);
        sling.doGet(userPath + "/oauth-tokens/" + oidcConnectionName, 404);

        // kick off oidc auth
        // Create a user-agent NameValues to simulate a browser and add it to a list of headers to be sent with the
        // request
        Header userAgentHeader = new BasicHeader("User-Agent", "Mozilla/5.0");

        SlingHttpResponse entryPointResponse = null;
        Header locationHeader = null;
        // Retry the request a few times to ensure that the osgi configuration have been applied
        for (int count = 0; count < MAX_RETRY; count++) {

            entryPointResponse = slingUser.doGet(TEST_PATH + ".json", null, List.of(userAgentHeader), 302);
            locationHeader = entryPointResponse.getFirstHeader("location");
            if (locationHeader.getValue().startsWith("http://localhost:" + keycloakPort)) {
                // If the location header starts with the keycloak port, we can break out of the loop
                break;
            }
            // Otherwise, we wait for a while and retry
            Thread.sleep(100);
        }
        assertThat(locationHeader.getElements())
                .as("Location header value from entry-point request")
                .singleElement()
                .asString()
                .startsWith("http://localhost:" + keycloakPort);
        assertThat(locationHeader.getElements())
                .as("Nonce is present in the redirect")
                .singleElement()
                .asString()
                .contains("nonce");

        String locationHeaderValue = locationHeader.getValue();

        DefaultCookieSpec cookieSpec = new DefaultCookieSpec();
        ArrayList<Header> headers = new ArrayList<>(Arrays.asList(entryPointResponse.getHeaders("set-cookie")));
        ArrayList<Cookie> cookies = new ArrayList<>(headers.size());
        for (Header header : headers) {
            cookies.addAll(cookieSpec.parse(header, new CookieOrigin("localhost", slingPort, "/", true)));
        }

        // Assert that cookies are set
        assertTrue(cookies.stream()
                .filter(cookie -> OAuthCookieValue.COOKIE_NAME_REQUEST_KEY.equals(cookie.getName()))
                .findFirst()
                .isPresent());
        // load login form from keycloak
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpRequest renderLoginFormRequest =
                HttpRequest.newBuilder().uri(URI.create(locationHeaderValue)).build();
        HttpResponse<Stream<String>> renderLoginFormResponse =
                httpClient.send(renderLoginFormRequest, BodyHandlers.ofLines());
        List<String> matchingFormLines = renderLoginFormResponse
                .body()
                .filter(line -> line.contains("id=\"kc-form-login\""))
                .collect(Collectors.toList());
        assertThat(matchingFormLines).as("lines matching form id").singleElement();
        String formLine = matchingFormLines.get(0);
        int actionAttrStart = formLine.indexOf("action=\"") + "action=\"".length();
        int actionAttrEnd = formLine.indexOf('"', actionAttrStart);

        String actionAttr = formLine.substring(actionAttrStart, actionAttrEnd).replace("&amp;", "&");

        List<String> authFormRequestCookies = renderLoginFormResponse.headers().allValues("set-cookie");

        // Post credentials to keycloak
        Map<String, String> authData = Map.of("username", "test", "password", "test", "credentialId", "");
        String requestBody = authData.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));

        HttpRequest.Builder authenticateRequest = HttpRequest.newBuilder(URI.create(actionAttr))
                .POST(BodyPublishers.ofString(requestBody))
                .header("content-type", "application/x-www-form-urlencoded");
        authFormRequestCookies.forEach(cookie -> authenticateRequest.header("cookie", cookie));

        HttpResponse<String> authenticateResponse =
                httpClient.send(authenticateRequest.build(), BodyHandlers.ofString());

        // Assert response from keycloak
        Optional<String> authResponseLocationHeader =
                authenticateResponse.headers().firstValue("location");
        assertThat(authResponseLocationHeader)
                .as("Authentication response header")
                .isPresent();

        // Http Request on sling with code from keycloak. The login cookie (sling.oidcauth) will be created
        URI redirectUri = URI.create(authResponseLocationHeader.get());
        List<NameValuePair> params = Arrays.stream(redirectUri.getRawQuery().split("&"))
                .map(s -> {
                    String[] parts = s.split("=");
                    return new BasicNameValuePair(parts[0], URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
                })
                .collect(Collectors.toList());

        headers = new ArrayList<>();
        String cookieHeader = "";
        for (Cookie cookie : cookies) {
            cookieHeader += cookie.getName() + "=" + cookie.getValue() + "; ";
        }
        headers.add(new BasicHeader("Cookie", cookieHeader));
        SlingHttpResponse authenticatedResponse = slingUser.doGet(redirectUri.getRawPath(), params, headers, 302);
        Header[] cookieHeaders = authenticatedResponse.getHeaders("set-cookie");
        // retrieve the login-cookie header
        Header loginCookieHeader = Arrays.stream(cookieHeaders)
                .filter(header -> header.getValue().contains("sling.oidcauth"))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No sling.oidcauth found"));
        // Create a list of header
        headers = new ArrayList<>();
        headers.add(new BasicHeader("Cookie", loginCookieHeader.getValue()));

        // Get the page from sling with login cookie
        slingUser.doGet(TEST_PATH + ".json", new ArrayList<>(), headers, 200);
    }

    private String getUserPath(SlingClient sling, String authorizableId) throws ClientException {

        ObjectNode usersJson = (ObjectNode) sling.doGetJson("/home/users", 2, 200);
        for (Map.Entry<String, JsonNode> user : toIterable(usersJson.fields())) {
            JsonNode jsonNode = user.getValue().get("jcr:primaryType");
            if (jsonNode == null) continue;

            if (jsonNode.isTextual() && "rep:AuthorizableFolder".equals(jsonNode.asText())) {
                ObjectNode node = (ObjectNode) user.getValue();
                for (Map.Entry<String, JsonNode> user2 : toIterable(node.fields())) {
                    JsonNode primaryType = user2.getValue().get("jcr:primaryType");
                    if (primaryType != null
                            && primaryType.isTextual()
                            && primaryType.asText().equals("rep:User")) {
                        JsonNode authorizableIdProp = user2.getValue().get("rep:authorizableId");
                        if (authorizableId.equals(authorizableIdProp.asText()))
                            return "/home/users/" + user.getKey() + "/" + user2.getKey();
                    }
                }
            }
        }

        throw new IllegalArgumentException(
                String.format("Unable to locate path for user with id '%s'", authorizableId));
    }

    private static <T> Iterable<T> toIterable(Iterator<T> iterator) {
        return () -> iterator;
    }
}
