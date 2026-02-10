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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.sling.auth.oauth_client.impl.JcrUserHomeOAuthTokenStore;
import org.apache.sling.auth.oauth_client.impl.OfflineTokenValidator;
import org.apache.sling.auth.oauth_client.impl.OidcConnectionImpl;
import org.apache.sling.auth.oauth_client.impl.OnlineTokenValidator;
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

class BearerAuthenticationIT {

    private static final String IV_GENERATOR_REGISTRAR_PID = JasyptRandomIvGeneratorRegistrar.class.getName();
    private static final String PASSWORD_PROVIDER_PID = EnvironmentVariablePasswordProvider.class.getName();
    private static final String CRYPTO_SERVICE_PID = JasyptStandardPbeStringCryptoService.class.getName();

    private static final String OIDC_CONNECTION_PID = OidcConnectionImpl.class.getName();
    private static final String OFFLINE_TOKEN_VALIDATOR_PID = OfflineTokenValidator.class.getName();
    private static final String ONLINE_TOKEN_VALIDATOR_PID = OnlineTokenValidator.class.getName();
    private static final int MAX_RETRY = 10;
    private static SupportBundle supportBundle;

    private static final String BEARER_AUTHENTICATION_HANDLER_PID =
            "org.apache.sling.auth.oauth_client.impl.OidcBearerAuthenticationHandler";
    private static final String SLING_AUTHENTICATOR_PID = "org.apache.sling.engine.impl.auth.SlingAuthenticator";
    private static final String SYNC_HANDLER_PID =
            "org.apache.jackrabbit.oak.spi.security.authentication.external.impl.DefaultSyncHandler";
    private static final String EXTERNAL_LOGIN_MODULE_FACTORY_PID =
            "org.apache.jackrabbit.oak.spi.security.authentication.external.impl.ExternalLoginModuleFactory";
    public static final String TEST_PATH = "/content/bearer-test";
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
            keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.4")
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
        sling.adaptTo(OsgiConsoleClient.class).deleteConfiguration(OIDC_CONNECTION_PID + ".keycloak");

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
    void bearerTokenAuthenticationWithOfflineValidation() throws Exception {
        createTestContent("Bearer Auth Test");
        String oidcConnectionName = configureCommonServices();
        configureBearerAuthHandler(oidcConnectionName, false, false);

        String accessToken = obtainAccessToken("test", "test");

        // Verify that we can't access without a token
        SlingHttpResponse unauthorizedResponse = slingUser.doGet(TEST_PATH + ".json", 401);
        assertThat(unauthorizedResponse.getStatusLine().getStatusCode())
                .as("Access without token should be unauthorized")
                .isEqualTo(401);

        // Access the protected resource with bearer token
        SlingHttpResponse authorizedResponse = accessProtectedResource(accessToken);
        assertThat(authorizedResponse.getStatusLine().getStatusCode())
                .as("Access with valid bearer token should succeed")
                .isEqualTo(200);

        // Verify the response content
        String responseContent = authorizedResponse.getContent();
        assertThat(responseContent).as("Response should contain test content").contains("Bearer Auth Test");

        // Test with invalid token
        Header invalidAuthHeader = new BasicHeader("Authorization", "Bearer invalid_token_12345");
        SlingHttpResponse invalidTokenResponse =
                slingUser.doGet(TEST_PATH + ".json", null, List.of(invalidAuthHeader), 401);
        assertThat(invalidTokenResponse.getStatusLine().getStatusCode())
                .as("Access with invalid token should be unauthorized")
                .isEqualTo(401);
    }

    @Test
    void bearerTokenAuthenticationWithOnlineValidation() throws Exception {
        createTestContent("Bearer Auth Online Test");
        String oidcConnectionName = configureCommonServices();
        configureBearerAuthHandler(oidcConnectionName, true, false);

        String accessToken = obtainAccessToken("test", "test");

        SlingHttpResponse authorizedResponse = accessProtectedResource(accessToken);
        assertThat(authorizedResponse.getStatusLine().getStatusCode())
                .as("Access with valid bearer token (online validation) should succeed")
                .isEqualTo(200);
    }

    @Test
    void bearerTokenAuthenticationWithUserInfoFetch() throws Exception {
        createTestContent("Bearer Auth UserInfo Test");
        String oidcConnectionName = configureCommonServices();
        configureBearerAuthHandler(oidcConnectionName, false, true);

        String accessToken = obtainAccessToken("test", "test");

        SlingHttpResponse authorizedResponse = accessProtectedResource(accessToken);
        assertThat(authorizedResponse.getStatusLine().getStatusCode())
                .as("Access with valid bearer token (with UserInfo fetch) should succeed")
                .isEqualTo(200);
    }

    /**
     * Creates a test content node at TEST_PATH.
     */
    private void createTestContent(String text) throws Exception {
        Map<String, String> properties = Map.of("text", text);
        List<NameValuePair> testContent = properties.entrySet().stream()
                .map(entry -> new BasicNameValuePair(entry.getKey(), entry.getValue()))
                .collect(Collectors.toList());
        HttpEntity entity = new UrlEncodedFormEntity(testContent, StandardCharsets.UTF_8);
        sling.doPost(TEST_PATH, entity, 200, 201);
    }

    /**
     * Configures all common OSGi services: Commons Crypto, Token Store, OIDC Connection,
     * Sling Authenticator, Sync Handler, External Login Module, and UserInfo Processor.
     *
     * @return the OIDC connection name
     */
    private String configureCommonServices() throws Exception {
        // Configure Commons Crypto
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

        // Configure token store
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(JcrUserHomeOAuthTokenStore.class.getName(), null, Map.of("unused", "unused")));

        String oidcConnectionName = "keycloak";

        // Configure connection to keycloak
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        OIDC_CONNECTION_PID + ".keycloak",
                        OIDC_CONNECTION_PID,
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
                                new String[] {"openid", "profile", "email"},
                                "requiredAudiences",
                                new String[] {"oidc-test", "account"})));

        // Configure Sling Authenticator to protect the test path
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        SLING_AUTHENTICATOR_PID,
                        null,
                        Map.of(
                                "auth.annonymous", true,
                                "auth.sudo.cookie", "sling.sudo",
                                "sling.auth.requirements", new String[] {"+" + TEST_PATH},
                                "auth.http.realm", "Sling (Development)",
                                "auth.http", "preemptive",
                                "auth.sudo.parameter", "sudo")));

        // Configure sync handler
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
                                "idp.name", "oidc-idp")));

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        SlingUserInfoProcessorImpl.class.getName(),
                        null,
                        Map.of(
                                "storeAccessToken", "true",
                                "storeRefreshToken", "true",
                                "connection", oidcConnectionName)));

        // Configure Offline Token Validator with claims validation
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        OFFLINE_TOKEN_VALIDATOR_PID + ".keycloak",
                        OFFLINE_TOKEN_VALIDATOR_PID,
                        Map.of(
                                "name",
                                "offline-validator",
                                "acceptedClientIds",
                                new String[] {"oidc-test", "account"},
                                "requiredScopes",
                                new String[] {"openid"},
                                "requiredAudiences",
                                new String[] {"oidc-test", "account", "account-console"})));

        // Configure Online Token Validator with claims validation
        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        ONLINE_TOKEN_VALIDATOR_PID + ".keycloak",
                        ONLINE_TOKEN_VALIDATOR_PID,
                        Map.of(
                                "name",
                                "online-validator",
                                "acceptedClientIds",
                                new String[] {"oidc-test", "account"},
                                "requiredScopes",
                                new String[] {"openid"},
                                "requiredAudiences",
                                new String[] {"oidc-test", "account", "account-console"})));

        return oidcConnectionName;
    }

    /**
     * Configures the Bearer Authentication Handler with specified options.
     *
     * @param oidcConnectionName the OIDC connection name
     * @param useOnlineValidation whether to use online validation (introspection)
     * @param fetchUserInfo whether to fetch user info from the UserInfo endpoint
     */
    private void configureBearerAuthHandler(
            String oidcConnectionName, boolean useOnlineValidation, boolean fetchUserInfo) throws Exception {
        String validatorName = useOnlineValidation ? "online-validator" : "offline-validator";

        configPidsToCleanup.add(sling.adaptTo(OsgiConsoleClient.class)
                .editConfiguration(
                        BEARER_AUTHENTICATION_HANDLER_PID + ".keycloak",
                        BEARER_AUTHENTICATION_HANDLER_PID,
                        Map.of(
                                "path",
                                TEST_PATH,
                                "connectionName",
                                oidcConnectionName,
                                "validatorName",
                                validatorName,
                                "fetchUserInfo",
                                Boolean.toString(fetchUserInfo),
                                "idp",
                                "oidc-idp")));

        // Wait for configurations to apply
        Thread.sleep(1000);
    }

    /**
     * Accesses the protected resource with the given access token, retrying if needed for configuration propagation.
     */
    private SlingHttpResponse accessProtectedResource(String accessToken) throws Exception {
        Header authorizationHeader = new BasicHeader("Authorization", "Bearer " + accessToken);
        SlingHttpResponse authorizedResponse = null;

        // Retry to allow time for OSGi configurations to propagate
        for (int count = 0; count < MAX_RETRY; count++) {
            try {
                authorizedResponse = slingUser.doGet(TEST_PATH + ".json", null, List.of(authorizationHeader), 200);
                break;
            } catch (Exception e) {
                if (count == MAX_RETRY - 1) throw e;
                Thread.sleep(200);
            }
        }

        return authorizedResponse;
    }

    /**
     * Obtains an access token from Keycloak using the Resource Owner Password Credentials grant (direct grant).
     */
    private String obtainAccessToken(String username, String password) throws Exception {
        HttpClient httpClient = HttpClient.newHttpClient();

        String tokenEndpoint = format("http://localhost:%d/realms/sling/protocol/openid-connect/token", keycloakPort);

        String credentials = "oidc-test:wM2XIbxBTLJAac2rJSuHyKaoP8IWvSwJ";
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        String requestBody = format(
                "grant_type=password&username=%s&password=%s&scope=openid%%20profile%%20email", username, password);

        HttpRequest tokenRequest = HttpRequest.newBuilder()
                .uri(URI.create(tokenEndpoint))
                .header("Authorization", "Basic " + encodedCredentials)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> tokenResponse = httpClient.send(tokenRequest, BodyHandlers.ofString());

        assertThat(tokenResponse.statusCode())
                .as("Token endpoint should return 200")
                .isEqualTo(200);

        // Parse JSON response to extract access_token
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        JsonNode jsonResponse = mapper.readTree(tokenResponse.body());
        String accessToken = jsonResponse.get("access_token").asText();

        assertThat(accessToken).as("Access token should not be null").isNotNull();

        return accessToken;
    }
}
