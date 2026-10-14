package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.federatedlogin.api.exception.ProviderCommunicationException;
import eu.exeris.caps.federatedlogin.api.model.FederatedIdentity;
import eu.exeris.caps.federatedlogin.api.model.ProviderExchangeRequest;
import eu.exeris.caps.federatedlogin.internal.http.HeapLoanedBuffer;
import eu.exeris.kernel.spi.http.HttpClientEngine;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("GitHubFederationProvider Unit Tests")
class GitHubFederationProviderTest {

    private static final class PathRoutingHttpClient implements HttpClientEngine {
        private final Map<String, HttpResponse> routes = new HashMap<>();
        final List<HttpRequest> recordedRequests = new ArrayList<>();

        void on(String path, HttpResponse response) {
            routes.put(path, response);
        }

        @Override public void start() {}
        @Override
        public HttpResponse send(HttpRequest request) {
            recordedRequests.add(request);
            HttpResponse response = routes.get(request.path());
            if (response == null) {
                throw new IllegalStateException("Unexpected path: " + request.path());
            }
            return response;
        }
        @Override public boolean isRunning() { return true; }
        @Override public String engineName() { return "routing-mock"; }
        @Override public void close() {}
    }

    @Test
    @DisplayName("buildAuthorizationUri contains expected GitHub parameters")
    void buildAuthorizationUri() {
        GitHubFederationProvider provider = new GitHubFederationProvider();
        String uri = provider.buildAuthorizationUri(
                "gh-client-123",
                "https://app.exeris.eu/auth/github/callback",
                "gh-state-456",
                "challenge-s256",
                null
        );

        assertThat(uri).startsWith("https://github.com/login/oauth/authorize");
        assertThat(uri).contains("client_id=gh-client-123");
        assertThat(uri).contains("redirect_uri=https%3A%2F%2Fapp.exeris.eu%2Fauth%2Fgithub%2Fcallback");
        assertThat(uri).contains("scope=read%3Auser+user%3Aemail");
        assertThat(uri).contains("state=gh-state-456");
        assertThat(uri).contains("code_challenge=challenge-s256");
        assertThat(uri).contains("code_challenge_method=S256");
    }

    @Test
    @DisplayName("successful exchange with standard verified primary email")
    void successfulExchangeWithStandardEmail() {
        GitHubFederationProvider provider = new GitHubFederationProvider();
        PathRoutingHttpClient client = new PathRoutingHttpClient();

        client.on("/login/oauth/access_token", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"access_token\": \"gho_testToken123\", \"token_type\": \"bearer\"}")
        ));

        client.on("/user", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("""
                        {
                            "id": 987654,
                            "login": "octocat",
                            "name": "Mona Lisa",
                            "avatar_url": "https://avatars.githubusercontent.com/u/987654",
                            "email": "octocat@github.com"
                        }
                        """)
        ));

        client.on("/user/emails", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("""
                        [
                            {"email": "secondary@example.com", "primary": false, "verified": true},
                            {"email": "mona@github.com", "primary": true, "verified": true}
                        ]
                        """)
        ));

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code-123",
                "https://app.exeris.eu/auth/github/callback",
                "verifier-pkce",
                null,
                "gh-client-id",
                "gh-client-secret",
                client,
                null
        );

        FederatedIdentity identity = provider.processExchange(request);

        assertThat(identity.issuer()).isEqualTo("https://github.com");
        assertThat(identity.externalSubject()).isEqualTo("987654");
        assertThat(identity.email()).isEqualTo("mona@github.com");
        assertThat(identity.emailVerified()).isTrue();
        assertThat(identity.displayName()).isEqualTo("Mona Lisa");
        assertThat(identity.avatarUrl()).isEqualTo("https://avatars.githubusercontent.com/u/987654");
        assertThat(identity.rawAttributes().get("is_privacy_masked")).isEqualTo(false);
    }

    @Test
    @DisplayName("Confirmed Design Decision 1: GitHub privacy-masked email (@users.noreply.github.com) sets is_privacy_masked: true")
    void privacyMaskedEmailPolicy() {
        GitHubFederationProvider provider = new GitHubFederationProvider();
        PathRoutingHttpClient client = new PathRoutingHttpClient();

        client.on("/login/oauth/access_token", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"access_token\": \"gho_maskedToken\"}")
        ));

        client.on("/user", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("""
                        {
                            "id": 112233,
                            "login": "maskeddev",
                            "name": "Anonymous Dev"
                        }
                        """)
        ));

        client.on("/user/emails", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("""
                        [
                            {"email": "112233+maskeddev@users.noreply.github.com", "primary": true, "verified": true}
                        ]
                        """)
        ));

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                "verifier",
                null,
                "client-id",
                "secret",
                client,
                null
        );

        FederatedIdentity identity = provider.processExchange(request);

        assertThat(identity.email()).isEqualTo("112233+maskeddev@users.noreply.github.com");
        assertThat(identity.emailVerified()).isTrue();
        assertThat(identity.rawAttributes().get("is_privacy_masked")).isEqualTo(true);
    }

    @Test
    @DisplayName("GitHub error response during token exchange raises ProviderCommunicationException")
    void tokenExchangeError() {
        GitHubFederationProvider provider = new GitHubFederationProvider();
        PathRoutingHttpClient client = new PathRoutingHttpClient();

        client.on("/login/oauth/access_token", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"error\": \"bad_verification_code\", \"error_description\": \"The code passed is incorrect or expired.\"}")
        ));

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "bad-code",
                "https://cb",
                null,
                null,
                "id",
                "sec",
                client,
                null
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(ProviderCommunicationException.class)
                .hasMessageContaining("bad_verification_code");
    }

    @Test
    @DisplayName("GitHub /user/emails server error raises ProviderCommunicationException")
    void userEmailsServerError() {
        GitHubFederationProvider provider = new GitHubFederationProvider();
        PathRoutingHttpClient client = new PathRoutingHttpClient();

        client.on("/login/oauth/access_token", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"access_token\": \"gho_testToken123\"}")
        ));

        client.on("/user", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"id\": 12345, \"login\": \"testuser\"}")
        ));

        client.on("/user/emails", new HttpResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"message\": \"Internal Server Error\"}")
        ));

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                null,
                null,
                "id",
                "sec",
                client,
                null
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(ProviderCommunicationException.class)
                .hasMessageContaining("/user/emails call failed");
    }

    @Test
    @DisplayName("GitHub profile missing id raises ProviderCommunicationException")
    void missingProfileId() {
        GitHubFederationProvider provider = new GitHubFederationProvider();
        PathRoutingHttpClient client = new PathRoutingHttpClient();

        client.on("/login/oauth/access_token", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"access_token\": \"gho_testToken123\"}")
        ));

        client.on("/user", new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of("{\"login\": \"noid\"}") // Missing id!
        ));

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                null,
                null,
                "id",
                "sec",
                client,
                null
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(ProviderCommunicationException.class)
                .hasMessageContaining("missing 'id'");
    }

    @Test
    @DisplayName("error messages carry the status and OAuth error code, never the response body")
    void errorsDoNotEmbedProviderBody() {
        GitHubFederationProvider provider = new GitHubFederationProvider();
        ProviderExchangeRequest request = new ProviderExchangeRequest("code", "https://cb", "verifier", null,
                "client", "secret", null, null);

        PathRoutingHttpClient rejected = new PathRoutingHttpClient();
        rejected.on("/login/oauth/access_token", new HttpResponse(HttpStatus.BAD_REQUEST, HttpVersion.HTTP_1_1, List.of(),
                HeapLoanedBuffer.of("{\"error\": \"bad_verification_code\", \"access_token\": \"gho_SECRET\"}")));
        assertThatThrownBy(() -> provider.processExchange(withClient(request, rejected)))
                .isInstanceOf(ProviderCommunicationException.class)
                .hasMessageContaining("bad_verification_code").hasMessageNotContaining("SECRET");

        PathRoutingHttpClient noToken = new PathRoutingHttpClient();
        noToken.on("/login/oauth/access_token", new HttpResponse(HttpStatus.OK, HttpVersion.HTTP_1_1, List.of(),
                HeapLoanedBuffer.of("{\"refresh_token\": \"ghr_SECRET\"}")));
        assertThatThrownBy(() -> provider.processExchange(withClient(request, noToken)))
                .isInstanceOf(ProviderCommunicationException.class)
                .hasMessageContaining("missing access_token").hasMessageNotContaining("SECRET");

        PathRoutingHttpClient userFails = new PathRoutingHttpClient();
        userFails.on("/login/oauth/access_token", new HttpResponse(HttpStatus.OK, HttpVersion.HTTP_1_1, List.of(),
                HeapLoanedBuffer.of("{\"access_token\": \"gho_SECRET\"}")));
        userFails.on("/user", new HttpResponse(HttpStatus.UNAUTHORIZED, HttpVersion.HTTP_1_1, List.of(),
                HeapLoanedBuffer.of("{\"message\": \"Bad credentials gho_SECRET\"}")));
        assertThatThrownBy(() -> provider.processExchange(withClient(request, userFails)))
                .isInstanceOf(ProviderCommunicationException.class)
                .hasMessageContaining("401").hasMessageNotContaining("SECRET");
    }

    private static ProviderExchangeRequest withClient(ProviderExchangeRequest r, HttpClientEngine client) {
        return new ProviderExchangeRequest(r.code(), r.redirectUri(), r.codeVerifier(), r.nonce(), r.clientId(), r.clientSecret(), client, null);
    }
}
