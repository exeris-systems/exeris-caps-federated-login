package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.federatedlogin.api.exception.ProviderCommunicationException;
import eu.exeris.caps.federatedlogin.api.exception.TokenValidationException;
import eu.exeris.caps.federatedlogin.api.model.FederatedIdentity;
import eu.exeris.caps.federatedlogin.api.model.ProviderExchangeRequest;
import eu.exeris.caps.federatedlogin.internal.http.HeapLoanedBuffer;
import eu.exeris.kernel.spi.exceptions.security.SecurityAuthenticationException;
import eu.exeris.kernel.spi.http.HttpClientEngine;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.memory.LoanedBuffer;
import eu.exeris.kernel.spi.security.identity.TokenValidator;
import eu.exeris.kernel.spi.security.identity.VerifiedClaims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("GoogleFederationProvider Unit Tests")
class GoogleFederationProviderTest {

    private static final class MockHttpClient implements HttpClientEngine {
        private final HttpResponse response;
        HttpRequest lastRequest;

        MockHttpClient(HttpResponse response) {
            this.response = response;
        }

        @Override public void start() {}
        @Override public HttpResponse send(HttpRequest request) {
            this.lastRequest = request;
            return response;
        }
        @Override public boolean isRunning() { return true; }
        @Override public String engineName() { return "mock"; }
        @Override public void close() {}
    }

    private static final class MockVerifiedClaims implements VerifiedClaims {
        private final String subject;
        private final String issuer;
        private final Set<String> audience;
        private final Instant expiresAt;
        private final Map<String, String> claims;

        MockVerifiedClaims(String subject, String issuer, Map<String, String> claims) {
            this(subject, issuer, Set.of("google-client-id"), Instant.now().plusSeconds(3600), claims);
        }

        MockVerifiedClaims(String subject, String issuer, Set<String> audience, Instant expiresAt, Map<String, String> claims) {
            this.subject = subject;
            this.issuer = issuer;
            this.audience = audience;
            this.expiresAt = expiresAt;
            this.claims = claims;
        }

        @Override public String subject() { return subject; }
        @Override public String issuer() { return issuer; }
        @Override public Set<String> audience() { return audience; }
        @Override public Optional<Instant> expiresAt() { return Optional.ofNullable(expiresAt); }
        @Override public Optional<String> claim(String name) { return Optional.ofNullable(claims.get(name)); }
        @Override public Set<String> stringSetClaim(String name) { return Set.of(); }
    }

    @Test
    @DisplayName("buildAuthorizationUri contains expected Google OIDC and PKCE parameters")
    void buildAuthorizationUri() {
        GoogleFederationProvider provider = new GoogleFederationProvider();
        String uri = provider.buildAuthorizationUri(
                "client-123.apps.googleusercontent.com",
                "https://app.exeris.eu/auth/callback",
                "state-456",
                "challenge-789",
                "nonce-abc"
        );

        assertThat(uri).startsWith("https://accounts.google.com/o/oauth2/v2/auth");
        assertThat(uri).contains("response_type=code");
        assertThat(uri).contains("client_id=client-123.apps.googleusercontent.com");
        assertThat(uri).contains("redirect_uri=https%3A%2F%2Fapp.exeris.eu%2Fauth%2Fcallback");
        assertThat(uri).contains("state=state-456");
        assertThat(uri).contains("code_challenge=challenge-789");
        assertThat(uri).contains("code_challenge_method=S256");
        assertThat(uri).contains("nonce=nonce-abc");
    }

    @Test
    @DisplayName("successful code exchange and verified claims extraction")
    void successfulExchange() {
        GoogleFederationProvider provider = new GoogleFederationProvider();

        String tokenJson = """
                {
                    "access_token": "ya29.mock-token",
                    "id_token": "mock.jwt.id-token",
                    "expires_in": 3599,
                    "token_type": "Bearer"
                }
                """;

        MockHttpClient client = new MockHttpClient(new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of(tokenJson)
        ));

        TokenValidator validator = buffer -> new MockVerifiedClaims(
                "google-user-12345",
                "https://accounts.google.com",
                Map.of(
                        "email", "user@exeris.eu",
                        "email_verified", "true",
                        "name", "Jan Kowalski",
                        "picture", "https://avatar.exeris.eu/pic.png",
                        "nonce", "test-nonce-123"
                )
        );

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "auth-code-123",
                "https://app.exeris.eu/callback",
                "verifier-456",
                "test-nonce-123",
                "google-client-id",
                "google-client-secret",
                client,
                validator
        );

        FederatedIdentity identity = provider.processExchange(request);

        assertThat(identity.issuer()).isEqualTo("https://accounts.google.com");
        assertThat(identity.externalSubject()).isEqualTo("google-user-12345");
        assertThat(identity.email()).isEqualTo("user@exeris.eu");
        assertThat(identity.emailVerified()).isTrue();
        assertThat(identity.displayName()).isEqualTo("Jan Kowalski");
        assertThat(identity.avatarUrl()).isEqualTo("https://avatar.exeris.eu/pic.png");

        assertThat(client.lastRequest.authority()).isEqualTo("oauth2.googleapis.com:443");
        assertThat(client.lastRequest.path()).isEqualTo("/token");
    }

    @Test
    @DisplayName("nonce mismatch raises TokenValidationException")
    void nonceMismatch() {
        GoogleFederationProvider provider = new GoogleFederationProvider();

        String tokenJson = "{\"id_token\": \"mock.jwt\"}";
        MockHttpClient client = new MockHttpClient(new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of(tokenJson)
        ));

        TokenValidator validator = buffer -> new MockVerifiedClaims(
                "sub-1",
                "https://accounts.google.com",
                Map.of("nonce", "different-nonce")
        );

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                "verifier",
                "expected-nonce",
                "google-client-id",
                "secret",
                client,
                validator
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("OIDC nonce mismatch");
    }

    @Test
    @DisplayName("token validator failure raises TokenValidationException")
    void tokenValidatorFailure() {
        GoogleFederationProvider provider = new GoogleFederationProvider();

        String tokenJson = "{\"id_token\": \"invalid.jwt\"}";
        MockHttpClient client = new MockHttpClient(new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of(tokenJson)
        ));

        TokenValidator validator = buffer -> {
            throw new SecurityAuthenticationException("JWT", "invalid_signature");
        };

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                "verifier",
                "nonce",
                "client-id",
                "secret",
                client,
                validator
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("verification failed");
    }

    @Test
    @DisplayName("Google OAuth error response raises ProviderCommunicationException")
    void googleOAuthError() {
        GoogleFederationProvider provider = new GoogleFederationProvider();

        String errorJson = "{\"error\": \"invalid_grant\", \"error_description\": \"Code has expired\"}";
        MockHttpClient client = new MockHttpClient(new HttpResponse(
                HttpStatus.BAD_REQUEST,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of(errorJson)
        ));

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                "verifier",
                "nonce",
                "client-id",
                "secret",
                client,
                buffer -> null
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(ProviderCommunicationException.class)
                .hasMessageContaining("Google token exchange failed");
    }

    @Test
    @DisplayName("audience mismatch raises TokenValidationException (prevents confused deputy)")
    void audienceMismatch() {
        GoogleFederationProvider provider = new GoogleFederationProvider();

        String tokenJson = "{\"id_token\": \"mock.jwt\"}";
        MockHttpClient client = new MockHttpClient(new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of(tokenJson)
        ));

        TokenValidator validator = buffer -> new MockVerifiedClaims(
                "sub-1",
                "https://accounts.google.com",
                Set.of("another-app-client-id"), // Different audience!
                Instant.now().plusSeconds(3600),
                Map.of()
        );

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                "verifier",
                null,
                "expected-google-client-id",
                "secret",
                client,
                validator
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("audience mismatch");
    }

    @Test
    @DisplayName("missing subject claim raises TokenValidationException")
    void missingSubjectClaim() {
        GoogleFederationProvider provider = new GoogleFederationProvider();

        String tokenJson = "{\"id_token\": \"mock.jwt\"}";
        MockHttpClient client = new MockHttpClient(new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of(tokenJson)
        ));

        TokenValidator validator = buffer -> new MockVerifiedClaims(
                "", // Blank subject!
                "https://accounts.google.com",
                Set.of("google-client-id"),
                Instant.now().plusSeconds(3600),
                Map.of("email", "test@gmail.com")
        );

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                "verifier",
                null,
                "google-client-id",
                "secret",
                client,
                validator
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("missing subject claim");
    }

    @Test
    @DisplayName("expired ID token raises TokenValidationException")
    void expiredIdToken() {
        GoogleFederationProvider provider = new GoogleFederationProvider();

        String tokenJson = "{\"id_token\": \"mock.jwt\"}";
        MockHttpClient client = new MockHttpClient(new HttpResponse(
                HttpStatus.OK,
                HttpVersion.HTTP_1_1,
                List.of(),
                HeapLoanedBuffer.of(tokenJson)
        ));

        TokenValidator validator = buffer -> new MockVerifiedClaims(
                "sub-1",
                "https://accounts.google.com",
                Set.of("google-client-id"),
                Instant.now().minusSeconds(10), // Expired!
                Map.of()
        );

        ProviderExchangeRequest request = new ProviderExchangeRequest(
                "code",
                "https://cb",
                "verifier",
                null,
                "google-client-id",
                "secret",
                client,
                validator
        );

        assertThatThrownBy(() -> provider.processExchange(request))
                .isInstanceOf(TokenValidationException.class)
                .hasMessageContaining("expired");
    }
}
