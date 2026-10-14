package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.federatedlogin.api.FederationProviderAdapter;
import eu.exeris.caps.federatedlogin.api.exception.ProviderCommunicationException;
import eu.exeris.caps.federatedlogin.api.exception.TokenValidationException;
import eu.exeris.caps.federatedlogin.api.model.FederatedIdentity;
import eu.exeris.caps.federatedlogin.api.model.ProviderExchangeRequest;
import eu.exeris.caps.federatedlogin.api.model.ProviderMetadata;
import eu.exeris.caps.federatedlogin.internal.http.HeapLoanedBuffer;
import eu.exeris.caps.federatedlogin.internal.http.JsonReader;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.security.identity.VerifiedClaims;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Built-in provider adapter for Google OpenID Connect (OIDC).
 *
 * <p>Uses RFC 7636 PKCE S256 for code exchange and verifies the OIDC {@code id_token}
 * using the kernel {@link eu.exeris.kernel.spi.security.identity.TokenValidator} SPI (ADR-099, Obligation 6).
 *
 * @since 0.1.0
 */
public final class GoogleFederationProvider implements FederationProviderAdapter {

    public static final String PROVIDER_ID = "google";
    public static final String ISSUER = "https://accounts.google.com";
    public static final String AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
    public static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

    private final ProviderMetadata metadata;

    public GoogleFederationProvider() {
        this.metadata = new ProviderMetadata(
                PROVIDER_ID,
                ISSUER,
                AUTH_ENDPOINT,
                TOKEN_ENDPOINT,
                null,
                List.of("openid", "email", "profile"),
                true
        );
    }

    @Override
    public ProviderMetadata metadata() {
        return metadata;
    }

    @Override
    public String buildAuthorizationUri(String clientId, String redirectUri, String state, String codeChallenge, String nonce) {
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(state, "state must not be null");

        StringBuilder sb = new StringBuilder(AUTH_ENDPOINT);
        sb.append("?response_type=code")
          .append("&client_id=").append(urlEncode(clientId))
          .append("&redirect_uri=").append(urlEncode(redirectUri))
          .append("&scope=").append(urlEncode("openid email profile"))
          .append("&state=").append(urlEncode(state));

        if (codeChallenge != null && !codeChallenge.isBlank()) {
            sb.append("&code_challenge=").append(urlEncode(codeChallenge))
              .append("&code_challenge_method=S256");
        }

        if (nonce != null && !nonce.isBlank()) {
            sb.append("&nonce=").append(urlEncode(nonce));
        }

        return sb.toString();
    }

    @Override
    public FederatedIdentity processExchange(ProviderExchangeRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        if (request.httpClient() == null) {
            throw new IllegalStateException("HttpClientEngine is required for Google code exchange");
        }
        if (request.tokenValidator() == null) {
            throw new IllegalStateException("TokenValidator is required for Google ID token verification");
        }

        // 1. Build form-urlencoded token request body
        StringBuilder form = new StringBuilder();
        form.append("code=").append(urlEncode(request.code()))
            .append("&client_id=").append(urlEncode(request.clientId()))
            .append("&client_secret=").append(urlEncode(request.clientSecret()))
            .append("&redirect_uri=").append(urlEncode(request.redirectUri()))
            .append("&grant_type=authorization_code");

        if (request.codeVerifier() != null && !request.codeVerifier().isBlank()) {
            form.append("&code_verifier=").append(urlEncode(request.codeVerifier()));
        }

        byte[] formBytes = form.toString().getBytes(StandardCharsets.UTF_8);

        HttpRequest httpRequest = new HttpRequest(
                HttpMethod.POST,
                "oauth2.googleapis.com:443",
                "/token",
                HttpVersion.HTTP_1_1,
                List.of(
                        new HttpHeader("Content-Type", "application/x-www-form-urlencoded"),
                        new HttpHeader("Accept", "application/json")
                ),
                HeapLoanedBuffer.of(formBytes)
        );

        HttpResponse httpResponse;
        try {
            httpResponse = request.httpClient().send(httpRequest);
        } catch (Exception e) {
            throw new ProviderCommunicationException("Failed to send token exchange request to Google: " + e.getMessage(), e);
        }

        String responseBody = "";
        if (httpResponse.body() != null) {
            try {
                responseBody = HeapLoanedBuffer.readUtf8String(httpResponse.body());
            } finally {
                httpResponse.body().close();
            }
        }

        if (httpResponse.status().code() < 200 || httpResponse.status().code() >= 300) {
            throw new ProviderCommunicationException("Google token exchange failed (error: " + ProviderErrors.errorCode(responseBody) + ")", httpResponse.status().code());
        }

        Map<String, Object> tokenPayload = JsonReader.parseObject(responseBody);
        if (tokenPayload.containsKey("error")) {
            throw new ProviderCommunicationException("Google returned OAuth error: " + ProviderErrors.errorCode(tokenPayload));
        }

        String idToken = (String) tokenPayload.get("id_token");
        if (idToken == null || idToken.isBlank()) {
            throw new ProviderCommunicationException("Google token response missing id_token", httpResponse.status().code());
        }

        // 2. Cryptographic ID Token validation via TokenValidator
        VerifiedClaims claims;
        try {
            claims = request.tokenValidator().validate(HeapLoanedBuffer.of(idToken));
        } catch (Exception e) {
            throw new TokenValidationException("Google ID token signature/claims verification failed", e);
        }

        // 3. Verify audience (OIDC Core 1.0 § 3.1.3.7 - prevent Confused Deputy)
        java.util.Set<String> audience = claims.audience();
        if (audience == null || !audience.contains(request.clientId())) {
            throw new TokenValidationException("Google ID token audience mismatch");
        }

        // OIDC Core 1.0 § 3.1.3.7: with several audiences the authorized party must be this client
        if (audience.size() > 1 && !claims.claim("azp").map(request.clientId()::equals).orElse(false)) {
            throw new TokenValidationException("Google ID token authorized party mismatch");
        }

        // 4. Verify issuer
        String tokenIssuer = claims.issuer();
        if (!ISSUER.equals(tokenIssuer) && !"accounts.google.com".equals(tokenIssuer)) {
            throw new TokenValidationException("Google ID token issuer mismatch");
        }

        // 5. Assert nonce
        if (request.nonce() != null && !request.nonce().isBlank()) {
            Optional<String> tokenNonce = claims.claim("nonce");
            if (tokenNonce.isEmpty() || !request.nonce().equals(tokenNonce.get())) {
                throw new TokenValidationException("OIDC nonce mismatch");
            }
        }

        // 6. Assert token not expired
        if (claims.expiresAt().isEmpty()) {
            throw new TokenValidationException("Google ID token has no exp claim");
        }
        if (!claims.expiresAt().get().isAfter(java.time.Instant.now())) {
            throw new TokenValidationException("Google ID token is expired");
        }

        String subject = claims.subject();
        if (subject == null || subject.isBlank()) {
            throw new TokenValidationException("Google ID token missing subject claim");
        }
        String email = claims.claim("email").orElse(null);
        boolean emailVerified = claims.claim("email_verified")
                .map(Boolean::parseBoolean)
                .orElse(false);
        String name = claims.claim("name").orElse(null);
        String picture = claims.claim("picture").orElse(null);

        return new FederatedIdentity(
                ISSUER,
                subject,
                email,
                emailVerified,
                name,
                picture,
                ProviderErrors.withoutCredentials(tokenPayload)
        );
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
