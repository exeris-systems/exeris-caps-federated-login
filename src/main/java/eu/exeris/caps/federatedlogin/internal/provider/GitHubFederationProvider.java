package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.federatedlogin.api.FederationProviderAdapter;
import eu.exeris.caps.federatedlogin.api.exception.ProviderCommunicationException;
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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Built-in provider adapter for GitHub OAuth 2.0.
 *
 * <p>Supports RFC 7636 PKCE code exchange, access token resolution, and profile/email verification
 * via {@code /user} and {@code /user/emails}.
 *
 * <p>Implements the GitHub privacy-masked email policy: {@code @users.noreply.github.com} addresses
 * are permitted for identity linking and flagged with {@code is_privacy_masked: true} in profile metadata
 * to prevent dispatch of notifications to non-inbox addresses (Confirmed Design Decision 1).
 *
 * @since 0.1.0
 */
public final class GitHubFederationProvider implements FederationProviderAdapter {

    public static final String PROVIDER_ID = "github";
    public static final String ISSUER = "https://github.com";
    public static final String AUTH_ENDPOINT = "https://github.com/login/oauth/authorize";
    public static final String TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token";
    public static final String USER_ENDPOINT = "https://api.github.com/user";
    public static final String EMAILS_ENDPOINT = "https://api.github.com/user/emails";

    private final ProviderMetadata metadata;

    public GitHubFederationProvider() {
        this.metadata = new ProviderMetadata(
                PROVIDER_ID,
                ISSUER,
                AUTH_ENDPOINT,
                TOKEN_ENDPOINT,
                USER_ENDPOINT,
                List.of("read:user", "user:email"),
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
        sb.append("?client_id=").append(urlEncode(clientId))
          .append("&redirect_uri=").append(urlEncode(redirectUri))
          .append("&scope=").append(urlEncode("read:user user:email"))
          .append("&state=").append(urlEncode(state));

        if (codeChallenge != null && !codeChallenge.isBlank()) {
            sb.append("&code_challenge=").append(urlEncode(codeChallenge))
              .append("&code_challenge_method=S256");
        }

        return sb.toString();
    }

    @Override
    public FederatedIdentity processExchange(ProviderExchangeRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        if (request.httpClient() == null) {
            throw new IllegalStateException("HttpClientEngine is required for GitHub code exchange");
        }

        // 1. Exchange authorization code for access token
        StringBuilder form = new StringBuilder();
        form.append("client_id=").append(urlEncode(request.clientId()))
            .append("&client_secret=").append(urlEncode(request.clientSecret()))
            .append("&code=").append(urlEncode(request.code()))
            .append("&redirect_uri=").append(urlEncode(request.redirectUri()));

        if (request.codeVerifier() != null && !request.codeVerifier().isBlank()) {
            form.append("&code_verifier=").append(urlEncode(request.codeVerifier()));
        }

        byte[] formBytes = form.toString().getBytes(StandardCharsets.UTF_8);

        HttpRequest tokenRequest = new HttpRequest(
                HttpMethod.POST,
                "github.com:443",
                "/login/oauth/access_token",
                HttpVersion.HTTP_1_1,
                List.of(
                        new HttpHeader("Content-Type", "application/x-www-form-urlencoded"),
                        new HttpHeader("Accept", "application/json")
                ),
                HeapLoanedBuffer.of(formBytes)
        );

        HttpResponse tokenResponse;
        try {
            tokenResponse = request.httpClient().send(tokenRequest);
        } catch (Exception e) {
            throw new ProviderCommunicationException("Failed to exchange code with GitHub: " + e.getMessage(), e);
        }

        String tokenResponseBody = "";
        if (tokenResponse.body() != null) {
            try {
                tokenResponseBody = HeapLoanedBuffer.readUtf8String(tokenResponse.body());
            } finally {
                tokenResponse.body().close();
            }
        }

        if (tokenResponse.status().code() < 200 || tokenResponse.status().code() >= 300) {
            throw new ProviderCommunicationException("GitHub token exchange failed (error: " + ProviderErrors.errorCode(tokenResponseBody) + ")", tokenResponse.status().code());
        }

        Map<String, Object> tokenMap = JsonReader.parseObject(tokenResponseBody);
        if (tokenMap.containsKey("error")) {
            throw new ProviderCommunicationException("GitHub returned OAuth error: " + ProviderErrors.errorCode(tokenMap));
        }

        String accessToken = (String) tokenMap.get("access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new ProviderCommunicationException("GitHub response missing access_token", tokenResponse.status().code());
        }

        // 2. Fetch User Profile from /user
        HttpRequest userRequest = new HttpRequest(
                HttpMethod.GET,
                "api.github.com:443",
                "/user",
                HttpVersion.HTTP_1_1,
                List.of(
                        new HttpHeader("Authorization", "Bearer " + accessToken),
                        new HttpHeader("User-Agent", "Exeris-Federated-Login"),
                        new HttpHeader("Accept", "application/json")
                ),
                null
        );

        HttpResponse userResponse;
        try {
            userResponse = request.httpClient().send(userRequest);
        } catch (Exception e) {
            throw new ProviderCommunicationException("Failed to fetch GitHub user profile: " + e.getMessage(), e);
        }

        String userResponseBody = "";
        if (userResponse.body() != null) {
            try {
                userResponseBody = HeapLoanedBuffer.readUtf8String(userResponse.body());
            } finally {
                userResponse.body().close();
            }
        }

        if (userResponse.status().code() < 200 || userResponse.status().code() >= 300) {
            throw new ProviderCommunicationException("GitHub /user call failed", userResponse.status().code());
        }

        Map<String, Object> userMap = JsonReader.parseObject(userResponseBody);
        Object idObj = userMap.get("id");
        if (idObj == null || String.valueOf(idObj).isBlank()) {
            throw new ProviderCommunicationException("GitHub user profile missing 'id'");
        }
        String externalSubject = String.valueOf(idObj);
        String login = (String) userMap.get("login");
        String name = (String) userMap.get("name");
        String displayName = (name != null && !name.isBlank()) ? name : login;
        String avatarUrl = (String) userMap.get("avatar_url");
        String baseEmail = (String) userMap.get("email");

        // 3. Fetch verified email from /user/emails
        HttpRequest emailsRequest = new HttpRequest(
                HttpMethod.GET,
                "api.github.com:443",
                "/user/emails",
                HttpVersion.HTTP_1_1,
                List.of(
                        new HttpHeader("Authorization", "Bearer " + accessToken),
                        new HttpHeader("User-Agent", "Exeris-Federated-Login"),
                        new HttpHeader("Accept", "application/json")
                ),
                null
        );

        HttpResponse emailsResponse;
        try {
            emailsResponse = request.httpClient().send(emailsRequest);
        } catch (Exception e) {
            throw new ProviderCommunicationException("Failed to fetch GitHub user emails: " + e.getMessage(), e);
        }

        String emailsResponseBody = "";
        if (emailsResponse.body() != null) {
            try {
                emailsResponseBody = HeapLoanedBuffer.readUtf8String(emailsResponse.body());
            } finally {
                emailsResponse.body().close();
            }
        }

        if (emailsResponse.status().code() == 401 || emailsResponse.status().code() >= 500) {
            throw new ProviderCommunicationException("GitHub /user/emails call failed", emailsResponse.status().code());
        }

        String selectedEmail = baseEmail;
        boolean selectedEmailVerified = false;

        if (emailsResponse.status().code() >= 200 && emailsResponse.status().code() < 300 && !emailsResponseBody.isBlank()) {
            List<Object> emailsList = JsonReader.parseArray(emailsResponseBody);
            String primaryVerifiedEmail = null;
            String firstVerifiedEmail = null;
            String firstEmail = null;

            for (Object obj : emailsList) {
                if (obj instanceof Map<?, ?> emailItem) {
                    String emailVal = (String) emailItem.get("email");
                    boolean primary = Boolean.TRUE.equals(emailItem.get("primary"));
                    boolean verified = Boolean.TRUE.equals(emailItem.get("verified"));

                    if (firstEmail == null && emailVal != null) {
                        firstEmail = emailVal;
                    }
                    if (verified && firstVerifiedEmail == null && emailVal != null) {
                        firstVerifiedEmail = emailVal;
                    }
                    if (primary && verified && emailVal != null) {
                        primaryVerifiedEmail = emailVal;
                        break;
                    }
                }
            }

            if (primaryVerifiedEmail != null) {
                selectedEmail = primaryVerifiedEmail;
                selectedEmailVerified = true;
            } else if (firstVerifiedEmail != null) {
                selectedEmail = firstVerifiedEmail;
                selectedEmailVerified = true;
            } else if (firstEmail != null) {
                selectedEmail = firstEmail;
                selectedEmailVerified = false;
            }
        }

        // 4. Privacy-masked email detection (Decision 1)
        boolean isPrivacyMasked = selectedEmail != null && selectedEmail.toLowerCase(java.util.Locale.ROOT).endsWith("@users.noreply.github.com");

        Map<String, Object> attributes = new LinkedHashMap<>(userMap);
        attributes.put("is_privacy_masked", isPrivacyMasked);
        attributes.put("github_login", login != null ? login : "");

        return new FederatedIdentity(
                ISSUER,
                externalSubject,
                selectedEmail,
                selectedEmailVerified,
                displayName,
                avatarUrl,
                attributes
        );
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
