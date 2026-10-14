package eu.exeris.caps.federatedlogin.internal.flow;

import eu.exeris.caps.federatedlogin.api.exception.FederatedLoginConfigurationException;
import eu.exeris.caps.federatedlogin.api.exception.InvalidRedirectException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The redirect targets a login flow may use.
 *
 * <p>A {@code redirectUri} must equal, per provider, one configured URI in scheme, host, port and path;
 * it carries no userinfo, query or fragment. A {@code targetPostLoginUrl} must be a relative path that
 * stays on the current origin, or an absolute URL on a configured origin. An empty policy allows nothing.
 *
 * <p>Configuration: {@value #ENV_REDIRECT_URIS} is {@code <provider>=<uri>[,<uri>...][;<provider>=...]}
 * and {@value #ENV_POST_LOGIN_ORIGINS} is {@code <origin>[,<origin>...]}. Plain {@code http} is accepted
 * only for loopback hosts.
 *
 * @since 0.1.0
 */
public final class RedirectPolicy {

    public static final String ENV_REDIRECT_URIS = "EXERIS_FEDERATED_LOGIN_REDIRECT_URIS";
    public static final String ENV_POST_LOGIN_ORIGINS = "EXERIS_FEDERATED_LOGIN_POST_LOGIN_ORIGINS";

    private static final RedirectPolicy DENY_ALL = new RedirectPolicy(Map.of(), Set.of());

    private final Map<String, Set<String>> redirectUris;
    private final Set<String> origins;

    private RedirectPolicy(Map<String, Set<String>> redirectUris, Set<String> origins) {
        this.redirectUris = redirectUris;
        this.origins = origins;
    }

    /**
     * Returns the policy that rejects every redirect URI and every absolute post-login URL.
     *
     * @return a policy that rejects every redirect URI and every absolute post-login URL
     */
    public static RedirectPolicy denyAll() {
        return DENY_ALL;
    }

    /**
     * Builds a policy from explicit lists.
     *
     * @throws FederatedLoginConfigurationException if an entry is not an acceptable URI or origin
     */
    public static RedirectPolicy of(Map<String, ? extends Collection<String>> redirectUrisByProvider,
                                    Collection<String> postLoginOrigins) {
        Map<String, Set<String>> uris = new LinkedHashMap<>();
        redirectUrisByProvider.forEach((provider, list) -> {
            Set<String> normalized = new HashSet<>();
            for (String uri : list) {
                normalized.add(configured(ENV_REDIRECT_URIS, uri, true));
            }
            uris.put(provider, Set.copyOf(normalized));
        });
        Set<String> normalizedOrigins = new HashSet<>();
        for (String origin : postLoginOrigins) {
            normalizedOrigins.add(configured(ENV_POST_LOGIN_ORIGINS, origin, false));
        }
        return new RedirectPolicy(Map.copyOf(uris), Set.copyOf(normalizedOrigins));
    }

    /**
     * Reads the policy from the environment. Absent keys yield an empty list for that part.
     */
    public static RedirectPolicy fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment must not be null");
        Map<String, Set<String>> uris = new LinkedHashMap<>();
        String spec = environment.get(ENV_REDIRECT_URIS);
        if (spec != null && !spec.isBlank()) {
            for (String part : spec.trim().split(";")) {
                String entry = part.trim();
                if (entry.isEmpty()) {
                    continue;
                }
                int eq = entry.indexOf('=');
                if (eq <= 0) {
                    throw new FederatedLoginConfigurationException(ENV_REDIRECT_URIS, "an entry is not <provider>=<uri>[,<uri>...]");
                }
                String provider = entry.substring(0, eq).trim();
                Set<String> list = uris.computeIfAbsent(provider, k -> new HashSet<>());
                for (String uri : entry.substring(eq + 1).split(",")) {
                    list.add(configured(ENV_REDIRECT_URIS, uri.trim(), true));
                }
            }
        }
        Set<String> origins = new HashSet<>();
        String originSpec = environment.get(ENV_POST_LOGIN_ORIGINS);
        if (originSpec != null && !originSpec.isBlank()) {
            for (String origin : originSpec.trim().split(",")) {
                origins.add(configured(ENV_POST_LOGIN_ORIGINS, origin.trim(), false));
            }
        }
        Map<String, Set<String>> frozen = new LinkedHashMap<>();
        uris.forEach((k, v) -> frozen.put(k, Set.copyOf(v)));
        return new RedirectPolicy(Map.copyOf(frozen), Set.copyOf(origins));
    }

    /**
     * Requires {@code redirectUri} to exactly match a URI configured for {@code providerId}.
     *
     * @throws InvalidRedirectException unless {@code redirectUri} exactly matches a URI configured for
     *                                  {@code providerId}
     */
    public void requireRegisteredRedirectUri(String providerId, String redirectUri) {
        Set<String> allowed = redirectUris.get(providerId);
        String candidate = parse(redirectUri);
        if (allowed == null || candidate == null || !allowed.contains(candidate)) {
            throw new InvalidRedirectException("redirectUri is not registered for provider '" + providerId + "'");
        }
    }

    /**
     * Accepts a {@code null}, relative-path or configured-origin destination and rejects anything else.
     *
     * @param targetPostLoginUrl the destination after login; {@code null} means none
     * @throws InvalidRedirectException unless it is {@code null}, a safe relative path, or on a
     *                                  configured origin
     */
    public void requireSafePostLoginUrl(String targetPostLoginUrl) {
        if (targetPostLoginUrl == null) {
            return;
        }
        if (isSafeRelativePath(targetPostLoginUrl)) {
            return;
        }
        String origin = originOf(targetPostLoginUrl);
        if (origin == null || !origins.contains(origin)) {
            throw new InvalidRedirectException("targetPostLoginUrl is neither a relative path nor on an allowed origin");
        }
    }

    static boolean isSafeRelativePath(String value) {
        if (value.length() < 1 || value.charAt(0) != '/' || !plainAscii(value)) {
            return false;
        }
        if (value.length() > 1 && (value.charAt(1) == '/' || value.charAt(1) == '\\')) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        return !lower.contains("%2f") && !lower.contains("%5c");
    }

    private static boolean plainAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x20 || c >= 0x7f || c == '\\') {
                return false;
            }
        }
        return true;
    }

    private static String originOf(String url) {
        URI uri = strictAbsolute(url);
        return uri == null ? null : origin(uri);
    }

    private static String configured(String key, String value, boolean withPath) {
        String normalized = withPath ? parse(value) : originOnly(value);
        if (normalized == null) {
            throw new FederatedLoginConfigurationException(key, "an entry is not an acceptable "
                    + (withPath ? "absolute redirect URI" : "origin")
                    + " (https, or http on loopback; no userinfo, query or fragment)");
        }
        return normalized;
    }

    private static String originOnly(String value) {
        URI uri = strictAbsolute(value);
        if (uri == null || !(uri.getRawPath() == null || uri.getRawPath().isEmpty() || "/".equals(uri.getRawPath()))
                || uri.getRawQuery() != null || uri.getRawFragment() != null || !schemeAllowed(uri)) {
            return null;
        }
        return origin(uri);
    }

    /** Normalised {@code scheme://host:port/path}, or {@code null} if the value is not acceptable. */
    private static String parse(String value) {
        URI uri = strictAbsolute(value);
        if (uri == null || uri.getRawQuery() != null || uri.getRawFragment() != null || !schemeAllowed(uri)) {
            return null;
        }
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        return origin(uri) + path;
    }

    private static boolean schemeAllowed(URI uri) {
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if ("https".equals(scheme)) {
            return true;
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        return "http".equals(scheme) && ("localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host));
    }

    private static URI strictAbsolute(String value) {
        if (value == null || value.isEmpty() || !plainAscii(value)) {
            return null;
        }
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            return null;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !("http".equals(scheme.toLowerCase(Locale.ROOT)) || "https".equals(scheme.toLowerCase(Locale.ROOT)))
                || uri.getRawUserInfo() != null || uri.getHost() == null || uri.getHost().isEmpty()
                || uri.getRawAuthority() == null) {
            return null;
        }
        return uri;
    }

    private static String origin(URI uri) {
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        int port = uri.getPort() >= 0 ? uri.getPort() : ("https".equals(scheme) ? 443 : 80);
        return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + ":" + port;
    }
}
