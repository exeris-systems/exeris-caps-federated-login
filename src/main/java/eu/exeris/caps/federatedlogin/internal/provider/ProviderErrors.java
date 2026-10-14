package eu.exeris.caps.federatedlogin.internal.provider;

import eu.exeris.caps.federatedlogin.internal.http.JsonReader;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Reduces a provider response to what may be shown in an exception message or a log line.
 *
 * <p>A provider response can carry {@code access_token}, {@code refresh_token} or {@code id_token}, so a
 * message never embeds a body. It carries the HTTP status and the OAuth {@code error} code, and only
 * when that code is a short token of plain characters.
 *
 * @since 0.1.0
 */
final class ProviderErrors {

    private static final Pattern ERROR_CODE = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    private static final Set<String> TOKEN_FIELDS = Set.of("access_token", "refresh_token", "id_token", "token", "code");

    private ProviderErrors() {
    }

    /**
     * Extracts the OAuth {@code error} code from a provider response body without echoing any other
     * content of the body.
     *
     * @return the OAuth {@code error} code of a response body, or {@code "unspecified"} when the body is
     *         not a JSON object with a plain {@code error} member
     */
    static String errorCode(String body) {
        if (body == null || body.isBlank()) {
            return "unspecified";
        }
        try {
            return errorCode(JsonReader.parseObject(body));
        } catch (RuntimeException e) {
            return "unspecified";
        }
    }

    static String errorCode(Map<String, Object> parsed) {
        Object error = parsed.get("error");
        if (error instanceof String code && ERROR_CODE.matcher(code).matches()) {
            return code;
        }
        return "unspecified";
    }

    /**
     * Removes the credential-bearing fields from a provider payload before it becomes identity
     * attributes.
     *
     * @return a copy of {@code payload} without the fields that carry a credential
     */
    static Map<String, Object> withoutCredentials(Map<String, Object> payload) {
        Map<String, Object> copy = new LinkedHashMap<>(payload);
        copy.keySet().removeAll(TOKEN_FIELDS);
        return copy;
    }
}
