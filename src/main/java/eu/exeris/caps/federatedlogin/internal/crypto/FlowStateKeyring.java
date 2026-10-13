package eu.exeris.caps.federatedlogin.internal.crypto;

import eu.exeris.caps.federatedlogin.api.exception.FederatedLoginConfigurationException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The keys that seal flow state at rest, each under an id.
 *
 * <p>The first entry is the active key and seals every new flow state; the others only open flow
 * states sealed earlier, so a key rotates by prepending a new entry and is dropped once no stored flow
 * names it. A key is exactly 32 random bytes (AES-256), given in Base64. There is no default and no
 * derivation from a passphrase: a keyring that is absent or malformed is a configuration error, never
 * a reason to substitute a key.
 *
 * <p>Format: {@code <id>:<base64>[,<id>:<base64>...]}, from {@value #ENV_KEYS} or from the file named
 * by {@value #ENV_KEYS_FILE} (a mounted secret), never both.
 *
 * @since 0.1.0
 */
public final class FlowStateKeyring {

    public static final String ENV_KEYS = "EXERIS_FEDERATED_LOGIN_STATE_KEYS";
    public static final String ENV_KEYS_FILE = "EXERIS_FEDERATED_LOGIN_STATE_KEYS_FILE";

    static final int KEY_LENGTH_BYTES = 32;
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");

    private final String activeId;
    private final Map<String, SecretKey> keys;

    private FlowStateKeyring(String activeId, Map<String, SecretKey> keys) {
        this.activeId = activeId;
        this.keys = keys;
    }

    /**
     * Reads the keyring from {@value #ENV_KEYS} or {@value #ENV_KEYS_FILE}.
     *
     * @throws FederatedLoginConfigurationException when neither or both are set, the file cannot be
     *                                              read, or the content is malformed
     */
    public static FlowStateKeyring fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment must not be null");
        String inline = environment.get(ENV_KEYS);
        String file = environment.get(ENV_KEYS_FILE);
        boolean hasInline = inline != null && !inline.isBlank();
        boolean hasFile = file != null && !file.isBlank();
        if (hasInline && hasFile) {
            throw new FederatedLoginConfigurationException(ENV_KEYS,
                    "set either " + ENV_KEYS + " or " + ENV_KEYS_FILE + ", not both");
        }
        if (hasInline) {
            return parse(ENV_KEYS, inline);
        }
        if (hasFile) {
            String content;
            try {
                content = Files.readString(Path.of(file.trim()), StandardCharsets.UTF_8);
            } catch (IOException | RuntimeException e) {
                throw new FederatedLoginConfigurationException(ENV_KEYS_FILE, "the keyring file cannot be read", e);
            }
            return parse(ENV_KEYS_FILE, content);
        }
        throw new FederatedLoginConfigurationException(ENV_KEYS, "a flow-state keyring is required when flow "
                + "state is stored in PostgreSQL; set " + ENV_KEYS + " or " + ENV_KEYS_FILE);
    }

    /**
     * Parses a keyring specification. {@code source} names the configuration key in errors; the
     * specification itself never appears in a message.
     */
    public static FlowStateKeyring parse(String source, String specification) {
        Objects.requireNonNull(source, "source must not be null");
        if (specification == null || specification.isBlank()) {
            throw new FederatedLoginConfigurationException(source, "the keyring is empty");
        }
        Map<String, SecretKey> keys = new LinkedHashMap<>();
        String activeId = null;
        String[] entries = specification.trim().split(",");
        for (int i = 0; i < entries.length; i++) {
            String entry = entries[i].trim();
            int colon = entry.indexOf(':');
            if (colon <= 0) {
                throw new FederatedLoginConfigurationException(source, "entry " + (i + 1) + " is not <id>:<base64>");
            }
            String id = entry.substring(0, colon);
            if (!KEY_ID.matcher(id).matches()) {
                throw new FederatedLoginConfigurationException(source, "entry " + (i + 1)
                        + " has an id that is not 1-32 characters of [A-Za-z0-9._-]");
            }
            if (keys.containsKey(id)) {
                throw new FederatedLoginConfigurationException(source, "key id '" + id + "' appears twice");
            }
            byte[] material = decode(source, id, entry.substring(colon + 1).trim());
            keys.put(id, new SecretKeySpec(material, "AES"));
            Arrays.fill(material, (byte) 0);
            if (activeId == null) {
                activeId = id;
            }
        }
        return new FlowStateKeyring(activeId, Map.copyOf(keys));
    }

    private static byte[] decode(String source, String id, String base64) {
        byte[] decoded;
        try {
            decoded = base64.indexOf('-') >= 0 || base64.indexOf('_') >= 0
                    ? Base64.getUrlDecoder().decode(base64)
                    : Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new FederatedLoginConfigurationException(source, "key '" + id + "' is not valid Base64");
        }
        if (decoded.length != KEY_LENGTH_BYTES) {
            int length = decoded.length;
            Arrays.fill(decoded, (byte) 0);
            throw new FederatedLoginConfigurationException(source, "key '" + id + "' must decode to "
                    + KEY_LENGTH_BYTES + " bytes, got " + length);
        }
        return decoded;
    }

    /**
     * @return the id of the key that seals new flow states
     */
    public String activeId() {
        return activeId;
    }

    SecretKey activeKey() {
        return keys.get(activeId);
    }

    Optional<SecretKey> key(String id) {
        return Optional.ofNullable(keys.get(id));
    }

    @Override
    public String toString() {
        return "FlowStateKeyring[active=" + activeId + ", ids=" + keys.keySet() + "]";
    }
}
