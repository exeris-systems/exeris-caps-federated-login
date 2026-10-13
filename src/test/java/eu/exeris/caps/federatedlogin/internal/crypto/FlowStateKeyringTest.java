package eu.exeris.caps.federatedlogin.internal.crypto;

import eu.exeris.caps.federatedlogin.api.exception.FederatedLoginConfigurationException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("FlowStateKeyring Unit Tests")
class FlowStateKeyringTest {

    private static final String KEY_A = FlowStateCryptoTest.KEY_A;
    private static final String KEY_B = FlowStateCryptoTest.KEY_B;

    @Test
    @DisplayName("the first entry is active")
    void firstEntryIsActive() {
        FlowStateKeyring ring = FlowStateKeyring.parse("test", "new:" + KEY_B + ", old:" + KEY_A);

        assertThat(ring.activeId()).isEqualTo("new");
        assertThat(ring.key("old")).isPresent();
        assertThat(ring.toString()).doesNotContain(KEY_A).doesNotContain(KEY_B);
    }

    @Test
    @DisplayName("an absent keyring fails closed, naming the key and not a value")
    void absentKeyringFailsClosed() {
        assertThatThrownBy(() -> FlowStateKeyring.fromEnvironment(Map.of()))
                .isInstanceOf(FederatedLoginConfigurationException.class)
                .hasMessageContaining(FlowStateKeyring.ENV_KEYS);
        assertThatThrownBy(() -> FlowStateKeyring.fromEnvironment(Map.of(FlowStateKeyring.ENV_KEYS, " ")))
                .isInstanceOf(FederatedLoginConfigurationException.class);
    }

    @Test
    @DisplayName("malformed entries are rejected without echoing the secret")
    void malformedRejected() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);
        assertThatThrownBy(() -> FlowStateKeyring.parse("t", "k:" + shortKey))
                .isInstanceOf(FederatedLoginConfigurationException.class).hasMessageContaining("32 bytes")
                .hasMessageNotContaining(shortKey);
        assertThatThrownBy(() -> FlowStateKeyring.parse("t", "k:not base64!")).isInstanceOf(FederatedLoginConfigurationException.class);
        assertThatThrownBy(() -> FlowStateKeyring.parse("t", KEY_A)).isInstanceOf(FederatedLoginConfigurationException.class);
        assertThatThrownBy(() -> FlowStateKeyring.parse("t", "bad id:" + KEY_A)).isInstanceOf(FederatedLoginConfigurationException.class);
        assertThatThrownBy(() -> FlowStateKeyring.parse("t", "k:" + KEY_A + ",k:" + KEY_B))
                .isInstanceOf(FederatedLoginConfigurationException.class).hasMessageContaining("twice");
    }

    @Test
    @DisplayName("inline and file are exclusive; the file form reads a mounted secret")
    void inlineAndFile(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("keys");
        Files.writeString(file, "k1:" + KEY_A + "\n");

        assertThat(FlowStateKeyring.fromEnvironment(Map.of(FlowStateKeyring.ENV_KEYS_FILE, file.toString())).activeId())
                .isEqualTo("k1");
        assertThatThrownBy(() -> FlowStateKeyring.fromEnvironment(Map.of(
                FlowStateKeyring.ENV_KEYS, "k1:" + KEY_A, FlowStateKeyring.ENV_KEYS_FILE, file.toString())))
                .isInstanceOf(FederatedLoginConfigurationException.class).hasMessageContaining("not both");
        assertThatThrownBy(() -> FlowStateKeyring.fromEnvironment(Map.of(
                FlowStateKeyring.ENV_KEYS_FILE, dir.resolve("missing").toString())))
                .isInstanceOf(FederatedLoginConfigurationException.class);
    }
}
