package eu.exeris.caps.federatedlogin.internal.crypto;

import eu.exeris.caps.federatedlogin.api.exception.FlowStateUnreadableException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("FlowStateCrypto Unit Tests")
class FlowStateCryptoTest {

    static final String KEY_A = Base64.getEncoder().encodeToString(new byte[32]);
    static final String KEY_B = Base64.getEncoder().encodeToString(filled(7));
    static final String KEY_C = Base64.getEncoder().encodeToString(filled(9));

    static byte[] filled(int value) {
        byte[] bytes = new byte[32];
        java.util.Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    static FlowStateCrypto crypto(String spec) {
        return new FlowStateCrypto(FlowStateKeyring.parse("test", spec));
    }

    @Test
    @DisplayName("AES-256-GCM seal and open round-trip")
    void roundTrip() {
        FlowStateCrypto crypto = crypto("k1:" + KEY_A);
        String plain = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        String sealed = crypto.encrypt(plain, "state-1");

        assertThat(sealed).startsWith("k1:").doesNotContain(plain);
        assertThat(crypto.decrypt(sealed, "state-1")).isEqualTo(plain);
    }

    @Test
    @DisplayName("random IV produces different ciphertext for identical plaintext")
    void randomizedIv() {
        FlowStateCrypto crypto = crypto("k1:" + KEY_A);

        assertThat(crypto.encrypt("same", "s")).isNotEqualTo(crypto.encrypt("same", "s"));
    }

    @Test
    @DisplayName("a second instance holding the same keyring opens what the first sealed")
    void sharedKeyringOpensAcrossInstances() {
        String sealed = crypto("k1:" + KEY_A).encrypt("verifier", "state-1");

        assertThat(crypto("k1:" + KEY_A).decrypt(sealed, "state-1")).isEqualTo("verifier");
    }

    @Test
    @DisplayName("tampered ciphertext fails with a typed exception")
    void tamperedCiphertextFails() {
        FlowStateCrypto crypto = crypto("k1:" + KEY_A);
        String sealed = crypto.encrypt("secret-token", "state-1");
        int colon = sealed.indexOf(':');
        byte[] bytes = Base64.getUrlDecoder().decode(sealed.substring(colon + 1));
        bytes[bytes.length - 1] ^= 0x01;
        String tampered = sealed.substring(0, colon + 1) + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        assertThatThrownBy(() -> crypto.decrypt(tampered, "state-1")).isInstanceOf(FlowStateUnreadableException.class);
    }

    @Test
    @DisplayName("a sealed value does not open under another state id")
    void associatedDataIsBound() {
        FlowStateCrypto crypto = crypto("k1:" + KEY_A);
        String sealed = crypto.encrypt("verifier", "state-1");

        assertThatThrownBy(() -> crypto.decrypt(sealed, "state-2")).isInstanceOf(FlowStateUnreadableException.class);
    }

    @Test
    @DisplayName("an unknown key id and a malformed payload are typed failures")
    void unknownKeyAndMalformed() {
        String sealed = crypto("k1:" + KEY_A).encrypt("verifier", "s");
        FlowStateCrypto other = crypto("k2:" + KEY_B);

        assertThatThrownBy(() -> other.decrypt(sealed, "s"))
                .isInstanceOf(FlowStateUnreadableException.class).hasMessageContaining("k1");
        assertThatThrownBy(() -> other.decrypt("no-separator", "s")).isInstanceOf(FlowStateUnreadableException.class);
        assertThatThrownBy(() -> other.decrypt("k2:!!!", "s")).isInstanceOf(FlowStateUnreadableException.class);
    }

    @Test
    @DisplayName("rotation: the first key seals, a later key still opens older payloads")
    void rotation() {
        String old = crypto("k1:" + KEY_A).encrypt("verifier", "s");
        FlowStateCrypto rotated = crypto("k2:" + KEY_B + ",k1:" + KEY_A);

        assertThat(rotated.decrypt(old, "s")).isEqualTo("verifier");
        assertThat(rotated.encrypt("verifier", "s")).startsWith("k2:");
    }
}
