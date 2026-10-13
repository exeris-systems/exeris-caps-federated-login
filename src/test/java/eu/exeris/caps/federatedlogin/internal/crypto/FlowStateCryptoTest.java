package eu.exeris.caps.federatedlogin.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("FlowStateCrypto Unit Tests")
class FlowStateCryptoTest {

    @Test
    @DisplayName("AES-256-GCM encryption and decryption round-trip")
    void encryptionRoundTrip() {
        FlowStateCrypto crypto = new FlowStateCrypto();
        String plainVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        String encrypted = crypto.encrypt(plainVerifier);
        assertThat(encrypted).isNotNull().isNotEqualTo(plainVerifier);

        String decrypted = crypto.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plainVerifier);
    }

    @Test
    @DisplayName("random IV produces different ciphertext for identical plaintext")
    void randomizedIv() {
        FlowStateCrypto crypto = new FlowStateCrypto();
        String plaintext = "same-plaintext-value";

        String enc1 = crypto.encrypt(plaintext);
        String enc2 = crypto.encrypt(plaintext);

        assertThat(enc1).isNotEqualTo(enc2);
        assertThat(crypto.decrypt(enc1)).isEqualTo(plaintext);
        assertThat(crypto.decrypt(enc2)).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("tampered ciphertext fails authentication tag validation")
    void tamperedCiphertextFails() {
        FlowStateCrypto crypto = new FlowStateCrypto();
        String encrypted = crypto.encrypt("secret-token");

        // Tamper with last byte
        byte[] bytes = java.util.Base64.getUrlDecoder().decode(encrypted);
        bytes[bytes.length - 1] ^= 0x01;
        String tampered = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        assertThatThrownBy(() -> crypto.decrypt(tampered))
                .isInstanceOf(IllegalStateException.class);
    }
}
