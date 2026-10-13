package eu.exeris.caps.federatedlogin.internal.flow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("PkceGenerator Unit Tests")
class PkceGeneratorTest {

    @Test
    @DisplayName("RFC 7636 Appendix B test vector verification")
    void rfc7636AppendixBTestVector() {
        // RFC 7636 Appendix B test vector
        String testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        String actualChallenge = PkceGenerator.generateCodeChallenge(testVerifier);

        assertThat(actualChallenge).isEqualTo(expectedChallenge);
    }

    @Test
    @DisplayName("generated code verifier satisfies RFC 7636 entropy and length requirements")
    void generatedCodeVerifierProperties() {
        String verifier1 = PkceGenerator.generateCodeVerifier();
        String verifier2 = PkceGenerator.generateCodeVerifier();

        assertThat(verifier1).hasSize(43);
        assertThat(verifier2).hasSize(43);
        assertThat(verifier1).isNotEqualTo(verifier2);
        assertThat(verifier1).matches("^[A-Za-z0-9_-]+$");
    }

    @Test
    @DisplayName("generated state and nonce are high entropy and distinct")
    void stateAndNonceProperties() {
        String state1 = PkceGenerator.generateState();
        String state2 = PkceGenerator.generateState();
        String nonce1 = PkceGenerator.generateNonce();
        String nonce2 = PkceGenerator.generateNonce();

        assertThat(state1).hasSize(43).isNotEqualTo(state2);
        assertThat(nonce1).hasSize(43).isNotEqualTo(nonce2);
    }

    @Test
    @DisplayName("computeStateHash produces deterministic 64-character hex digest")
    void computeStateHash() {
        String state = "test-state-token-12345";
        String hash1 = PkceGenerator.computeStateHash(state);
        String hash2 = PkceGenerator.computeStateHash(state);

        assertThat(hash1).hasSize(64);
        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).matches("^[0-9a-f]{64}$");

        String diffHash = PkceGenerator.computeStateHash("another-state");
        assertThat(diffHash).isNotEqualTo(hash1);
    }

    @Test
    @DisplayName("null input validation")
    void nullInputValidation() {
        assertThatThrownBy(() -> PkceGenerator.generateCodeChallenge(null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> PkceGenerator.computeStateHash(null))
                .isInstanceOf(NullPointerException.class);
    }
}
