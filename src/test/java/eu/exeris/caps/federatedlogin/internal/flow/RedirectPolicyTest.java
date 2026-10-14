package eu.exeris.caps.federatedlogin.internal.flow;

import eu.exeris.caps.federatedlogin.api.exception.FederatedLoginConfigurationException;
import eu.exeris.caps.federatedlogin.api.exception.InvalidRedirectException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("RedirectPolicy Unit Tests")
class RedirectPolicyTest {

    private static final RedirectPolicy POLICY = RedirectPolicy.of(
            Map.of("google", List.of("https://good.example/cb", "http://localhost:8080/cb"),
                    "github", List.of("https://good.example/gh")),
            List.of("https://good.example", "https://other.example:8443"));

    @Test
    @DisplayName("a registered redirectUri matches exactly, case of scheme and host aside, default port included")
    void registeredMatches() {
        assertThatCode(() -> POLICY.requireRegisteredRedirectUri("google", "https://good.example/cb")).doesNotThrowAnyException();
        assertThatCode(() -> POLICY.requireRegisteredRedirectUri("google", "HTTPS://Good.Example:443/cb")).doesNotThrowAnyException();
        assertThatCode(() -> POLICY.requireRegisteredRedirectUri("google", "http://localhost:8080/cb")).doesNotThrowAnyException();
    }

    @ParameterizedTest(name = "redirectUri rejected: {0}")
    @ValueSource(strings = {
            "https://good.example/cb/",
            "https://good.example/cb?x=1",
            "https://good.example/cb#frag",
            "https://good.example/CB",
            "https://good.example/gh",
            "https://good.example:444/cb",
            "http://good.example/cb",
            "https://good.example.evil.example/cb",
            "https://evil.example/cb",
            "//good.example/cb",
            "/cb",
            "https://evil@good.example/cb",
            "https://good.example@evil.example/cb",
            "https://good.example\\@evil.example/cb",
            "https://good.example/cb\\..\\x",
            "https://good.example/%2Fcb",
            "https://good.example/c%62",
            "https://good.example/cb\n",
            "https:///good.example/cb",
            "javascript:alert(1)",
            "",
            " https://good.example/cb"
    })
    void redirectBypassesRejected(String candidate) {
        assertThatThrownBy(() -> POLICY.requireRegisteredRedirectUri("google", candidate))
                .isInstanceOf(InvalidRedirectException.class);
    }

    @Test
    @DisplayName("a redirectUri is bound to its provider, and an unknown provider has none")
    void perProvider() {
        assertThatThrownBy(() -> POLICY.requireRegisteredRedirectUri("github", "https://good.example/cb"))
                .isInstanceOf(InvalidRedirectException.class);
        assertThatThrownBy(() -> POLICY.requireRegisteredRedirectUri("unknown", "https://good.example/cb"))
                .isInstanceOf(InvalidRedirectException.class);
    }

    @ParameterizedTest(name = "post-login accepted: {0}")
    @ValueSource(strings = {"/", "/home", "/a/b?c=d#e", "https://good.example/welcome", "https://other.example:8443/x"})
    void postLoginAccepted(String url) {
        assertThatCode(() -> POLICY.requireSafePostLoginUrl(url)).doesNotThrowAnyException();
        assertThatCode(() -> POLICY.requireSafePostLoginUrl(null)).doesNotThrowAnyException();
    }

    @ParameterizedTest(name = "post-login rejected: {0}")
    @ValueSource(strings = {
            "//evil.example",
            "//good.example",
            "/\\evil.example",
            "\\\\evil.example",
            "\\/evil.example",
            "/%2Fevil.example",
            "/%2fevil.example",
            "/%5Cevil.example",
            "/\t/evil.example",
            "/\n/evil.example",
            "https://evil.example/x",
            "https://good.example@evil.example/x",
            "https://evil@good.example/x",
            "https://good.example\\@evil.example",
            "https://other.example/x",
            "http://good.example/x",
            "javascript:alert(1)",
            "data:text/html,x",
            "evil.example",
            "home",
            "",
            " "
    })
    void postLoginBypassesRejected(String url) {
        assertThatThrownBy(() -> POLICY.requireSafePostLoginUrl(url)).isInstanceOf(InvalidRedirectException.class);
    }

    @Test
    @DisplayName("the empty policy allows no redirect URI and no absolute URL")
    void denyAll() {
        assertThatThrownBy(() -> RedirectPolicy.denyAll().requireRegisteredRedirectUri("google", "https://good.example/cb"))
                .isInstanceOf(InvalidRedirectException.class);
        assertThatThrownBy(() -> RedirectPolicy.denyAll().requireSafePostLoginUrl("https://good.example/"))
                .isInstanceOf(InvalidRedirectException.class);
        assertThatCode(() -> RedirectPolicy.denyAll().requireSafePostLoginUrl("/home")).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("configuration is parsed from the environment and unacceptable entries fail construction")
    void environment() {
        RedirectPolicy policy = RedirectPolicy.fromEnvironment(Map.of(
                RedirectPolicy.ENV_REDIRECT_URIS, "google=https://a.example/cb,https://b.example/cb;github=https://a.example/gh",
                RedirectPolicy.ENV_POST_LOGIN_ORIGINS, "https://a.example"));

        assertThatCode(() -> policy.requireRegisteredRedirectUri("google", "https://b.example/cb")).doesNotThrowAnyException();
        assertThatCode(() -> policy.requireSafePostLoginUrl("https://a.example/x")).doesNotThrowAnyException();

        for (String bad : List.of("google", "google=http://a.example/cb", "google=https://a.example/cb?x=1",
                "google=https://u@a.example/cb", "google=/cb")) {
            assertThatThrownBy(() -> RedirectPolicy.fromEnvironment(Map.of(RedirectPolicy.ENV_REDIRECT_URIS, bad)))
                    .isInstanceOf(FederatedLoginConfigurationException.class);
        }
        for (String bad : List.of("https://a.example/path", "http://a.example", "a.example")) {
            assertThatThrownBy(() -> RedirectPolicy.fromEnvironment(Map.of(RedirectPolicy.ENV_POST_LOGIN_ORIGINS, bad)))
                    .isInstanceOf(FederatedLoginConfigurationException.class);
        }
    }
}
