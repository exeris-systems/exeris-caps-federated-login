package eu.exeris.caps.federatedlogin.internal.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JsonReader Unit Tests")
class JsonReaderTest {

    @Test
    @DisplayName("parses flat and nested JSON objects with various types")
    void parseObject() {
        String json = """
                {
                    "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "scope": "read:user",
                    "active": true,
                    "revoked": false,
                    "details": null,
                    "profile": {
                        "id": 12345,
                        "name": "Octo Cat"
                    }
                }
                """;

        Map<String, Object> map = JsonReader.parseObject(json);

        assertThat(map.get("access_token")).isEqualTo("gho_16C7e42F292c6912E7710c838347Ae178B4a");
        assertThat(map.get("token_type")).isEqualTo("bearer");
        assertThat(map.get("expires_in")).isEqualTo(3600L);
        assertThat(map.get("scope")).isEqualTo("read:user");
        assertThat(map.get("active")).isEqualTo(true);
        assertThat(map.get("revoked")).isEqualTo(false);
        assertThat(map.get("details")).isNull();

        @SuppressWarnings("unchecked")
        Map<String, Object> profile = (Map<String, Object>) map.get("profile");
        assertThat(profile).isNotNull();
        assertThat(profile.get("id")).isEqualTo(12345L);
        assertThat(profile.get("name")).isEqualTo("Octo Cat");
    }

    @Test
    @DisplayName("parses JSON arrays")
    void parseArray() {
        String json = """
                [
                    {"email": "octo@github.com", "primary": true, "verified": true},
                    {"email": "alt@github.com", "primary": false, "verified": true}
                ]
                """;

        List<Object> list = JsonReader.parseArray(json);
        assertThat(list).hasSize(2);

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) list.get(0);
        assertThat(first.get("email")).isEqualTo("octo@github.com");
        assertThat(first.get("primary")).isEqualTo(true);
        assertThat(first.get("verified")).isEqualTo(true);
    }

    @Test
    @DisplayName("serializes objects and maps to valid JSON")
    void serializeToJson() {
        Map<String, Object> map = Map.of(
                "issuer", "https://accounts.google.com",
                "verified", true,
                "count", 42L
        );

        String json = JsonReader.toJson(map);
        assertThat(json).contains("\"issuer\":\"https://accounts.google.com\"");
        assertThat(json).contains("\"verified\":true");
        assertThat(json).contains("\"count\":42");

        Map<String, Object> roundtrip = JsonReader.parseObject(json);
        assertThat(roundtrip.get("issuer")).isEqualTo("https://accounts.google.com");
        assertThat(roundtrip.get("verified")).isEqualTo(true);
        assertThat(roundtrip.get("count")).isEqualTo(42L);
    }

    @Test
    @DisplayName("handles escape sequences in strings")
    void escapeSequences() {
        String json = "{\"text\": \"line1\\nline2\\t\\\"quoted\\\"\"}";
        Map<String, Object> map = JsonReader.parseObject(json);
        assertThat(map.get("text")).isEqualTo("line1\nline2\t\"quoted\"");
    }

    @Test
    @DisplayName("rejects malformed JSON")
    void rejectsMalformed() {
        assertThatThrownBy(() -> JsonReader.parseObject("{invalid"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> JsonReader.parseObject("{\"num\": -}"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("handles unicode escapes and scientific notation numbers")
    void unicodeAndNumbers() {
        String json = """
                {
                    "unicode": "hello\\u0020world",
                    "sci": 1.5e2,
                    "zero": 0,
                    "negative": -100
                }
                """;
        Map<String, Object> map = JsonReader.parseObject(json);
        assertThat(map.get("unicode")).isEqualTo("hello world");
        assertThat(map.get("sci")).isEqualTo(150.0);
        assertThat(map.get("zero")).isEqualTo(0L);
        assertThat(map.get("negative")).isEqualTo(-100L);
    }

    @Test
    @DisplayName("handles empty object and empty array")
    void emptyStructures() {
        assertThat(JsonReader.parseObject("{}")).isEmpty();
        assertThat(JsonReader.parseArray("[]")).isEmpty();
        assertThat(JsonReader.parseObject("")).isEmpty();
        assertThat(JsonReader.parseArray("")).isEmpty();
    }
}
