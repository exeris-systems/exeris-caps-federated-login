package eu.exeris.caps.federatedlogin.internal.http;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Lightweight, zero-dependency JSON parser and serializer for parsing OAuth/OIDC responses
 * and persisting metadata without external library dependencies (Wall compliance).
 *
 * @since 0.1.0
 */
public final class JsonReader {

    private JsonReader() {
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        Object parsed = parse(json.trim());
        if (parsed instanceof Map) {
            return (Map<String, Object>) parsed;
        }
        throw new IllegalArgumentException("Expected JSON object but got: " + parsed);
    }

    @SuppressWarnings("unchecked")
    public static List<Object> parseArray(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        Object parsed = parse(json.trim());
        if (parsed instanceof List) {
            return (List<Object>) parsed;
        }
        throw new IllegalArgumentException("Expected JSON array but got: " + parsed);
    }

    public static Object parse(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        Parser parser = new Parser(json.trim());
        return parser.parseValue();
    }

    public static String toJson(Object obj) {
        if (obj == null) {
            return "null";
        }
        if (obj instanceof String s) {
            return quote(s);
        }
        if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        }
        if (obj instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                sb.append(quote(String.valueOf(entry.getKey()))).append(":").append(toJson(entry.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }
        if (obj instanceof Iterable<?> list) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    sb.append(",");
                }
                first = false;
                sb.append(toJson(item));
            }
            sb.append("]");
            return sb.toString();
        }
        return quote(obj.toString());
    }

    private static String quote(String string) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < string.length(); i++) {
            char c = string.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        String hex = "000" + Integer.toHexString(c);
                        sb.append("\\u").append(hex.substring(hex.length() - 4));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private static final class Parser {
        private final String text;
        private int pos = 0;

        Parser(String text) {
            this.text = text;
        }

        Object parseValue() {
            skipWhitespace();
            if (pos >= text.length()) {
                return null;
            }
            char c = text.charAt(pos);
            if (c == '{') {
                return parseObject();
            } else if (c == '[') {
                return parseArray();
            } else if (c == '"') {
                return parseString();
            } else if (c == 't' || c == 'f') {
                return parseBoolean();
            } else if (c == 'n') {
                return parseNull();
            } else if (c == '-' || (c >= '0' && c <= '9')) {
                return parseNumber();
            }
            throw new IllegalArgumentException("Unexpected character at pos " + pos + ": " + c);
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // skip '{'
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (pos < text.length()) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                if (pos >= text.length() || text.charAt(pos) != ':') {
                    throw new IllegalArgumentException("Expected ':' at pos " + pos);
                }
                pos++; // skip ':'
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                if (pos < text.length() && text.charAt(pos) == ',') {
                    pos++; // skip ','
                } else if (pos < text.length() && text.charAt(pos) == '}') {
                    pos++; // skip '}'
                    break;
                } else {
                    throw new IllegalArgumentException("Expected ',' or '}' at pos " + pos);
                }
            }
            return map;
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            pos++; // skip '['
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (pos < text.length()) {
                Object value = parseValue();
                list.add(value);
                skipWhitespace();
                if (pos < text.length() && text.charAt(pos) == ',') {
                    pos++; // skip ','
                } else if (pos < text.length() && text.charAt(pos) == ']') {
                    pos++; // skip ']'
                    break;
                } else {
                    throw new IllegalArgumentException("Expected ',' or ']' at pos " + pos);
                }
            }
            return list;
        }

        private String parseString() {
            skipWhitespace();
            if (pos >= text.length() || text.charAt(pos) != '"') {
                throw new IllegalArgumentException("Expected '\"' at pos " + pos);
            }
            pos++; // skip '"'
            StringBuilder sb = new StringBuilder();
            while (pos < text.length()) {
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                } else if (c == '\\') {
                    if (pos >= text.length()) {
                        throw new IllegalArgumentException("Unterminated escape sequence");
                    }
                    char esc = text.charAt(pos++);
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > text.length()) {
                                throw new IllegalArgumentException("Invalid unicode escape");
                            }
                            String hex = text.substring(pos, pos + 4);
                            pos += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                        }
                        default -> sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Unterminated string");
        }

        private Boolean parseBoolean() {
            if (text.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            } else if (text.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("Invalid boolean literal at pos " + pos);
        }

        private Object parseNull() {
            if (text.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalArgumentException("Invalid null literal at pos " + pos);
        }

        private Number parseNumber() {
            int start = pos;
            if (text.charAt(pos) == '-') {
                pos++;
            }
            boolean isFloat = false;
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+') {
                    isFloat = true;
                    pos++;
                } else {
                    break;
                }
            }
            String numStr = text.substring(start, pos);
            if (numStr.isEmpty() || "-".equals(numStr)) {
                throw new IllegalArgumentException("Invalid number at pos " + start);
            }
            try {
                if (isFloat) {
                    return Double.parseDouble(numStr);
                }
                return Long.parseLong(numStr);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid number format at pos " + start + ": " + numStr, e);
            }
        }

        private void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    pos++;
                } else {
                    break;
                }
            }
        }
    }
}
