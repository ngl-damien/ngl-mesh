package ngl.relay.integration;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class StrictUtf8Test {
    private static int checks = 0;
    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void rejects(byte[] bytes, String label) {
        try {
            StrictUtf8.decode(bytes);
            throw new AssertionError(label + " was accepted");
        } catch (IllegalArgumentException expected) {
            check("invalid_utf8".equals(expected.getMessage()), label + " has a stable rejection");
        }
    }

    public static void main(String[] args) {
        check("".equals(StrictUtf8.decode(new byte[0])), "empty UTF-8 is valid");
        byte[] ascii = "{\"observation\":{\"artifact\":{}}}".getBytes(StandardCharsets.UTF_8);
        check(Arrays.equals(ascii, StrictUtf8.decode(ascii).getBytes(StandardCharsets.UTF_8)),
            "ASCII bytes round-trip exactly");
        String multilingual = "No_Gas_Labs · Featherstone 🧪";
        byte[] encoded = multilingual.getBytes(StandardCharsets.UTF_8);
        check(multilingual.equals(StrictUtf8.decode(encoded)), "multilingual UTF-8 decodes");
        check(Arrays.equals(encoded, StrictUtf8.decode(encoded).getBytes(StandardCharsets.UTF_8)),
            "multilingual bytes round-trip exactly");

        rejects(new byte[] {(byte) 0xC3}, "truncated two-byte sequence");
        rejects(new byte[] {(byte) 0xC3, 0x28}, "invalid continuation byte");
        rejects(new byte[] {(byte) 0xC0, (byte) 0xAF}, "overlong encoding");
        rejects(new byte[] {(byte) 0xED, (byte) 0xA0, (byte) 0x80}, "UTF-8 encoded surrogate");
        rejects(new byte[] {(byte) 0xF4, (byte) 0x90, (byte) 0x80, (byte) 0x80}, "code point above Unicode range");
        rejects(null, "null input");
        System.out.println("STRICT_UTF8: " + checks + " checks passed");
    }
}
