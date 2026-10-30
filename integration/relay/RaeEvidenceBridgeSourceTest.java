package ngl.relay.integration;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class RaeEvidenceBridgeSourceTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: <RaeEvidenceBridge.java>");
        String source = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        int decode = source.indexOf("StrictUtf8.decode(reportBytes)");
        int parse = source.indexOf("CoreJson.parseObject(reportText)");
        int reportHash = source.indexOf("String reportHash = sha(reportBytes)");
        check(decode >= 0, "bridge must use the strict decoder for report bytes");
        check(parse > decode, "strict decoding must happen before JSON parsing");
        check(reportHash > parse, "the original bytes must be hashed after successful decoding");
        check(!source.contains("new String(reportBytes, StandardCharsets.UTF_8)"),
            "replacement-decoding must not return");
        System.out.println("RAE_BRIDGE_SOURCE_CONTRACT: 4 checks passed");
    }
}
