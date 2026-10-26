package ngl.relay.integration;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public final class DurableMarkerTest {
    @FunctionalInterface private interface CheckedAction { void run() throws Exception; }
    private static int checks = 0;

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void expect(String code, CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected " + code);
        } catch (Exception expected) {
            check(expected.getMessage() != null && expected.getMessage().contains(code),
                "expected " + code + " but got " + expected.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("ngl-durable-marker-");
        try {
            String name = "a".repeat(64);
            Path used = root.resolve("used");
            DurableMarker.create(used.toFile(), name, "consumed\n", "authority_replay");
            check(Files.readString(used.resolve(name), StandardCharsets.UTF_8).equals("consumed\n"),
                "marker bytes must be written before success returns");

            expect("authority_replay",
                () -> DurableMarker.create(used.toFile(), name, "replacement\n", "authority_replay"));
            check(Files.readString(used.resolve(name), StandardCharsets.UTF_8).equals("consumed\n"),
                "duplicate marker must not overwrite the original");

            Path victim = root.resolve("victim.txt");
            Files.writeString(victim, "leave unchanged\n", StandardCharsets.UTF_8);
            Path linked = root.resolve("linked");
            Files.createDirectory(linked);
            Files.createSymbolicLink(linked.resolve(name), victim);
            expect("authority_replay",
                () -> DurableMarker.create(linked.toFile(), name, "overwrite\n", "authority_replay"));
            check(Files.readString(victim, StandardCharsets.UTF_8).equals("leave unchanged\n"),
                "pre-existing symlink target must not be overwritten");

            Path directoryLink = root.resolve("directory-link");
            Files.createSymbolicLink(directoryLink, used);
            expect("authority_state_not_directory",
                () -> DurableMarker.create(directoryLink.toFile(), "b".repeat(64), "x\n", "authority_replay"));

            expect("authority_marker_invalid",
                () -> DurableMarker.create(used.toFile(), "../victim.txt", "overwrite\n", "authority_replay"));
            check(Files.readString(victim, StandardCharsets.UTF_8).equals("leave unchanged\n"),
                "invalid marker names must not escape the state directory");

            System.out.println("DURABLE_MARKER: " + checks + " checks passed");
        } finally {
            try (Stream<Path> paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }
}
