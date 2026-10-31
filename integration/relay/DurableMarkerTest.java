package ngl.relay.integration;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
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
            check(Files.getPosixFilePermissions(used).equals(PosixFilePermissions.fromString("rwx------")),
                "new marker directory must be owner-only");
            check(Files.getOwner(used).getName().equals(ProcessHandle.current().info().user().orElseThrow()),
                "new marker directory must belong to the current OS user");
            check(Files.getPosixFilePermissions(used.resolve(name)).equals(PosixFilePermissions.fromString("rw-------")),
                "marker file must be owner-only");
            check(DurableMarker.exists(used.toFile(), name), "a valid marker is recognized");
            check(!DurableMarker.exists(used.toFile(), "f".repeat(64)), "an absent marker is not reported");

            Path nestedUsed = root.resolve("deep").resolve("nested").resolve("used");
            String nestedName = "d".repeat(64);
            DurableMarker.create(nestedUsed.toFile(), nestedName, "nested marker\n", "authority_replay");
            check(Files.readString(nestedUsed.resolve(nestedName), StandardCharsets.UTF_8).equals("nested marker\n"),
                "nested marker creation must complete after syncing each newly created directory entry");

            expect("authority_replay",
                () -> DurableMarker.create(used.toFile(), name, "replacement\n", "authority_replay"));
            check(Files.readString(used.resolve(name), StandardCharsets.UTF_8).equals("consumed\n"),
                "duplicate marker must not overwrite the original");

            Path victim = root.resolve("victim.txt");
            Files.writeString(victim, "leave unchanged\n", StandardCharsets.UTF_8);
            Path linked = root.resolve("linked");
            Files.createDirectory(linked);
            Files.setPosixFilePermissions(linked, PosixFilePermissions.fromString("rwx------"));
            Files.createSymbolicLink(linked.resolve(name), victim);
            expect("authority_marker_not_regular", () -> DurableMarker.exists(linked.toFile(), name));
            expect("authority_replay",
                () -> DurableMarker.create(linked.toFile(), name, "overwrite\n", "authority_replay"));
            check(Files.readString(victim, StandardCharsets.UTF_8).equals("leave unchanged\n"),
                "pre-existing symlink target must not be overwritten");

            Path directoryLink = root.resolve("directory-link");
            Files.createSymbolicLink(directoryLink, used);
            expect("authority_state_not_directory",
                () -> DurableMarker.create(directoryLink.toFile(), "b".repeat(64), "x\n", "authority_replay"));
            expect("authority_state_not_directory",
                () -> DurableMarker.exists(directoryLink.toFile(), "b".repeat(64)));

            Path realAncestor = root.resolve("real-ancestor");
            Path realNested = realAncestor.resolve("nested");
            Files.createDirectories(realNested);
            Path ancestorLink = root.resolve("ancestor-link");
            Files.createSymbolicLink(ancestorLink, realAncestor);
            Path redirected = ancestorLink.resolve("nested").resolve("used");
            expect("authority_state_not_directory",
                () -> DurableMarker.create(redirected.toFile(), "c".repeat(64), "x\n", "authority_replay"));
            check(!Files.exists(realNested.resolve("used"), LinkOption.NOFOLLOW_LINKS),
                "a symlinked grandparent must not redirect marker creation");

            Path permissiveParent = root.resolve("permissive-parent");
            Files.createDirectory(permissiveParent);
            Files.setPosixFilePermissions(permissiveParent, PosixFilePermissions.fromString("rwxrwxrwx"));
            Path blockedChild = permissiveParent.resolve("used");
            String parentBlockedName = "g".repeat(64);
            expect("authority_state_permissions_unsafe",
                () -> DurableMarker.create(blockedChild.toFile(), parentBlockedName, "must not persist\n", "authority_replay"));
            check(!Files.exists(blockedChild, LinkOption.NOFOLLOW_LINKS),
                "a permissive parent must be rejected before a child marker directory is created");

            Path permissive = root.resolve("permissive");
            Files.createDirectory(permissive);
            Files.setPosixFilePermissions(permissive, PosixFilePermissions.fromString("rwxrwxrwx"));
            String blockedName = "e".repeat(64);
            expect("authority_state_permissions_unsafe",
                () -> DurableMarker.create(permissive.toFile(), blockedName, "must not persist\n", "authority_replay"));
            check(!Files.exists(permissive.resolve(blockedName), LinkOption.NOFOLLOW_LINKS),
                "a pre-existing permissive directory must not receive replay/revocation markers");

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
