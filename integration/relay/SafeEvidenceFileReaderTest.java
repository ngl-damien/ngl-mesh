package ngl.relay.integration;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

public final class SafeEvidenceFileReaderTest {
    private static int checks = 0;
    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static void rejects(File file, int limit, String expected) throws Exception {
        try {
            SafeEvidenceFileReader.read(file, limit);
            throw new AssertionError("unsafe evidence input was accepted: " + file);
        } catch (IOException error) {
            check(expected.equals(error.getMessage()), "stable rejection for " + file.getName());
        }
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("ngl-safe-evidence-");
        try {
            Path regular = root.resolve("report.json");
            Files.writeString(regular, "{}", StandardCharsets.UTF_8);
            check("{}".equals(new String(SafeEvidenceFileReader.read(regular.toFile(), 2), StandardCharsets.UTF_8)),
                "bounded regular file is read exactly");
            rejects(regular.toFile(), 1, "input_not_regular_or_too_large");

            Path directory = root.resolve("directory");
            Files.createDirectory(directory);
            rejects(directory.toFile(), 16, "input_not_regular_or_too_large");

            Path link = root.resolve("report-link.json");
            Files.createSymbolicLink(link, regular.getFileName());
            check(Files.isSymbolicLink(link), "symlink fixture is a symbolic link");
            rejects(link.toFile(), 16, "input_symlink_component");

            Path directoryLink = root.resolve("directory-link");
            Files.createSymbolicLink(directoryLink, directory.getFileName());
            rejects(directoryLink.toFile(), 16, "input_symlink_component");

            Path outside = root.resolve("outside");
            Files.createDirectory(outside);
            Files.writeString(outside.resolve("report.json"), "{}", StandardCharsets.UTF_8);
            Path parentLink = root.resolve("parent-link");
            Files.createSymbolicLink(parentLink, outside.getFileName());
            check(Files.isSymbolicLink(parentLink), "parent symlink fixture is a symbolic link");
            rejects(parentLink.resolve("report.json").toFile(), 16, "input_symlink_component");

            Path empty = root.resolve("empty");
            Files.write(empty, new byte[0]);
            check(SafeEvidenceFileReader.read(empty.toFile(), 0).length == 0, "empty regular file is accepted at zero limit");
        } finally {
            try (Stream<Path> paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
        System.out.println("SAFE_EVIDENCE_FILE_READER: " + checks + " checks passed");
    }
}
