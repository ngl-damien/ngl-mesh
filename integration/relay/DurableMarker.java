package ngl.relay.integration;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

/**
 * Creates replay/revocation markers without following an existing marker path.
 * Success means both marker contents and the directory entry were synced.
 * A sync failure is fail-closed: callers must not perform the authorized action.
 */
public final class DurableMarker {
    private DurableMarker() {}

    private static void syncDirectory(Path directory) throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static void rejectSymlinkAncestors(Path path) {
        for (Path current = path; current != null; current = current.getParent()) {
            if (Files.isSymbolicLink(current)) {
                throw new SecurityException("authority_state_not_directory");
            }
        }
    }

    private static void ensureDirectory(Path dir) throws IOException {
        // Check every component, not only the leaf and its immediate parent:
        // an existing grandparent symlink can redirect a seemingly normal path.
        rejectSymlinkAncestors(dir);

        List<Path> missing = new ArrayList<>();
        for (Path current = dir; current != null
                && !Files.exists(current, LinkOption.NOFOLLOW_LINKS); current = current.getParent()) {
            missing.add(current);
        }
        if (!missing.isEmpty()) {
            try {
                Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE)));
            } catch (UnsupportedOperationException unsupported) {
                Files.createDirectories(dir);
            }
        }

        // Recheck the entire path after creation to catch a replaced ancestor
        // observed between the initial validation and directory creation.
        rejectSymlinkAncestors(dir);
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("authority_state_not_directory");
        }
        for (Path created : missing) {
            if (Files.isSymbolicLink(created) || !Files.isDirectory(created, LinkOption.NOFOLLOW_LINKS)) {
                throw new SecurityException("authority_state_not_directory");
            }
        }
        // Persist every newly created directory entry from the parent outward.
        for (Path created : missing) {
            Path containing = created.getParent();
            if (containing != null) syncDirectory(containing);
        }
    }

    public static void create(File directory, String name, String value, String conflictCode)
            throws IOException {
        if (directory == null || name == null || !name.matches("[a-f0-9]{64}")
                || value == null || conflictCode == null || conflictCode.isBlank()) {
            throw new IllegalArgumentException("authority_marker_invalid");
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 4096) throw new IllegalArgumentException("authority_marker_too_large");

        Path dir = directory.toPath().toAbsolutePath().normalize();
        ensureDirectory(dir);
        Path target = dir.resolve(name);
        try (FileChannel file = FileChannel.open(target,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) file.write(buffer);
            file.force(true);
        } catch (FileAlreadyExistsException conflict) {
            // CREATE_NEW rejects files and symlinks without following the target.
            throw new IllegalStateException(conflictCode, conflict);
        }

        // A successful file fsync alone does not guarantee its new directory
        // entry survives a crash. Fail closed if this filesystem cannot sync it.
        syncDirectory(dir);
    }
}
