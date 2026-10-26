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

/**
 * Creates replay/revocation markers without following an existing marker path.
 * Success means both marker contents and the directory entry were synced.
 * A sync failure is fail-closed: callers must not perform the authorized action.
 */
public final class DurableMarker {
    private DurableMarker() {}

    public static void create(File directory, String name, String value, String conflictCode)
            throws IOException {
        if (directory == null || name == null || !name.matches("[a-f0-9]{64}")
                || value == null || conflictCode == null || conflictCode.isBlank()) {
            throw new IllegalArgumentException("authority_marker_invalid");
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 4096) throw new IllegalArgumentException("authority_marker_too_large");

        Path dir = directory.toPath();
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) Files.createDirectories(dir);
        if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("authority_state_not_directory");
        }

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
        try (FileChannel parent = FileChannel.open(dir, StandardOpenOption.READ)) {
            parent.force(true);
        }
    }
}
