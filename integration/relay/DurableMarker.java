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
import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

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


    private static UserPrincipal currentUser(Path directory) {
        String name = ProcessHandle.current().info().user()
            .orElseThrow(() -> new SecurityException("authority_state_owner_unavailable"));
        try {
            return directory.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(name);
        } catch (IOException | UnsupportedOperationException error) {
            throw new SecurityException("authority_state_owner_unavailable", error);
        }
    }

    private static void assertPrivateDirectory(Path directory) throws IOException {
        if (Files.isSymbolicLink(directory) || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new SecurityException("authority_state_not_directory");
        }

        Set<PosixFilePermission> permissions;
        try {
            permissions = Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException unsupported) {
            throw new SecurityException("authority_state_permissions_unavailable", unsupported);
        }
        if (!permissions.containsAll(EnumSet.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)) ||
                permissions.contains(PosixFilePermission.GROUP_READ) ||
                permissions.contains(PosixFilePermission.GROUP_WRITE) ||
                permissions.contains(PosixFilePermission.GROUP_EXECUTE) ||
                permissions.contains(PosixFilePermission.OTHERS_READ) ||
                permissions.contains(PosixFilePermission.OTHERS_WRITE) ||
                permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) {
            throw new SecurityException("authority_state_permissions_unsafe");
        }

        UserPrincipal actual;
        try {
            actual = Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException unsupported) {
            throw new SecurityException("authority_state_owner_unavailable", unsupported);
        }
        if (!actual.equals(currentUser(directory))) {
            throw new SecurityException("authority_state_owner_mismatch");
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
                throw new SecurityException("authority_state_permissions_unavailable", unsupported);
            }
        }

        // Recheck the entire path after creation to catch a replaced ancestor
        // observed between the initial validation and directory creation.
        rejectSymlinkAncestors(dir);
        if (missing.isEmpty()) {
            assertPrivateDirectory(dir);
        } else {
            // CREATE_DIRECTORIES attributes do not repair an existing directory.
            // Validate every newly created component and the existing leaf before
            // trusting the path as replay/revocation state.
            for (Path created : missing) assertPrivateDirectory(created);
        }

        // Sync the parent entry before syncing entries created inside it:
        // the missing list is leaf-first, so walk it in reverse (outermost first).
        for (int i = missing.size() - 1; i >= 0; i--) {
            Path containing = missing.get(i).getParent();
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
