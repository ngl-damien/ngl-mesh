package ngl.relay.integration;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;

/** Bounded regular-file reader that refuses symbolic links and path replacement. */
public final class SafeEvidenceFileReader {
    private SafeEvidenceFileReader() {}

    public static byte[] read(File file, int limit) throws IOException {
        if (file == null || limit < 0) throw new IOException("input_not_regular_or_too_large");
        Path path = file.toPath();
        BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.size() > limit) {
            throw new IOException("input_not_regular_or_too_large");
        }

        byte[] bytes;
        try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
             InputStream in = Channels.newInputStream(channel);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = in.read(buffer)) != -1) {
                if (out.size() + count > limit) throw new IOException("input_limit");
                out.write(buffer, 0, count);
            }
            bytes = out.toByteArray();
        }

        BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!after.isRegularFile() || before.size() != bytes.length || after.size() != bytes.length
            || !before.lastModifiedTime().equals(after.lastModifiedTime())
            || !Objects.equals(before.fileKey(), after.fileKey())) {
            throw new IOException("input_changed_during_read");
        }
        return bytes;
    }
}
