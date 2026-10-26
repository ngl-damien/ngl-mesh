package ngl.relay.integration;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Verifies a host-provisioned Ed25519 trust pin before a caller-supplied public
 * key can authorize a Relay transition. The pin must not come from the request
 * or be computed from the supplied key at request time.
 */
public final class OperatorKeyTrust {
    private static final int MAX_KEY_BYTES = 16 * 1024;
    private static final String BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String END = "-----END PUBLIC KEY-----";

    private OperatorKeyTrust() {}

    public record PinnedKey(PublicKey key, String spkiFingerprint, String legacyPemFingerprint) {}

    static String configuredFingerprint() {
        String environment = System.getenv("NGL_RELAY_OPERATOR_KEY_SHA256");
        if (environment != null && !environment.isBlank()) return environment.trim();
        String property = System.getProperty("ngl.relay.operatorKeySha256");
        return property == null ? null : property.trim();
    }

    public static String fingerprint(PublicKey key) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
        return HexFormat.of().formatHex(digest);
    }

    public static PinnedKey loadPinnedKey(File file, String expectedFingerprint) throws Exception {
        if (expectedFingerprint == null || expectedFingerprint.isBlank())
            throw new SecurityException("operator_trust_pin_missing");
        String expected = expectedFingerprint.trim();
        if (!expected.matches("[a-f0-9]{64}"))
            throw new SecurityException("operator_trust_pin_invalid");
        if (file == null) throw new SecurityException("operator_key_file_missing");

        Path path = file.toPath();
        BasicFileAttributes before;
        try {
            before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException failure) {
            throw new SecurityException("operator_key_unreadable", failure);
        }
        if (Files.isSymbolicLink(path) || !before.isRegularFile())
            throw new SecurityException("operator_key_not_regular");
        if (before.size() > MAX_KEY_BYTES) throw new SecurityException("operator_key_too_large");

        byte[] bytes;
        try (InputStream input = Files.newInputStream(
                path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (output.size() + count > MAX_KEY_BYTES)
                    throw new SecurityException("operator_key_too_large");
                output.write(buffer, 0, count);
            }
            bytes = output.toByteArray();
        }

        BasicFileAttributes after;
        try {
            after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException failure) {
            throw new SecurityException("operator_key_changed", failure);
        }
        Object beforeKey = before.fileKey();
        Object afterKey = after.fileKey();
        if (Files.isSymbolicLink(path) || !after.isRegularFile()
                || (beforeKey != null && !beforeKey.equals(afterKey))
                || before.size() != after.size()
                || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
            throw new SecurityException("operator_key_changed");
        }

        String text = new String(bytes, StandardCharsets.UTF_8).trim();
        if (!text.startsWith(BEGIN) || !text.endsWith(END))
            throw new SecurityException("operator_key_pem_invalid");
        String encoded = text.substring(BEGIN.length(), text.length() - END.length())
                .replaceAll("\\s+", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException failure) {
            throw new SecurityException("operator_key_pem_invalid", failure);
        }

        PublicKey key;
        try {
            key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception failure) {
            throw new SecurityException("operator_key_ed25519_invalid", failure);
        }
        String actual = fingerprint(key);
        if (!MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.US_ASCII),
                expected.getBytes(StandardCharsets.US_ASCII))) {
            throw new SecurityException("operator_trust_pin_mismatch");
        }
        String legacyPemFingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(bytes));
        return new PinnedKey(key, actual, legacyPemFingerprint);
    }

    public static PublicKey loadPinnedPublicKey(File file, String expectedFingerprint) throws Exception {
        return loadPinnedKey(file, expectedFingerprint).key();
    }
}
