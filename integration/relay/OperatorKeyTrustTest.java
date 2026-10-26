package ngl.relay.integration;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.stream.Stream;

public final class OperatorKeyTrustTest {
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
        } catch (SecurityException expected) {
            check(expected.getMessage() != null && expected.getMessage().contains(code),
                "expected " + code + " but got " + expected.getMessage());
        }
    }

    private static String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(key.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
    }

    private static void writeKey(Path path, PublicKey key) throws IOException {
        Files.writeString(path, pem(key), StandardCharsets.UTF_8);
    }

    private static void testPropertyFallbackRequiresExplicitOptIn() {
        String environment = System.getenv("NGL_RELAY_OPERATOR_KEY_SHA256");
        if (environment != null && !environment.isBlank()) {
            check(environment.trim().equals(OperatorKeyTrust.configuredFingerprint()),
                "configured environment pin must take precedence");
            return;
        }
        String previousPin = System.getProperty("ngl.relay.operatorKeySha256");
        String previousOptIn = System.getProperty("ngl.relay.allowTestOperatorKeyProperty");
        String testPin = "a".repeat(64);
        try {
            System.setProperty("ngl.relay.operatorKeySha256", testPin);
            System.clearProperty("ngl.relay.allowTestOperatorKeyProperty");
            check(OperatorKeyTrust.configuredFingerprint() == null,
                "property pin must be ignored without explicit test/development opt-in");
            System.setProperty("ngl.relay.allowTestOperatorKeyProperty", "true");
            check(testPin.equals(OperatorKeyTrust.configuredFingerprint()),
                "property pin may be used only after explicit opt-in");
        } finally {
            if (previousPin == null) System.clearProperty("ngl.relay.operatorKeySha256");
            else System.setProperty("ngl.relay.operatorKeySha256", previousPin);
            if (previousOptIn == null) System.clearProperty("ngl.relay.allowTestOperatorKeyProperty");
            else System.setProperty("ngl.relay.allowTestOperatorKeyProperty", previousOptIn);
        }
    }

    public static void main(String[] args) throws Exception {
        testPropertyFallbackRequiresExplicitOptIn();
        Path directory = Files.createTempDirectory("ngl-operator-key-trust-");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            KeyPair trusted = generator.generateKeyPair();
            KeyPair attacker = generator.generateKeyPair();
            Path trustedFile = directory.resolve("trusted.pem");
            Path attackerFile = directory.resolve("attacker.pem");
            Path symlinkFile = directory.resolve("trusted-link.pem");
            Path tamperedFile = directory.resolve("tampered.pem");
            writeKey(trustedFile, trusted.getPublic());
            writeKey(attackerFile, attacker.getPublic());
            String pin = OperatorKeyTrust.fingerprint(trusted.getPublic());

            OperatorKeyTrust.PinnedKey pinned = OperatorKeyTrust.loadPinnedKey(trustedFile.toFile(), pin);
            check(Arrays.equals(pinned.key().getEncoded(), trusted.getPublic().getEncoded()),
                "correctly pinned key must load");
            String expectedLegacyFingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(trustedFile)));
            check(pinned.legacyPemFingerprint().equals(expectedLegacyFingerprint),
                "legacy marker fingerprint must preserve the validated PEM bytes");

            expect("operator_trust_pin_mismatch",
                () -> OperatorKeyTrust.loadPinnedPublicKey(attackerFile.toFile(), pin));
            expect("operator_trust_pin_missing",
                () -> OperatorKeyTrust.loadPinnedPublicKey(trustedFile.toFile(), null));
            expect("operator_trust_pin_invalid",
                () -> OperatorKeyTrust.loadPinnedPublicKey(trustedFile.toFile(), "not-a-fingerprint"));

            Files.createSymbolicLink(symlinkFile, trustedFile);
            expect("operator_key_not_regular",
                () -> OperatorKeyTrust.loadPinnedPublicKey(symlinkFile.toFile(), pin));

            writeKey(tamperedFile, attacker.getPublic());
            expect("operator_trust_pin_mismatch",
                () -> OperatorKeyTrust.loadPinnedPublicKey(tamperedFile.toFile(), pin));

            System.out.println("OPERATOR_KEY_TRUST: " + checks + " checks passed");
        } finally {
            try (Stream<Path> paths = Files.walk(directory)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }
}
