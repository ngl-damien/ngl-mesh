package ngl.relay.integration;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Comparator;
import java.util.stream.Stream;

public final class RevocationAuthorizationTest {
    private static int checks;
    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void expect(String code, Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected " + code); }
        catch (IllegalArgumentException | SecurityException expected) {
            check(expected.getMessage() != null && expected.getMessage().contains(code),
                "expected " + code + " but got " + expected.getMessage());
        }
    }
    private static byte[] sign(java.security.PrivateKey key, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }
    private static void writePublicKey(Path path, java.security.PublicKey key) throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
            + java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(key.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
        Files.writeString(path, pem, StandardCharsets.UTF_8);
    }
    public static void main(String[] args) throws Exception {
        check(RevocationAuthorization.isExpiredAt(100L, 100L), "revocation is expired at exact expiry instant");
        check(RevocationAuthorization.isExpiredAt(99L, 100L), "revocation is expired after its deadline");
        check(!RevocationAuthorization.isExpiredAt(101L, 100L), "revocation remains valid before its deadline");
        String oldPin = System.getProperty("ngl.relay.operatorKeySha256");
        String oldOptIn = System.getProperty("ngl.relay.allowTestOperatorKeyProperty");
        Path root = Files.createTempDirectory("ngl-revocation-auth-");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            KeyPair operator = generator.generateKeyPair();
            KeyPair outsider = generator.generateKeyPair();
            Path keyPath = root.resolve("operator.pem");
            writePublicKey(keyPath, operator.getPublic());
            System.setProperty("ngl.relay.operatorKeySha256", OperatorKeyTrust.fingerprint(operator.getPublic()));
            System.setProperty("ngl.relay.allowTestOperatorKeyProperty", "true");

            File authority = root.resolve("authority").toFile();
            String fingerprint = OperatorKeyTrust.fingerprint(operator.getPublic());
            long future = System.currentTimeMillis() + 60_000;
            String nonce = "revocation-nonce-0001";
            byte[] statement = RevocationAuthorization.canonical(fingerprint, nonce, future);

            expect("authority_revocation_signature_invalid", () ->
                RevocationAuthorization.revoke(keyPath.toFile(), nonce, future,
                    sign(outsider.getPrivate(), statement), authority));
            check(!Files.exists(root.resolve("authority/revoked")),
                "invalid signature must not create revocation state");

            RevocationAuthorization.revoke(keyPath.toFile(), nonce, future,
                sign(operator.getPrivate(), statement), authority);
            Path revoked = root.resolve("authority/revoked");
            check(Files.isDirectory(revoked), "authorized revocation directory exists");
            try (Stream<Path> files = Files.list(revoked)) {
                check(files.count() == 1, "one authorized marker is persisted");
            }

            try {
                RevocationAuthorization.revoke(keyPath.toFile(), nonce, future,
                    sign(operator.getPrivate(), statement), authority);
                throw new AssertionError("duplicate revocation accepted");
            } catch (IllegalStateException expected) {
                check(expected.getMessage().contains("authority_revocation_marker_exists"),
                    "duplicate revocation is rejected");
            }

            long expired = System.currentTimeMillis() - 1;
            String expiredNonce = "revocation-nonce-0002";
            byte[] expiredStatement = RevocationAuthorization.canonical(fingerprint, expiredNonce, expired);
            expect("authority_expired", () -> RevocationAuthorization.revoke(keyPath.toFile(),
                expiredNonce, expired, sign(operator.getPrivate(), expiredStatement), authority));

            expect("authority_nonce_invalid", () ->
                RevocationAuthorization.canonical(fingerprint, "short", future));
            expect("authority_fingerprint_invalid", () ->
                RevocationAuthorization.canonical("not-a-fingerprint", nonce, future));

            String otherNonce = "revocation-nonce-0003";
            byte[] otherStatement = RevocationAuthorization.canonical(fingerprint, otherNonce, future);
            expect("authority_revocation_signature_invalid", () -> RevocationAuthorization.revoke(
                keyPath.toFile(), "revocation-nonce-0004", future,
                sign(operator.getPrivate(), otherStatement), authority));

            System.out.println("REVOCATION_AUTHORIZATION: " + checks + " checks passed");
        } finally {
            if (oldPin == null) System.clearProperty("ngl.relay.operatorKeySha256");
            else System.setProperty("ngl.relay.operatorKeySha256", oldPin);
            if (oldOptIn == null) System.clearProperty("ngl.relay.allowTestOperatorKeyProperty");
            else System.setProperty("ngl.relay.allowTestOperatorKeyProperty", oldOptIn);
            try (Stream<Path> paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            }
        }
    }
}
