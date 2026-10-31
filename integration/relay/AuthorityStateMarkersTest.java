package ngl.relay.integration;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Comparator;
import java.util.stream.Stream;

public final class AuthorityStateMarkersTest {
    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static int checks;

    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    private static void expect(String code, Checked action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected " + code);
        } catch (IllegalStateException expected) {
            check(expected.getMessage() != null && expected.getMessage().contains(code),
                "expected " + code + " but got " + expected.getMessage());
        }
    }

    private static String pem(java.security.PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
            + java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(key.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
    }

    private static void writeKey(Path path, java.security.PublicKey key, boolean alternate) throws Exception {
        String contents = pem(key);
        if (alternate) contents = contents.replace("\n", "\r\n");
        Files.writeString(path, contents, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("ngl-authority-marker-identity-");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            KeyPair operator = generator.generateKeyPair();
            Path originalFile = root.resolve("operator.pem");
            Path alternateFile = root.resolve("operator-reformatted.pem");
            writeKey(originalFile, operator.getPublic(), false);
            writeKey(alternateFile, operator.getPublic(), true);

            String pin = OperatorKeyTrust.fingerprint(operator.getPublic());
            OperatorKeyTrust.PinnedKey original = OperatorKeyTrust.loadPinnedKey(originalFile.toFile(), pin);
            OperatorKeyTrust.PinnedKey alternate = OperatorKeyTrust.loadPinnedKey(alternateFile.toFile(), pin);
            check(original.spkiFingerprint().equals(alternate.spkiFingerprint()),
                "same DER public key retains one stable SPKI fingerprint");
            check(!original.legacyPemFingerprint().equals(alternate.legacyPemFingerprint()),
                "alternate PEM line endings change the legacy byte fingerprint");

            File state = root.resolve("authority").toFile();
            String revokedNonce = "revocation-stable-0001";
            AuthorityStateMarkers.createRevocation(state, original, revokedNonce);
            check(AuthorityStateMarkers.isRevoked(state, original, revokedNonce),
                "new revocation blocks the original PEM representation");
            check(AuthorityStateMarkers.isRevoked(state, alternate, revokedNonce),
                "new revocation remains effective after PEM reserialization");
            expect("authority_revocation_marker_exists",
                () -> AuthorityStateMarkers.createRevocation(state, alternate, revokedNonce));
            try (Stream<Path> files = Files.list(root.resolve("authority").resolve("revoked"))) {
                check(files.count() == 2, "new revocation dual-writes stable and legacy markers");
            }

            String legacyNonce = "revocation-legacy-0002";
            String legacyRevocation = AuthorityStateMarkers.legacyRevocationId(
                original.legacyPemFingerprint(), legacyNonce);
            DurableMarker.create(new File(state, "revoked"), legacyRevocation,
                "revoked\n", "authority_revocation_marker_exists");
            check(AuthorityStateMarkers.isRevoked(state, original, legacyNonce),
                "an existing legacy revocation is still recognized");
            String stableRevocation = AuthorityStateMarkers.stableRevocationId(
                original.spkiFingerprint(), legacyNonce);
            check(DurableMarker.exists(new File(state, "revoked"), stableRevocation),
                "legacy revocation lookup durably migrates the stable SPKI marker");
            check(AuthorityStateMarkers.isRevoked(state, alternate, legacyNonce),
                "a migrated legacy revocation survives later PEM reserialization");

            String evidenceHash = "a".repeat(64);
            String action = "append:verified-evidence-ack-v1";
            String replayNonce = "replay-stable-0003";
            AuthorityStateMarkers.createReplay(state, original, replayNonce, evidenceHash, action,
                "case_id=case-1\nevidence_hash=" + evidenceHash + "\n");
            check(AuthorityStateMarkers.isReplay(state, original, replayNonce, evidenceHash, action),
                "new replay marker blocks the original PEM representation");
            check(AuthorityStateMarkers.isReplay(state, alternate, replayNonce, evidenceHash, action),
                "new replay marker remains effective after PEM reserialization");
            expect("authority_replay",
                () -> AuthorityStateMarkers.createReplay(state, alternate, replayNonce, evidenceHash, action,
                    "duplicate\n"));

            String legacyReplayNonce = "replay-legacy-0004";
            String legacyReplay = AuthorityStateMarkers.legacyReplayId(
                original.legacyPemFingerprint(), legacyReplayNonce, evidenceHash, action);
            DurableMarker.create(new File(state, "used"), legacyReplay,
                "legacy replay\n", "authority_replay");
            check(AuthorityStateMarkers.isReplay(state, original, legacyReplayNonce, evidenceHash, action),
                "an existing legacy replay marker is still recognized");
            String stableReplay = AuthorityStateMarkers.stableReplayId(
                original.spkiFingerprint(), legacyReplayNonce, evidenceHash, action);
            check(DurableMarker.exists(new File(state, "used"), stableReplay),
                "legacy replay lookup durably migrates the stable SPKI marker");
            check(AuthorityStateMarkers.isReplay(state, alternate, legacyReplayNonce, evidenceHash, action),
                "a migrated legacy replay survives later PEM reserialization");

            System.out.println("AUTHORITY_STATE_MARKERS: " + checks + " checks passed");
        } finally {
            try (Stream<Path> paths = Files.walk(root)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }
}
