package ngl.relay.integration;

import java.io.File;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Stable, domain-separated replay/revocation marker identities.
 *
 * New markers are keyed by the pinned DER SubjectPublicKeyInfo fingerprint.
 * Legacy PEM-byte markers are dual-written for older code and migrated to the
 * stable identity on first lookup with the original key bytes.
 */
final class AuthorityStateMarkers {
    private static final String REVOCATION_DOMAIN = "ngl-relay-revocation-marker-v2\n";
    private static final String REPLAY_DOMAIN = "ngl-relay-replay-marker-v2\n";

    private AuthorityStateMarkers() {}

    private static String sha(String value) throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    private static void requireState(File authorityState) {
        if (authorityState == null) throw new IllegalArgumentException("authority_state_missing");
    }

    private static void requirePinned(OperatorKeyTrust.PinnedKey pinned) throws Exception {
        if (pinned == null || pinned.key() == null
                || pinned.spkiFingerprint() == null || !pinned.spkiFingerprint().matches("[a-f0-9]{64}")
                || pinned.legacyPemFingerprint() == null || !pinned.legacyPemFingerprint().matches("[a-f0-9]{64}")) {
            throw new SecurityException("authority_key_invalid");
        }
        String actual = OperatorKeyTrust.fingerprint(pinned.key());
        if (!MessageDigest.isEqual(
                actual.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                pinned.spkiFingerprint().getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            throw new SecurityException("authority_key_fingerprint_mismatch");
        }
    }

    private static void requireNonce(String nonce) {
        if (nonce == null || !nonce.matches("[A-Za-z0-9._-]{8,128}"))
            throw new IllegalArgumentException("authority_nonce_invalid");
    }

    static String stableRevocationId(String spkiFingerprint, String nonce) throws Exception {
        if (spkiFingerprint == null || !spkiFingerprint.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("authority_fingerprint_invalid");
        requireNonce(nonce);
        return sha(REVOCATION_DOMAIN + spkiFingerprint + "\n" + nonce + "\n");
    }

    static String legacyRevocationId(String legacyPemFingerprint, String nonce) throws Exception {
        if (legacyPemFingerprint == null || !legacyPemFingerprint.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("authority_fingerprint_invalid");
        requireNonce(nonce);
        // Preserve the exact pre-v2 identifier so existing local state remains readable.
        return sha("revoke\n" + legacyPemFingerprint + "\n" + nonce);
    }

    static String stableReplayId(String spkiFingerprint, String nonce, String evidenceHash, String action)
            throws Exception {
        if (spkiFingerprint == null || !spkiFingerprint.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("authority_fingerprint_invalid");
        requireNonce(nonce);
        if (evidenceHash == null || !evidenceHash.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("authority_evidence_hash_invalid");
        if (action == null || !action.matches("[A-Za-z0-9:._-]{1,128}"))
            throw new IllegalArgumentException("authority_action_invalid");
        return sha(REPLAY_DOMAIN + spkiFingerprint + "\n" + nonce + "\n" + evidenceHash + "\n" + action + "\n");
    }

    static String legacyReplayId(String legacyPemFingerprint, String nonce, String evidenceHash, String action)
            throws Exception {
        if (legacyPemFingerprint == null || !legacyPemFingerprint.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("authority_fingerprint_invalid");
        requireNonce(nonce);
        if (evidenceHash == null || !evidenceHash.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("authority_evidence_hash_invalid");
        if (action == null || !action.matches("[A-Za-z0-9:._-]{1,128}"))
            throw new IllegalArgumentException("authority_action_invalid");
        // Preserve the exact pre-v2 identifier so existing local state remains readable.
        return sha(legacyPemFingerprint + "\n" + nonce + "\n" + evidenceHash + "\n" + action);
    }

    static boolean isRevoked(File authorityState, OperatorKeyTrust.PinnedKey pinned, String nonce)
            throws Exception {
        requireState(authorityState);
        requirePinned(pinned);
        requireNonce(nonce);
        File directory = new File(authorityState, "revoked");
        String stableId = stableRevocationId(pinned.spkiFingerprint(), nonce);
        if (DurableMarker.exists(directory, stableId)) return true;

        String legacyId = legacyRevocationId(pinned.legacyPemFingerprint(), nonce);
        if (!DurableMarker.exists(directory, legacyId)) return false;

        // Upgrade a legacy marker before returning the revoked result. If the
        // upgrade cannot be durably recorded, the caller fails closed.
        migrate(directory, stableId, "revoked\n", "authority_revocation_marker_exists");
        return true;
    }

    static void createRevocation(File authorityState, OperatorKeyTrust.PinnedKey pinned, String nonce)
            throws Exception {
        requireState(authorityState);
        requirePinned(pinned);
        requireNonce(nonce);
        if (isRevoked(authorityState, pinned, nonce))
            throw new IllegalStateException("authority_revocation_marker_exists");

        File directory = new File(authorityState, "revoked");
        // Write the legacy ID first so older versions also fail closed if this
        // process stops between the two durable marker creations.
        DurableMarker.create(directory,
            legacyRevocationId(pinned.legacyPemFingerprint(), nonce),
            "revoked\n", "authority_revocation_marker_exists");
        DurableMarker.create(directory,
            stableRevocationId(pinned.spkiFingerprint(), nonce),
            "revoked\n", "authority_revocation_marker_exists");
    }

    static boolean isReplay(File authorityState, OperatorKeyTrust.PinnedKey pinned,
                            String nonce, String evidenceHash, String action) throws Exception {
        requireState(authorityState);
        requirePinned(pinned);
        File directory = new File(authorityState, "used");
        String stableId = stableReplayId(pinned.spkiFingerprint(), nonce, evidenceHash, action);
        if (DurableMarker.exists(directory, stableId)) return true;

        String legacyId = legacyReplayId(pinned.legacyPemFingerprint(), nonce, evidenceHash, action);
        if (!DurableMarker.exists(directory, legacyId)) return false;

        migrate(directory, stableId, "replay marker migrated from legacy PEM identity\n", "authority_replay");
        return true;
    }

    static void createReplay(File authorityState, OperatorKeyTrust.PinnedKey pinned,
                             String nonce, String evidenceHash, String action, String value) throws Exception {
        requireState(authorityState);
        requirePinned(pinned);
        if (value == null || value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 4096)
            throw new IllegalArgumentException("authority_marker_invalid");
        if (isReplay(authorityState, pinned, nonce, evidenceHash, action))
            throw new IllegalStateException("authority_replay");

        File directory = new File(authorityState, "used");
        DurableMarker.create(directory,
            legacyReplayId(pinned.legacyPemFingerprint(), nonce, evidenceHash, action),
            value, "authority_replay");
        DurableMarker.create(directory,
            stableReplayId(pinned.spkiFingerprint(), nonce, evidenceHash, action),
            value, "authority_replay");
    }

    private static void migrate(File directory, String stableId, String value, String conflictCode)
            throws Exception {
        try {
            DurableMarker.create(directory, stableId, value, conflictCode);
        } catch (IllegalStateException conflict) {
            if (!DurableMarker.exists(directory, stableId)) throw conflict;
        }
    }
}
