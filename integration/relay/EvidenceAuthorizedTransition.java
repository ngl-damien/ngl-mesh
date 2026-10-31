package ngl.relay.integration;

import ngl.relay.core.Artifact;
import ngl.relay.core.CaseStore;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.UUID;

/**
 * NEW integration experiment; not present in the reference APK.
 *
 * Turns an already-imported RAE evidence artifact into a prerequisite for one
 * bounded consequential append. Evidence does not authorize itself: a separate
 * Ed25519 operator key must sign a canonical grant bound to case, evidence hash,
 * action, nonce and expiry. Replay and revocation state are external to CaseStore
 * and fail closed.
 */
public final class EvidenceAuthorizedTransition {
    public static final String ACTION = "append:verified-evidence-ack-v1";

    private static String canonical(String caseId, String evidenceId, String evidenceHash,
                                    String action, String nonce, long expiresAt) {
        return "ngl-evidence-authority-v1\n"
            + "case_id=" + caseId + "\n"
            + "evidence_id=" + evidenceId + "\n"
            + "evidence_hash=" + evidenceHash + "\n"
            + "action=" + action + "\n"
            + "nonce=" + nonce + "\n"
            + "expires_at=" + expiresAt + "\n";
    }

    private static boolean verify(PublicKey key, byte[] message, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    private static void requireEvidence(Artifact evidence, String caseId) {
        if (evidence == null) throw new IllegalArgumentException("evidence_missing");
        if (!caseId.equals(evidence.caseId)) throw new IllegalArgumentException("evidence_case_mismatch");
        if (evidence.type != Artifact.Type.SYSTEM_EVENT) throw new IllegalArgumentException("evidence_type_mismatch");
        if (!"rae-evidence-bridge-v1".equals(evidence.nodeId)) throw new IllegalArgumentException("evidence_origin_mismatch");
        if (!"recorded".equals(evidence.status)) throw new IllegalArgumentException("evidence_status_mismatch");
        if (evidence.content == null || !evidence.content.startsWith("RAE EVIDENCE BRIDGE v1\n"))
            throw new IllegalArgumentException("evidence_content_mismatch");
    }

    public static Artifact apply(CaseStore store, String caseId, String evidenceId,
                                 File operatorPublicKey, String nonce, long expiresAt,
                                 byte[] signature, File authorityState) throws Exception {
        CaseStore.CaseMeta meta = store.getMeta(caseId);
        if (meta == null) throw new IllegalArgumentException("case_missing");
        Artifact evidence = store.getArtifact(caseId, evidenceId);
        requireEvidence(evidence, caseId);
        if (RevocationAuthorization.isExpiredAt(expiresAt, System.currentTimeMillis()))
            throw new IllegalArgumentException("authority_expired");
        if (nonce == null || !nonce.matches("[A-Za-z0-9._-]{8,128}"))
            throw new IllegalArgumentException("authority_nonce_invalid");

        String message = canonical(caseId, evidence.id, evidence.hash, ACTION, nonce, expiresAt);
        OperatorKeyTrust.PinnedKey pinned = OperatorKeyTrust.loadPinnedKey(
            operatorPublicKey, OperatorKeyTrust.configuredFingerprint());
        if (!verify(pinned.key(), message.getBytes(StandardCharsets.UTF_8), signature))
            throw new SecurityException("authority_signature_invalid");

        String keyFingerprint = pinned.spkiFingerprint();
        if (AuthorityStateMarkers.isRevoked(authorityState, pinned, nonce))
            throw new SecurityException("authority_revoked");

        AuthorityStateMarkers.createReplay(authorityState, pinned, nonce, evidence.hash, ACTION,
            "case_id=" + caseId + "\n"
                + "evidence_id=" + evidence.id + "\n"
                + "action=" + ACTION + "\n"
                + "operator_spki_sha256=" + keyFingerprint + "\n");

        String id = UUID.nameUUIDFromBytes(("authorized-transition-v1:" + caseId + ":" + evidence.hash + ":" + nonce)
            .getBytes(StandardCharsets.UTF_8)).toString();
        Artifact event = Artifact.builder(caseId, Artifact.Type.SYSTEM_EVENT, 0).id(id)
            .provider("system").nodeId("evidence-authorized-transition-v1").status("authorized")
            .parent(evidence.id).contentType("text/plain")
            .content("AUTHORIZED EVIDENCE TRANSITION v1\n"
                + "Evidence hash=" + evidence.hash + "\n"
                + "Action=" + ACTION + "\n"
                + "Operator key fingerprint=" + keyFingerprint + "\n"
                + "Nonce=" + nonce + "\n"
                + "No methodology-stage advancement. No human decision created.\n")
            .build();
        return store.appendArtifact(caseId, event);
    }

    public static void revoke(File operatorPublicKey, String nonce, long expiresAt,
                              byte[] signature, File authorityState) throws Exception {
        RevocationAuthorization.revoke(operatorPublicKey, nonce, expiresAt, signature, authorityState);
    }

    public static byte[] canonicalRevocation(String operatorSpkiFingerprint, String nonce, long expiresAt) {
        return RevocationAuthorization.canonical(operatorSpkiFingerprint, nonce, expiresAt);
    }

    public static byte[] canonicalGrant(String caseId, String evidenceId, String evidenceHash,
                                        String nonce, long expiresAt) {
        return canonical(caseId, evidenceId, evidenceHash, ACTION, nonce, expiresAt)
            .getBytes(StandardCharsets.UTF_8);
    }
}
