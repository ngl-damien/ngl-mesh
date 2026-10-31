package ngl.relay.integration;

import ngl.relay.core.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;

public final class EvidenceAuthorizedTransitionTest {
    private static void check(boolean ok, String message) { if (!ok) throw new AssertionError(message); }

    private static byte[] sign(PrivateKey key, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }

    private static void writePublicKey(File file, PublicKey key) throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n"
            + java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(key.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
        Files.writeString(file.toPath(), pem, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        check(EvidenceAuthorizedTransition.isExpiredAt(100L, 100L), "grant is expired at exact expiry instant");
        check(EvidenceAuthorizedTransition.isExpiredAt(99L, 100L), "grant is expired after its deadline");
        check(!EvidenceAuthorizedTransition.isExpiredAt(101L, 100L), "grant remains valid before its deadline");
        File apk = new File(args[0]), report = new File(args[1]), base = new File(args[2]);
        CaseStore store = new CaseStore(base);
        CaseStore.CaseMeta meta = store.createCase("Authority experiment", "Evidence must not authorize itself");
        Artifact evidence = RaeEvidenceBridge.append(store, meta.caseId, apk, report);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair operator = generator.generateKeyPair();
        File publicKey = new File(base, "operator-public.pem");
        writePublicKey(publicKey, operator.getPublic());
        System.setProperty("ngl.relay.operatorKeySha256", OperatorKeyTrust.fingerprint(operator.getPublic()));
        System.setProperty("ngl.relay.allowTestOperatorKeyProperty", "true");
        File state = new File(base, "authority-state");

        // 1. Evidence by itself has no transition mechanism.
        check(store.getMeta(meta.caseId).methodologyStage == 0, "import must not advance stage");
        check(store.getMeta(meta.caseId).humanDecision == null, "import must not create decision");

        // 2. A forged/self-signed outsider key cannot authorize against operator trust root.
        KeyPair outsider = generator.generateKeyPair();
        File outsiderPublicKey = new File(base, "outsider-public.pem");
        writePublicKey(outsiderPublicKey, outsider.getPublic());
        long expiry = System.currentTimeMillis() + 60_000;
        String forgedNonce = "forged-nonce-0001";
        byte[] forgedMessage = EvidenceAuthorizedTransition.canonicalGrant(
            meta.caseId, evidence.id, evidence.hash, forgedNonce, expiry);
        try {
            EvidenceAuthorizedTransition.apply(store, meta.caseId, evidence.id, publicKey, forgedNonce, expiry,
                sign(outsider.getPrivate(), forgedMessage), state);
            throw new AssertionError("forged authority accepted");
        } catch (SecurityException expected) {
            check(expected.getMessage().contains("signature_invalid"), "forged signature rejection");
        }

        // A caller-supplied attacker key must not become its own trust root.
        String selfSignedNonce = "self-signed-key-0001";
        byte[] selfSignedMessage = EvidenceAuthorizedTransition.canonicalGrant(
            meta.caseId, evidence.id, evidence.hash, selfSignedNonce, expiry);
        try {
            EvidenceAuthorizedTransition.apply(store, meta.caseId, evidence.id, outsiderPublicKey,
                selfSignedNonce, expiry, sign(outsider.getPrivate(), selfSignedMessage), state);
            throw new AssertionError("self-selected operator key accepted");
        } catch (SecurityException expected) {
            check(expected.getMessage().contains("operator_trust_pin_mismatch"),
                "caller-selected key must fail against the configured trust pin");
        }

        // 3. Valid independent authorization permits exactly one bounded append.
        String nonce = "operator-nonce-0001";
        byte[] message = EvidenceAuthorizedTransition.canonicalGrant(
            meta.caseId, evidence.id, evidence.hash, nonce, expiry);
        byte[] signature = sign(operator.getPrivate(), message);
        Artifact consequence = EvidenceAuthorizedTransition.apply(
            store, meta.caseId, evidence.id, publicKey, nonce, expiry, signature, state);
        check(consequence.type == Artifact.Type.SYSTEM_EVENT, "bounded consequence type");
        check(consequence.parents.contains(evidence.id), "consequence must descend from evidence");
        check(store.getMeta(meta.caseId).methodologyStage == 0, "authorized append must not invent stage semantics");
        check(store.getMeta(meta.caseId).humanDecision == null, "authorized append must not invent human decision");

        // 4. Same authorization cannot be replayed.
        try {
            EvidenceAuthorizedTransition.apply(store, meta.caseId, evidence.id, publicKey, nonce, expiry, signature, state);
            throw new AssertionError("replay accepted");
        } catch (IllegalStateException expected) {
            check(expected.getMessage().contains("authority_replay"), "replay rejection");
        }

        // 5. Authorization is evidence-bound: altered evidence hash invalidates the signature.
        String wrongHash = "0" + evidence.hash.substring(1);
        String boundNonce = "operator-nonce-0002";
        byte[] wrongBinding = EvidenceAuthorizedTransition.canonicalGrant(
            meta.caseId, evidence.id, wrongHash, boundNonce, expiry);
        try {
            EvidenceAuthorizedTransition.apply(store, meta.caseId, evidence.id, publicKey, boundNonce, expiry,
                sign(operator.getPrivate(), wrongBinding), state);
            throw new AssertionError("altered evidence binding accepted");
        } catch (SecurityException expected) {
            check(expected.getMessage().contains("signature_invalid"), "evidence binding rejection");
        }

        // 6. Revocation blocks an otherwise valid unused grant.
        String revokedNonce = "operator-nonce-0003";
        byte[] revokedMessage = EvidenceAuthorizedTransition.canonicalGrant(
            meta.caseId, evidence.id, evidence.hash, revokedNonce, expiry);
        byte[] revokedSignature = sign(operator.getPrivate(), revokedMessage);
        long revocationExpiry = System.currentTimeMillis() + 60_000;
        String operatorFingerprint = OperatorKeyTrust.fingerprint(operator.getPublic());
        byte[] revocationStatement = EvidenceAuthorizedTransition.canonicalRevocation(
            operatorFingerprint, revokedNonce, revocationExpiry);
        // Reuse the outsider key from the earlier negative grant check.
        
        try {
            EvidenceAuthorizedTransition.revoke(publicKey, revokedNonce, revocationExpiry,
                sign(outsider.getPrivate(), revocationStatement), state);
            throw new AssertionError("outsider revocation accepted");
        } catch (SecurityException expected) {
            check(expected.getMessage().contains("authority_revocation_signature_invalid"),
                "outsider revocation rejection");
        }
        EvidenceAuthorizedTransition.revoke(publicKey, revokedNonce, revocationExpiry,
            sign(operator.getPrivate(), revocationStatement), state);
        try {
            EvidenceAuthorizedTransition.apply(store, meta.caseId, evidence.id, publicKey, revokedNonce, expiry,
                revokedSignature, state);
            throw new AssertionError("revoked authority accepted");
        } catch (SecurityException expected) {
            check(expected.getMessage().contains("authority_revoked"), "revocation rejection");
        }

        // 7. Expired grants fail before consequence.
        long expired = System.currentTimeMillis() - 1;
        String expiredNonce = "operator-nonce-0004";
        byte[] expiredMessage = EvidenceAuthorizedTransition.canonicalGrant(
            meta.caseId, evidence.id, evidence.hash, expiredNonce, expired);
        try {
            EvidenceAuthorizedTransition.apply(store, meta.caseId, evidence.id, publicKey, expiredNonce, expired,
                sign(operator.getPrivate(), expiredMessage), state);
            throw new AssertionError("expired authority accepted");
        } catch (IllegalArgumentException expected) {
            check(expected.getMessage().contains("authority_expired"), "expiry rejection");
        }

        check(new CaseStore(base).getArtifact(meta.caseId, consequence.id).hash.equals(consequence.hash),
            "authorized consequence persists across restart");
        check(store.audit(meta.caseId).isEmpty(), "CaseStore audit remains clean");
        System.out.println("EVIDENCE_AUTHORIZED_TRANSITION: 15 checks passed; case=" + meta.caseId);
    }
}
