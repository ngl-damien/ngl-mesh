package ngl.relay.integration;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.HexFormat;

/** Operator-signed, domain-separated revocation for one authority nonce. */
public final class RevocationAuthorization {
    private RevocationAuthorization() {}

    public static byte[] canonical(String operatorSpkiFingerprint, String nonce, long expiresAt) {
        if (operatorSpkiFingerprint == null || !operatorSpkiFingerprint.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("authority_fingerprint_invalid");
        if (nonce == null || !nonce.matches("[A-Za-z0-9._-]{8,128}"))
            throw new IllegalArgumentException("authority_nonce_invalid");
        if (expiresAt < 0) throw new IllegalArgumentException("authority_expiry_invalid");
        return ("ngl-evidence-revocation-v1\n"
            + "operator_spki_sha256=" + operatorSpkiFingerprint + "\n"
            + "nonce=" + nonce + "\n"
            + "expires_at=" + expiresAt + "\n").getBytes(StandardCharsets.UTF_8);
    }

    private static boolean verify(java.security.PublicKey key, byte[] statement, byte[] signature)
            throws GeneralSecurityException {
        if (signature == null) return false;
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(statement);
        return verifier.verify(signature);
    }

    private static String sha(String value) throws GeneralSecurityException {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    public static void revoke(File operatorPublicKey, String nonce, long expiresAt,
                              byte[] signature, File authorityState) throws Exception {
        if (nonce == null || !nonce.matches("[A-Za-z0-9._-]{8,128}"))
            throw new IllegalArgumentException("authority_nonce_invalid");
        if (expiresAt < System.currentTimeMillis())
            throw new IllegalArgumentException("authority_expired");
        if (authorityState == null) throw new IllegalArgumentException("authority_state_missing");

        OperatorKeyTrust.PinnedKey pinned = OperatorKeyTrust.loadPinnedKey(
            operatorPublicKey, OperatorKeyTrust.configuredFingerprint());
        byte[] statement = canonical(pinned.spkiFingerprint(), nonce, expiresAt);
        if (!verify(pinned.key(), statement, signature))
            throw new SecurityException("authority_revocation_signature_invalid");

        // Preserve the established marker identifier so existing revocation
        // state remains effective after requiring signatures for new requests.
        String marker = sha("revoke\n" + pinned.legacyPemFingerprint() + "\n" + nonce);
        DurableMarker.create(new File(authorityState, "revoked"), marker,
            "revoked\n", "authority_revocation_marker_exists");
    }
}
