package ngl.relay.integration;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class EvidenceAuthorizedTransitionSourceTest {
    private static int checks;

    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Usage: <EvidenceAuthorizedTransition.java>");
        String source = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        check(source.contains("AuthorityStateMarkers.isRevoked(authorityState, pinned, nonce)"),
            "the transition must check stable and legacy revocation markers through the shared helper");
        check(source.contains("AuthorityStateMarkers.createReplay(authorityState, pinned, nonce, evidence.hash, ACTION"),
            "the transition must create stable and legacy replay markers through the shared helper");
        check(source.contains("pinned.spkiFingerprint()"),
            "the recorded operator identity must be the stable SPKI fingerprint");
        check(!source.contains("legacyPemFingerprint()"),
            "the transition must not derive canonical replay identity from PEM formatting");
        System.out.println("EVIDENCE_AUTHORIZED_TRANSITION_SOURCE: " + checks + " checks passed");
    }
}
