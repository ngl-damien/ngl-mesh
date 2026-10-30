package ngl.relay.integration;

import ngl.relay.core.Artifact;
import ngl.relay.core.CaseStore;
import ngl.relay.core.CoreJson;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/** NEW host/Android-compatible bridge; not present in the reference APK.
 * Independently checks APK identity. Imported extraction reports remain external
 * evidence, never human decisions, authority grants or proven runtime behavior.
 */
public final class RaeEvidenceBridge {
    public static final String REFERENCE_SHA256 = "6cee7b1ea12c435cc7705510b5d61c85c63764dcd9658a00b6ea99c2311e9ffe";
    public static final int REFERENCE_LENGTH = 49651;

    private static byte[] read(File file, int limit) throws IOException {
        if (!file.isFile() || file.length() > limit) throw new IOException("input_not_regular_or_too_large");
        try (InputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096]; int count;
            while ((count = in.read(buffer)) != -1) {
                if (out.size() + count > limit) throw new IOException("input_limit");
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        }
    }

    private static String sha(byte[] bytes) throws Exception {
        StringBuilder out = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bytes))
            out.append(Character.forDigit((b >>> 4) & 15, 16)).append(Character.forDigit(b & 15, 16));
        return out.toString();
    }

    public static Artifact append(CaseStore store, String caseId, File apk, File report) throws Exception {
        CaseStore.CaseMeta meta = store.getMeta(caseId);
        if (meta == null) throw new IllegalArgumentException("case_missing");
        try { return appendChecked(store, meta, apk, report); }
        catch (Exception failure) {
            store.appendArtifact(caseId, Artifact.builder(caseId, Artifact.Type.ERROR, 0).provider("system")
                .status("error").error(failure.getMessage()).parent(meta.originalInputArtifactId)
                .content("RAE bridge rejected import: " + failure.getMessage()).build());
            throw failure;
        }
    }

    private static Artifact appendChecked(CaseStore store, CaseStore.CaseMeta meta, File apk, File report) throws Exception {
        String caseId = meta.caseId;
        byte[] bytes = read(apk, REFERENCE_LENGTH);
        String apkHash = sha(bytes);
        if (bytes.length != REFERENCE_LENGTH || !REFERENCE_SHA256.equals(apkHash)) {
            throw new IllegalArgumentException("reference_identity_mismatch");
        }
        byte[] reportBytes = read(report, 16 * 1024 * 1024);
        String reportText = StrictUtf8.decode(reportBytes);
        CoreJson.JObject root = CoreJson.parseObject(reportText);
        CoreJson.JObject observed = root.getObject("observation");
        CoreJson.JObject artifact = observed == null ? null : observed.getObject("artifact");
        if (artifact == null || !apkHash.equals(artifact.get("sha256"))
            || artifact.getNum("byte_length", -1) != bytes.length) throw new IllegalArgumentException("report_artifact_mismatch");
        String reportHash = sha(reportBytes);
        // Scoped deterministic UUID prevents identical reports from being appended twice.
        String id = UUID.nameUUIDFromBytes(("rae-import-v1:" + caseId + ":" + apkHash + ":" + reportHash)
            .getBytes(StandardCharsets.UTF_8)).toString();
        String content = "RAE EVIDENCE BRIDGE v1\n"
            + "Independent observation: APK sha256=" + apkHash + "; bytes=" + bytes.length + "\n"
            + "External report sha256=" + reportHash + "\n"
            + "Extraction claims below are imported, not independently re-extracted by this Java bridge.\n"
            + "No execution authority granted. No human decision created.\n\n" + reportText;
        Artifact event = Artifact.builder(caseId, Artifact.Type.SYSTEM_EVENT, 0).id(id)
            .provider("system").nodeId("rae-evidence-bridge-v1").status("recorded")
            .parent(meta.originalInputArtifactId).contentType("text/plain").content(content).build();
        return store.appendArtifact(caseId, event);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("Usage: <store-base> <existing-case-id> <reference.apk> <report.json>");
        System.out.println(append(new CaseStore(new File(args[0])), args[1], new File(args[2]), new File(args[3])).toJson());
    }
}
