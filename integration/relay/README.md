# Relay / RAE evidence bridge

**Status: NEW, executable host integration. Not part of the reference APK.**

The reference APK was independently recovered and matched to the anchor:

- 49,651 bytes
- SHA-256 `6cee7b1ea12c435cc7705510b5d61c85c63764dcd9658a00b6ea99c2311e9ffe`
- 7 ZIP members, 71 DEX class definitions, 986 unique DEX strings
- All 27 explicit RAE reference predicates verified

The recovered Java source archive has SHA-256
`d19684e39512a11caf5fdbe5dc2fb7495dc63f9e434827b6a648393c1f2b24b9`.
The archive and APK are operator-supplied inputs and are not published here.
Matching source names is not a reproducible-build proof linking that source to
the APK. The core was independently compiled and its four existing test suites
passed 131 checks. Provider transport tests use local HTTP fixtures, not live AI
services.

## Reproduce

Requires Python 3.12, Java 17 with the `jdk.compiler` module, Node.js 20+, and the
RAE `work/verified-runtime` implementation. First produce a fresh report:

```sh
node /path/to/recursive-artifact-engine/src/cli.js inspect /path/to/NGL_BUS.apk --format apk --claims /path/to/recursive-artifact-engine/integration/relay-claims.json > /path/to/report.json
python3 integration/relay/verify_bridge.py /path/to/recovered-source.zip /path/to/NGL_BUS.apk /path/to/report.json
```

The harness pins the recovered archive by hash, extracts only Java core/test
source, compiles it with the new bridge, runs the 131 recovered checks and the
11 bridge checks, and deletes its temporary test store. Missing or mismatched
source is a `specification_gap`. It does not execute historical build scripts,
use archived binaries or keystores, or contact real providers.

## Operator-key trust boundary

The authority transition requires a separately provisioned SHA-256 fingerprint
of the operator's DER SubjectPublicKeyInfo. Configure
`NGL_RELAY_OPERATOR_KEY_SHA256` in the trusted host environment before accepting
requests. A JVM system property named `ngl.relay.operatorKeySha256` is a
test/development fallback only. Never derive either value from the incoming
request or from the supplied public-key file. Missing, malformed, or mismatched
pins fail closed. The trust pin uses DER SubjectPublicKeyInfo, while replay and
revocation markers retain the legacy SHA-256 of the validated PEM bytes so existing
local marker state is not silently invalidated. Do not reformat the key file without
a separate marker migration.

The isolated trust-pin regression can run without the recovered APK/source/report:

```sh
mkdir -p /tmp/ngl-operator-key-trust
javac -d /tmp/ngl-operator-key-trust integration/relay/OperatorKeyTrust.java integration/relay/OperatorKeyTrustTest.java
java -cp /tmp/ngl-operator-key-trust ngl.relay.integration.OperatorKeyTrustTest
```

The broader bridge harness still requires the recovered-source archive, reference
APK, and RAE report described above. A passing isolated test does not replace
that integration run or prove real-world operator identity.

## Integration contract

`RaeEvidenceBridge.append(store, existingCaseId, apk, report)`:

1. Requires an existing case and preserves its original input parent.
2. Independently reads the APK and checks exact reference identity.
3. Requires the report's artifact identity to match those independently read bytes.
4. Appends a system event containing the original report and its own content hash.
5. Preserves the original CaseStore persistence, UUID format, append ordering and
   hash checking. A scoped deterministic UUID rejects identical report imports.
6. Never advances methodology stages or creates a human decision. It labels
   imported extraction claims as external, not locally re-extracted truth.
7. Appends error evidence for rejected imports when the existing store can write.

The bridge checks APK identity itself; DEX parsing remains in RAE. A forged
report about the correct APK is still imported only as external data. It cannot
authorize a command. The RAE host runtime separately requires signed,
operation-specific grants for its build execution.

## Limits

The public control-surface JSON Schema remains a representation contract.
RAE enforces a narrow executable subset: pinned plans, signed grants, expiry,
replay rejection, revocation and a fixed dispatcher. This does not certify every
sovereignty rule for Android, connectors or arbitrary host processes.

No Android APK has been rebuilt or installed in this change. No provider model
has been called. There is no source/APK behavioral-equivalence proof. The next
integration boundary is to invoke this bridge from a recovered Android source
build and test import/restart behavior on a device, retaining the current APK
as the reference.
