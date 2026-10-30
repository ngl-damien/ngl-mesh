# ngl-mesh

## Mandatory agent instructions

Every AI agent and automated contributor must read [AGENTS.md](AGENTS.md) before acting. It points to the shared NGL operating protocol and repository-specific evidence constraints. A GitHub Actions check verifies that the required entry points remain present.

**Sovereign Android cognition fabric** recovered and staged from the NGL archaeological trail.

## Lineage (historical record; evidence levels differ)

| Artifact | Role | Evidence |
|----------|------|----------|
| `NGL_BUS.apk` / `NGL_RELAY_v1.apk` | Kernel relay client | 49,651 B; SHA-256 `6cee7b1ea12c435cc7705510b5d61c85c63764dcd9658a00b6ea99c2311e9ffe`; package `ngl.relay.*`; 5-stage MethodologyEngine; multi-provider HTTP |
| Drive `apk.zip` handoff 2026-09-13 | Mesh evolution source | 26+ main Kotlin files; Room substrate; Compose terminal; RPG realm; Cognition fabric; 162 unit tests claimed in XML evidence |
| GitHub `ai-guild-hardened-v0.2` | Capacitor shell only | `com.nogaslabs.ops` BridgeActivity — not the cognition kernel |

## Executable evidence bridge (new development)

`integration/relay/` now provides a Java bridge tested against recovered Relay
source. It independently rereads the reference APK's bytes, checks the pinned
digest and length, and appends an externally generated RAE report to the original
`CaseStore` as a `SYSTEM_EVENT`. It preserves parents, stages, human decisions,
duplicate rejection and failure evidence. Imported extraction claims grant no
execution authority. See [the integration instructions](integration/relay/README.md).

This is not an Android rebuild or a full mesh runtime. The Kotlin/Compose/Room
architecture below remains inferred from historical material, not implemented
in this checkout. The recovered Java Relay core uses UUID artifact identities
and separate SHA-256 content hashes; it must not be silently replaced by an
assumed content-addressed identity scheme.

## Architecture (INFERRED from recovered source)

```
TERMINAL UI (Compose)
    ↓
MethodologyEngine (5 stages: Independent → Cross → Iterative → Deliberation → Synthesis)
    ↓
Cognition Fabric / ExecutionFabric
    ↓
Adapters: OpenAI · Anthropic · xAI · Google · HuggingFace
    ↓
ArtifactStore + ProvenanceService + Room substrate
    ↓
Optional native libngl_engine.so
```

Human decisions and failures are first-class artifacts. Synthesis is labeled not verified truth.

## Installable APK (this campaign)

**File:** `NGL_RELAY_v1.apk` (identical bytes to `NGL_BUS.apk`)  
**SHA-256:** `6cee7b1ea12c435cc7705510b5d61c85c63764dcd9658a00b6ea99c2311e9ffe`  
**Size:** 49,651 bytes  
**Signer:** NGL Relay Self-Signed  
**Device status:** Operator-reported sideload success (ChatGPT key configured)

Full mesh APK (`ngl-mesh-debug` ~17 MB, sha256 `ffe8209f…` per handoff) was **not** present in the Drive package and could not be reassembled in this environment (Gradle resource merge I/O errors after SDK restore). Source + Gradle scaffold staged under campaign artifacts.

## Build (PROPOSED resume)

```bash
# Requires Android SDK 34, JDK 17+, Gradle 8.7
cd ngl-mesh-build
echo "sdk.dir=$ANDROID_HOME" > local.properties
gradle assembleDebug
```

## What another builder must know

1. Strongest coherent lineage is **Relay kernel → Mesh terminal**, not the Capacitor ops shell.
2. Do not promote README claims or test XML counts to VERIFIED without re-running tests.
3. Live provider calls stay UNVERIFIED until keys exist on device.
4. Preserve MethodologyEngine stage invariants and provenance parents.
