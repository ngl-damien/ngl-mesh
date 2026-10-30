#!/usr/bin/env python3
"""Compile recovered Relay source and run bridge checks, using explicit inputs.
Usage: python3 integration/relay/verify_bridge.py archive.zip reference.apk report.json
No historical binaries, keystores, screenshots, or provider credentials extracted.
"""
import hashlib
import pathlib
import subprocess
import sys
import tempfile
import zipfile

ARCHIVE_SHA256 = 'd19684e39512a11caf5fdbe5dc2fb7495dc63f9e434827b6a648393c1f2b24b9'
archive, apk, report = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:4])
if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
    raise SystemExit('specification_gap: recovered source archive digest mismatch')
here = pathlib.Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='ngl-relay-bridge-') as tmp:
    root = pathlib.Path(tmp)
    source = root / 'source'
    files = []
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            p = pathlib.PurePosixPath(info.filename)
            if not info.filename.startswith(('core/src/', 'core/test/')) or p.suffix != '.java':
                continue
            if p.is_absolute() or '..' in p.parts or info.file_size > 1024 * 1024:
                raise SystemExit('unsafe_source_member')
            target = source / p
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(info))
            files.append(str(target))
    if not files:
        raise SystemExit('specification_gap: recovered Java core absent')
    classes = root / 'classes'
    subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','-d',str(classes)]
                   + sorted(files) + [
                       str(here/'RaeEvidenceBridge.java'),
                       str(here/'RaeEvidenceBridgeTest.java'),
                       str(here/'EvidenceAuthorizedTransition.java'),
                       str(here/'EvidenceAuthorizedTransitionTest.java'),
                       str(here/'OperatorKeyTrust.java'),
                       str(here/'RevocationAuthorization.java'),
                       str(here/'DurableMarker.java')
                   ], check=True)
    for suite in ['CaseStoreTest','MethodologyEngineTest','ContextBuilderTest','ProviderTransportTest']:
        subprocess.run(['java','-cp',str(classes),'ngl.relay.core.'+suite],check=True,timeout=30)
    subprocess.run(['java','-cp',str(classes),'ngl.relay.integration.RaeEvidenceBridgeTest',
                    str(apk),str(report),str(root/'test-store')],check=True,timeout=30)
    subprocess.run(['java','-cp',str(classes),'ngl.relay.integration.EvidenceAuthorizedTransitionTest',
                    str(apk),str(report),str(root/'authority-test-store')],check=True,timeout=30)
