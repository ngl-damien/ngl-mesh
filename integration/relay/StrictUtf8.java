package ngl.relay.integration;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Strict UTF-8 decoding for evidence bytes whose digest is retained separately. */
public final class StrictUtf8 {
    private StrictUtf8() {}

    public static String decode(byte[] bytes) {
        if (bytes == null) throw new IllegalArgumentException("invalid_utf8");
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException("invalid_utf8", error);
        }
    }
}
