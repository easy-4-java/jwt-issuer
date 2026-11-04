package io.github.easy4j.jwt;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import io.github.easy4j.jwt.token.SignedWithSecretKeyJWTRepository;
import io.jsonwebtoken.Jwts;

public class ParserCacheIsolationTest {
    @Test
    public void differentResolversWithSameHashMustNotShareParser() {
        Key first = new SecretKeySpec("0123456789abcdef0123456789abcXYZ".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        Key second = new SecretKeySpec("abcdef0123456789abcdef0123456789".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        io.jsonwebtoken.SigningKeyResolver firstResolver = fixedResolver(first);
        io.jsonwebtoken.SigningKeyResolver secondResolver = fixedResolver(second);
        assertNotSame(firstResolver, secondResolver);
        assertEquals(firstResolver.hashCode(), secondResolver.hashCode());
        io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository firstRepository =
                new io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository(firstResolver);
        io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository secondRepository =
                new io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository(secondResolver);
        firstRepository.setClock(() -> new Date(1800000000000L));
        secondRepository.setClock(() -> new Date(1800000000000L));
        String token = Jwts.builder().setSubject("test").setExpiration(new Date(1893456000000L)).signWith(first).compact();
        assertTrue(firstRepository.verify(token, true));
        assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> secondRepository.verify(token, true));
    }

    private static io.jsonwebtoken.SigningKeyResolver fixedResolver(Key key) {
        return new io.jsonwebtoken.SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(io.jsonwebtoken.JwsHeader header, io.jsonwebtoken.Claims claims) { return key; }
            @Override
            public int hashCode() { return 1234567; }
        };
    }

    @Test
    public void differentKeysWithSameHashMustNotShareParser() {
        Key first = new SecretKeySpec("0123456789abcdef0123456789abcXYZ".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        Key second = new SecretKeySpec("0313456789abcdef0123456789abcXYZ".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        assertFalse(first.equals(second));
        assertEquals(first.hashCode(), second.hashCode());
        SignedWithSecretKeyJWTRepository repository = new SignedWithSecretKeyJWTRepository();
        repository.setClock(() -> new Date(1800000000000L));
        String token = Jwts.builder().setSubject("test").setExpiration(new Date(1893456000000L)).signWith(first).compact();
        assertTrue(repository.verify(first, token, true));
        assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.verify(second, token, true));
    }
}
