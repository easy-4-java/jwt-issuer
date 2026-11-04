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
        String otherToken = Jwts.builder().setSubject("other").setExpiration(new Date(1893456000000L)).signWith(second).compact();
        for (boolean expiry : new boolean[] {true, false}) {
            assertTrue(firstRepository.verify(token, expiry));
            assertEquals("test", firstRepository.getPlayload(token, expiry).getSubject());
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> secondRepository.verify(token, expiry));
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> secondRepository.getPlayload(token, expiry));
            assertTrue(secondRepository.verify(otherToken, expiry));
            assertEquals("other", secondRepository.getPlayload(otherToken, expiry).getSubject());
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> firstRepository.verify(otherToken, expiry));
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> firstRepository.getPlayload(otherToken, expiry));
        }
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
        String otherToken = Jwts.builder().setSubject("other").setExpiration(new Date(1893456000000L)).signWith(second).compact();
        for (boolean expiry : new boolean[] {true, false}) {
            assertTrue(repository.verify(first, token, expiry));
            assertEquals("test", repository.getPlayload(first, token, expiry).getSubject());
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.verify(second, token, expiry));
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.getPlayload(second, token, expiry));
            assertTrue(repository.verify(second, otherToken, expiry));
            assertEquals("other", repository.getPlayload(second, otherToken, expiry).getSubject());
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.verify(first, otherToken, expiry));
            assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.getPlayload(first, otherToken, expiry));
        }
    }
    @Test
    public void changingResolverRejectsTokensSignedWithPreviousKey() {
        Key previous = new SecretKeySpec("previous-test-key-0123456789abcdef".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        Key replacement = new SecretKeySpec("replacement-test-key-0123456789ab".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository repository =
                new io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository(fixedResolver(previous));
        repository.setClock(() -> new Date(1800000000000L));
        String oldToken = Jwts.builder().setSubject("test").setExpiration(new Date(1893456000000L)).signWith(previous).compact();
        assertTrue(repository.verify(oldToken, true));
        assertTrue(repository.verify(oldToken, false));
        repository.setSigningKeyResolver(fixedResolver(replacement));
        assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.verify(oldToken, true));
        assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.verify(oldToken, false));
        assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.getPlayload(oldToken, true));
        assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> repository.getPlayload(oldToken, false));
        String newToken = Jwts.builder().setSubject("test").setExpiration(new Date(1893456000000L)).signWith(replacement).compact();
        assertTrue(repository.verify(newToken, true));
        assertTrue(repository.verify(newToken, false));
    }

    @Test
    public void missingKeyAndResolverKeepNullPointerExceptionContract() {
        SignedWithSecretKeyJWTRepository direct = new SignedWithSecretKeyJWTRepository();
        io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository resolverRepository =
                new io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository();
        for (boolean expiry : new boolean[] {true, false}) {
            assertThrows(NullPointerException.class, () -> direct.getJwtParser(null, expiry));
            assertThrows(NullPointerException.class, () -> resolverRepository.getJwtParser(null, expiry));
        }
    }

}
