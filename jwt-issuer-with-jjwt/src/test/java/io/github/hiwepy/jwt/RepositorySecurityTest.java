package io.github.easy4j.jwt;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import io.github.easy4j.jwt.exception.ExpiredJwtException;
import io.github.easy4j.jwt.exception.IncorrectJwtException;
import io.github.easy4j.jwt.exception.InvalidJwtToken;
import io.github.easy4j.jwt.exception.JwtException;
import io.github.easy4j.jwt.token.SignedWithSecretKeyJWTRepository;
import io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.security.SignatureException;

/** Offline contract tests. All keys are public, non-production test fixtures. */
@RunWith(Parameterized.class)
public class RepositorySecurityTest {
    private static final long NOW = 1893456000000L;
    private static final Key KEY = key("0123456789abcdef0123456789abcdef");
    private static final Key WRONG_KEY = key("abcdef0123456789abcdef0123456789");
    private final boolean resolveKey;
    private SignedWithSecretKeyJWTRepository direct;
    private SignedWithSecretResolverJWTRepository resolver;

    @Parameterized.Parameters(name = "resolver={0}")
    public static Iterable<Object[]> implementations() {
        return Arrays.asList(new Object[][] {{false}, {true}});
    }

    public RepositorySecurityTest(boolean resolveKey) { this.resolveKey = resolveKey; }

    @Before
    public void configure() {
        direct = new SignedWithSecretKeyJWTRepository();
        direct.setClock(() -> new Date(NOW));
        resolver = new SignedWithSecretResolverJWTRepository(new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                assertEquals("test-key", header.getKeyId());
                return KEY;
            }
        });
        resolver.setClock(() -> new Date(NOW));
    }

    private static Key key(String value) {
        return new SecretKeySpec(value.getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
    }

    private String token(Key key, long expiry, Long notBefore) {
        io.jsonwebtoken.JwtBuilder builder = Jwts.builder().setHeaderParam("kid", "test-key")
                .setId("test-id").setSubject("alice").setIssuer("test-issuer").setAudience("test-audience")
                .setIssuedAt(new Date(NOW - 10000)).setExpiration(new Date(expiry));
        if (notBefore != null) { builder.setNotBefore(new Date(notBefore)); }
        return builder.signWith(key, SignatureAlgorithm.HS256).compact();
    }

    private boolean verify(String token, boolean expiry) {
        return resolveKey ? resolver.verify(token, expiry) : direct.verify(KEY, token, expiry);
    }

    private JwtPayload payload(String token, boolean expiry) {
        return resolveKey ? resolver.getPlayload(token, expiry) : direct.getPlayload(KEY, token, expiry);
    }

    @Test
    public void issuesSignedTokenAndPreservesClaimsAndMillisecondTtl() {
        String token = resolveKey
                ? resolver.issueJwt(KEY, "test-key", "test-id", "alice", "test-issuer", "test-audience",
                        Collections.singletonMap("scope", "read"), "HS256", 60000)
                : direct.issueJwt(KEY, "test-id", "alice", "test-issuer", "test-audience",
                        Collections.singletonMap("scope", "read"), "HS256", 60000);
        assertTrue(verify(token, true));
        JwtPayload claims = payload(token, true);
        assertEquals("test-id", claims.getTokenId());
        assertEquals("alice", claims.getSubject());
        assertEquals("test-issuer", claims.getIssuer());
        assertEquals(Collections.singletonList("test-audience"), claims.getAudience());
        assertEquals("read", claims.getClaims().get("scope"));
        assertEquals(NOW, claims.getIssuedAt().getTime());
        assertEquals(NOW + 60000, claims.getExpiration().getTime());
    }

    @Test
    public void wrongSigningKeyIsRejectedByBothEntryPoints() {
        String token = token(WRONG_KEY, NOW + 60000, null);
        assertThrows(SignatureException.class, () -> verify(token, true));
        assertThrows(SignatureException.class, () -> payload(token, true));
        assertThrows(SignatureException.class, () -> payload(token, false));
    }

    @Test
    public void modifiedPayloadCannotBeAuthenticatedEvenWhenExpiryCheckDisabled() {
        String[] parts = token(KEY, NOW + 60000, null).split("\\.");
        String body = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertTrue(body.contains("alice"));
        parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString(
                body.replace("alice", "admin").getBytes(StandardCharsets.UTF_8));
        String forged = String.join(".", parts);
        for (boolean expiry : new boolean[] {true, false}) {
            assertThrows(SignatureException.class, () -> verify(forged, expiry));
            assertThrows(SignatureException.class, () -> payload(forged, expiry));
        }
    }

    @Test
    public void modifiedSignatureIsRejected() {
        String[] parts = token(KEY, NOW + 60000, null).split("\\.");
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        signature[0] ^= 1;
        String forged = parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        assertThrows(SignatureException.class, () -> verify(forged, true));
        assertThrows(SignatureException.class, () -> payload(forged, false));
    }

    @Test
    public void expiredTokenHasDomainExceptionWithUnderlyingExpiryCause() {
        String token = token(KEY, NOW - 1000, null);
        ExpiredJwtException rejected = assertThrows(ExpiredJwtException.class, () -> verify(token, true));
        assertTrue(rejected.getCause() instanceof io.jsonwebtoken.ExpiredJwtException);
        assertThrows(ExpiredJwtException.class, () -> payload(token, true));
    }

    @Test
    public void signedPayloadCanBeInspectedWithoutExpiryButVerifyStillRejectsExpiredToken() {
        String token = token(KEY, NOW - 1000, null);
        assertEquals("alice", payload(token, false).getSubject());
        // Current public behavior: verify independently enforces expiry even with checkExpiry=false.
        IncorrectJwtException rejected = assertThrows(IncorrectJwtException.class, () -> verify(token, false));
        assertTrue(rejected.getCause() instanceof ExpiredJwtException);
    }

    @Test
    public void tokenAtExactExpirationIsAcceptedButOneSecondEarlierIsExpired() {
        assertTrue(verify(token(KEY, NOW, null), true));
        assertThrows(ExpiredJwtException.class, () -> verify(token(KEY, NOW - 1000, null), true));
    }

    @Test
    public void futureNotBeforeIsRejectedByBothEntryPoints() {
        String token = token(KEY, NOW + 60000, NOW + 1000);
        for (boolean expiry : new boolean[] {true, false}) {
            assertThrows(InvalidJwtToken.class, () -> verify(token, expiry));
            assertThrows(InvalidJwtToken.class, () -> payload(token, expiry));
        }
    }

    @Test
    public void malformedAndMissingTokensHaveDomainErrors() {
        for (String token : new String[] {null, "", " ", "not-a-jwt", "a.b", "a.b.c.d", "e30.e30.invalid"}) {
            for (boolean expiry : new boolean[] {true, false}) {
                assertThrows("verify: " + token, IncorrectJwtException.class, () -> verify(token, expiry));
                assertThrows("payload: " + token, IncorrectJwtException.class, () -> payload(token, expiry));
            }
        }
    }

    @Test
    public void weakSigningKeyIsRejectedBeforeIssuance() {
        Key weak = key("too-short");
        JwtException rejected = assertThrows(JwtException.class, () -> {
            if (resolveKey) {
                resolver.issueJwt(weak, "test-key", "id", "alice", "issuer", "audience", "[]", "[]", "HS256", 60000);
            } else {
                direct.issueJwt(weak, "id", "alice", "issuer", "audience", "[]", "[]", "HS256", 60000);
            }
        });
        assertTrue(rejected.getCause() instanceof io.jsonwebtoken.security.WeakKeyException);
    }
}
