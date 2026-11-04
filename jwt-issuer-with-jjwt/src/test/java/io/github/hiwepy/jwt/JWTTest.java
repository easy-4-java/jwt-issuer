package io.github.easy4j.jwt;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import io.github.easy4j.jwt.utils.JJwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;

/** Offline utility contracts with a public test-only signing key. */
public class JWTTest {
    private static final SecretKey KEY = new SecretKeySpec(
            "utility-test-key-0123456789abcdef".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");

    @Test
    public void mapBuilderPreservesRegisteredAndCustomClaims() throws Exception {
        long before = System.currentTimeMillis();
        String token = JJwtUtils.jwtBuilder("id", "alice", "issuer", "audience",
                Collections.singletonMap("scope", "read"), 60000).signWith(KEY).compact();
        Claims claims = JJwtUtils.parseJWT(KEY, token);
        assertEquals("id", claims.getId());
        assertEquals("alice", claims.getSubject());
        assertEquals("issuer", claims.getIssuer());
        assertEquals("audience", claims.getAudience());
        assertEquals("read", claims.get("scope"));
        assertTrue(claims.getIssuedAt().getTime() >= before - 999);
        assertEquals(60000, claims.getExpiration().getTime() - claims.getIssuedAt().getTime());
        JwtPayload payload = JJwtUtils.payload(claims);
        assertEquals("alice", payload.getSubject());
        assertEquals("id", payload.getTokenId());
        assertEquals(Collections.singletonList("audience"), payload.getAudience());
        assertEquals(claims.getExpiration(), payload.getExpiration());
        assertFalse(JJwtUtils.isTokenExpired(KEY, token));
    }

    @Test
    public void rolesBuilderSetsTtlAndRoundTripsStructuredRoles() throws Exception {
        String roles = "[{\"id\":\"1\",\"key\":\"admin\",\"value\":\"Administrator\"}]";
        String perms = "read,write";
        Claims claims = JJwtUtils.parseJWT(KEY, JJwtUtils.jwtBuilder(
                "id", "alice", "issuer", "audience", roles, perms, 60000).signWith(KEY).compact());
        assertEquals(60000, claims.getExpiration().getTime() - claims.getIssuedAt().getTime());
        assertEquals(roles, claims.get("roles"));
        assertEquals(perms, claims.get("perms"));
        JwtPayload payload = JJwtUtils.payload(claims);
        assertEquals(1, payload.getRoles().size());
        assertEquals(new java.util.HashSet<>(java.util.Arrays.asList("read", "write")), payload.getPerms());
    }

    @Test
    public void negativePeriodExplicitlyOmitsExpirationInBothOverloads() {
        assertNull(JJwtUtils.parseJWT(KEY, JJwtUtils.jwtBuilder(null, "alice", null, null,
                (java.util.Map<String, Object>) null, -1).signWith(KEY).compact()).getExpiration());
        assertNull(JJwtUtils.parseJWT(KEY, JJwtUtils.jwtBuilder(null, "alice", null, null,
                null, null, -1).signWith(KEY).compact()).getExpiration());
    }

    @Test
    public void zeroPeriodSetsAnExpirationInsteadOfCreatingImmortalToken() {
        // Inspect with the explicit no-expiry parser to avoid a wall-clock race at zero TTL.
        Claims claims = JJwtUtils.parserBuilder().setSigningKey(KEY).build().parseClaimsJws(
                JJwtUtils.jwtBuilder("id", "alice", "issuer", "audience", "[]", "[]", 0)
                        .signWith(KEY).compact()).getBody();
        assertNotNull(claims.getExpiration());
        assertEquals(claims.getIssuedAt(), claims.getExpiration());
    }

    @Test
    public void parseRejectsWrongKeysAndExpiredTokens() {
        String token = JJwtUtils.jwtBuilder("id", "alice", "issuer", "audience",
                Collections.emptyMap(), 60000).signWith(KEY).compact();
        SecretKey wrong = new SecretKeySpec("wrong-utility-key-0123456789abcdef".getBytes(StandardCharsets.US_ASCII), "HmacSHA256");
        assertThrows(SignatureException.class, () -> JJwtUtils.parseJWT(wrong, token));
        String expired = Jwts.builder().setSubject("alice").setExpiration(new Date(1000))
                .signWith(KEY, SignatureAlgorithm.HS256).compact();
        assertThrows(io.jsonwebtoken.ExpiredJwtException.class, () -> JJwtUtils.parseJWT(KEY, expired));
    }

    @Test
    public void refreshPreservesIdentityAndCustomClaimsAndRejectsInvalidInput() {
        JJwtUtils utils = new JJwtUtils();
        String token = utils.genAccessToken(KEY, "id", "alice", "issuer", "audience",
                Collections.singletonMap("scope", "read"), 60000);
        assertTrue(utils.canTokenBeRefreshed(KEY, token, null));
        assertFalse(utils.canTokenBeRefreshed(KEY, token, new Date(System.currentTimeMillis() + 60000)));
        Claims refreshed = JJwtUtils.parseJWT(KEY, utils.refreshToken(KEY, token, 120000));
        assertEquals("id", refreshed.getId());
        assertEquals("alice", refreshed.getSubject());
        assertEquals("read", refreshed.get("scope"));
        assertEquals(120000, refreshed.getExpiration().getTime() - refreshed.getIssuedAt().getTime());
        assertNull(utils.refreshToken(KEY, "invalid", 60000));
        assertNull(utils.getUsernameFromToken(KEY, "invalid"));
        assertNull(utils.getCreatedDateFromToken(KEY, "invalid"));
        assertNull(JJwtUtils.getExpirationDateFromToken(KEY, "invalid"));
        assertEquals(0, utils.getUserIdFromToken(KEY, "invalid"));
    }

    @Test
    public void refreshTokenAndPasswordResetBoundaryHaveExplicitAssertions() {
        JJwtUtils utils = new JJwtUtils();
        String token = utils.genRefreshToken(KEY, "id", "alice", "issuer", "audience", Collections.emptyMap(), 60000);
        assertEquals("alice", utils.getUsernameFromToken(KEY, token));
        assertNotNull(utils.getCreatedDateFromToken(KEY, token));
        assertNotNull(JJwtUtils.getExpirationDateFromToken(KEY, token));
        Date created = new Date(1000);
        assertFalse(JJwtUtils.isCreatedBeforeLastPasswordReset(created, null));
        assertFalse(JJwtUtils.isCreatedBeforeLastPasswordReset(created, new Date(1000)));
        assertTrue(JJwtUtils.isCreatedBeforeLastPasswordReset(created, new Date(1001)));
    }
}
