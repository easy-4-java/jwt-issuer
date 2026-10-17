package io.github.easy4j.jwt.utils;

import com.nimbusds.jwt.JWTClaimsSet;
import io.github.easy4j.jwt.JwtPayload;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class NimbusdsUtilsTest {

    @Test
    void claimsAndLifetimeSurvivePayloadConversion() throws ParseException {
        JWTClaimsSet claims = NimbusdsUtils.claimsSet("token-1", "alice", "issuer", "app-a,app-b",
                "admin", "document:read", 60_000).build();

        JwtPayload payload = NimbusdsUtils.payload(claims);
        assertEquals("token-1", payload.getTokenId());
        assertEquals("alice", payload.getSubject());
        assertEquals("issuer", payload.getIssuer());
        assertEquals(Arrays.asList("app-a", "app-b"), payload.getAudience());
        assertEquals("admin", payload.getClaims().get("roles"));
        assertEquals("document:read", payload.getClaims().get("perms"));
        assertEquals(60_000, payload.getExpiration().getTime() - payload.getIssuedAt().getTime());
        assertEquals(payload.getIssuedAt(), payload.getNotBefore());
    }

    @Test
    void negativeLifetimeLeavesExpirationUnset() {
        JWTClaimsSet claims = NimbusdsUtils.claimsSet("token-2", "alice", "issuer", null,
                Collections.singletonMap("tenant", "t1"), -1).build();

        assertNull(claims.getExpirationTime());
        assertEquals("t1", claims.getClaim("tenant"));
    }
}
