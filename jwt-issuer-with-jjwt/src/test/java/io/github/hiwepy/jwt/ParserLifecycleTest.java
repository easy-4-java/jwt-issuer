package io.github.easy4j.jwt;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import io.github.easy4j.jwt.token.SignedWithSecretKeyJWTRepository;
import io.github.easy4j.jwt.token.SignedWithSecretResolverJWTRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.security.SignatureException;

/** Real parsing and signature checks, including concurrent callers; no external services. */
@RunWith(Parameterized.class)
public class ParserLifecycleTest {
    private static final long NOW = 1800000000000L;
    private static final Key KEY = key(false);
    private static final Key COLLIDING_KEY = key(true);
    private final boolean resolveKey;

    @Parameterized.Parameters(name = "resolver={0}")
    public static Iterable<Object[]> implementations() {
        return Arrays.asList(new Object[][] {{false}, {true}});
    }

    public ParserLifecycleTest(boolean resolveKey) { this.resolveKey = resolveKey; }

    private static Key key(boolean collide) {
        byte[] bytes = Arrays.copyOf("0123456789abcdef-lifecycle-testX".getBytes(StandardCharsets.US_ASCII), 32);
        if (collide) { bytes[1] += 2; bytes[2] -= 1; }
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    private static SigningKeyResolver resolver(Key key) {
        return new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) { return key; }
            @Override
            public int hashCode() { return 8172364; }
        };
    }

    private final class Context {
        final Key key;
        final SignedWithSecretKeyJWTRepository direct = new SignedWithSecretKeyJWTRepository();
        final SignedWithSecretResolverJWTRepository resolving;
        SigningKeyResolver signingResolver;

        Context(Key key) {
            this.key = key;
            signingResolver = resolver(key);
            resolving = new SignedWithSecretResolverJWTRepository(signingResolver);
            clock(NOW);
        }

        void clock(long instant) {
            direct.setClock(() -> new Date(instant));
            resolving.setClock(() -> new Date(instant));
        }

        void skew(long seconds) {
            direct.setAllowedClockSkewSeconds(seconds);
            resolving.setAllowedClockSkewSeconds(seconds);
        }

        void compression(CompressionCodecResolver codecResolver) {
            direct.setCompressionCodecResolver(codecResolver);
            resolving.setCompressionCodecResolver(codecResolver);
        }

        JwtParser parser(boolean checkExpiry) {
            return resolveKey ? resolving.getJwtParser(signingResolver, checkExpiry) : direct.getJwtParser(key, checkExpiry);
        }

        boolean verify(String token, boolean checkExpiry) {
            return resolveKey ? resolving.verify(token, checkExpiry) : direct.verify(key, token, checkExpiry);
        }

        JwtPayload payload(String token, boolean checkExpiry) {
            return resolveKey ? resolving.getPlayload(token, checkExpiry) : direct.getPlayload(key, token, checkExpiry);
        }
    }

    private static String token(Key key, long expires, Long notBefore, boolean compressed) {
        io.jsonwebtoken.JwtBuilder builder = Jwts.builder().setSubject("test-user")
                .setExpiration(new Date(expires));
        if (notBefore != null) { builder.setNotBefore(new Date(notBefore)); }
        if (compressed) { builder.compressWith(CompressionCodecs.DEFLATE); }
        return builder.signWith(key).compact();
    }

    @Test
    public void sameKeyInDifferentRepositoriesUsesEachRepositoryClock() {
        Context beforeExpiry = new Context(KEY);
        Context afterExpiry = new Context(KEY);
        afterExpiry.clock(NOW + 2000);
        String token = token(KEY, NOW + 1000, null, false);
        assertEquals("test-user", beforeExpiry.parser(true).parseClaimsJws(token).getBody().getSubject());
        assertThrows(io.jsonwebtoken.ExpiredJwtException.class, () -> afterExpiry.parser(true).parseClaimsJws(token));
        assertEquals("test-user", afterExpiry.parser(false).parseClaimsJws(token).getBody().getSubject());
    }

    @Test
    public void subsequentParserUsesUpdatedClockWithoutChangingExistingParser() {
        Context context = new Context(KEY);
        String token = token(KEY, NOW + 1000, null, false);
        JwtParser earlier = context.parser(true);
        assertEquals("test-user", earlier.parseClaimsJws(token).getBody().getSubject());
        context.clock(NOW + 2000);
        assertThrows(io.jsonwebtoken.ExpiredJwtException.class, () -> context.parser(true).parseClaimsJws(token));
        assertEquals("test-user", earlier.parseClaimsJws(token).getBody().getSubject());
    }

    @Test
    public void clockSkewIsIsolatedBetweenInstancesAndUpdatesApplyToNextParser() {
        Context lenient = new Context(KEY);
        Context strict = new Context(KEY);
        lenient.skew(2);
        String token = token(KEY, NOW + 60000, NOW + 1000, false);
        assertEquals("test-user", lenient.parser(true).parseClaimsJws(token).getBody().getSubject());
        assertThrows(io.jsonwebtoken.PrematureJwtException.class, () -> strict.parser(true).parseClaimsJws(token));
        lenient.skew(0);
        assertThrows(io.jsonwebtoken.PrematureJwtException.class, () -> lenient.parser(true).parseClaimsJws(token));
    }

    @Test
    public void updatedCompressionPolicyAppliesToNextParser() {
        Context context = new Context(KEY);
        String token = token(KEY, NOW + 60000, null, true);
        assertTrue(context.verify(token, true));
        context.compression(header -> { throw new CompressionRejected(); });
        assertThrows(CompressionRejected.class, () -> context.parser(true).parseClaimsJws(token));
        assertThrows(CompressionRejected.class, () -> context.parser(false).parseClaimsJws(token));
        context.compression(null);
        assertTrue(context.verify(token, true));
    }

    @Test
    public void expiryModeCannotBeReusedByStrictParser() {
        Context context = new Context(KEY);
        String expired = token(KEY, NOW - 1000, null, false);
        assertEquals("test-user", context.parser(false).parseClaimsJws(expired).getBody().getSubject());
        assertThrows(io.jsonwebtoken.ExpiredJwtException.class, () -> context.parser(true).parseClaimsJws(expired));
    }

    @Test(timeout = 30000)
    public void concurrentCollidingKeysAndResolversNeverAuthenticateEachOthersTokens() throws Exception {
        assertFalse(KEY.equals(COLLIDING_KEY));
        assertEquals(KEY.hashCode(), COLLIDING_KEY.hashCode());
        Context first = new Context(KEY);
        Context second = new Context(COLLIDING_KEY);
        String firstToken = token(KEY, NOW + 60000, null, true);
        String secondToken = token(COLLIDING_KEY, NOW + 60000, null, false);
        ExecutorService executor = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> tasks = new ArrayList<>();
        try {
            for (int task = 0; task < 8; task++) {
                final boolean useFirst = task % 2 == 0;
                tasks.add(executor.submit(() -> {
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    Context own = useFirst ? first : second;
                    String ownToken = useFirst ? firstToken : secondToken;
                    String otherToken = useFirst ? secondToken : firstToken;
                    for (int iteration = 0; iteration < 16; iteration++) {
                        boolean expiry = iteration % 2 == 0;
                        assertTrue(own.verify(ownToken, expiry));
                        assertEquals("test-user", own.payload(ownToken, expiry).getSubject());
                        assertThrows(SignatureException.class, () -> own.verify(otherToken, expiry));
                        assertThrows(SignatureException.class, () -> own.payload(otherToken, expiry));
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> task : tasks) { task.get(20, TimeUnit.SECONDS); }
        } finally {
            start.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private static final class CompressionRejected extends RuntimeException { }
}
