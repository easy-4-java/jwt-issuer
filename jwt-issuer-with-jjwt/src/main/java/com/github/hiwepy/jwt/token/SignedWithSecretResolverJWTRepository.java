/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.github.hiwepy.jwt.token;

import com.github.hiwepy.jwt.JwtPayload;
import com.github.hiwepy.jwt.exception.ExpiredJwtException;
import com.github.hiwepy.jwt.exception.JwtException;
import com.github.hiwepy.jwt.exception.*;
import com.github.hiwepy.jwt.utils.JJwtUtils;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureException;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <b> JSON Web Token (JWT) with signature  </b>
 * https://github.com/jwtk/jjwt
 */
public class SignedWithSecretResolverJWTRepository implements JwtKeyResolverRepository<Key> {

	private Logger logger = LoggerFactory.getLogger(getClass());
	private long allowedClockSkewSeconds = -1;
	private CompressionCodec compressWith = CompressionCodecs.DEFLATE;
	private SigningKeyResolver signingKeyResolver;
    private CompressionCodecResolver compressionCodecResolver;
    private Clock clock = new JwtClock();
    private static final Map<String, JwtParser> PARSER_CONTEXT = new ConcurrentHashMap<>();

	public JwtParser getJwtParser(SigningKeyResolver signingKeyResolver, boolean checkExpiry) {

		String key = String.format("%s-%s", signingKeyResolver.hashCode() , checkExpiry);
		JwtParser ret = PARSER_CONTEXT.get(key);
		if (ret != null) {
			return ret;
		}

		JwtParserBuilder jwtParserBuilder = checkExpiry ? Jwts.parser() : JJwtUtils.parserBuilder();
		// 时钟
		jwtParserBuilder.setClock(clock)
		// 签名Key解析器
		.setSigningKeyResolver(signingKeyResolver)
		// 允许的时间误差
		.setAllowedClockSkewSeconds(getAllowedClockSkewSeconds());
		// 压缩方式解析器
		if(null != getCompressionCodecResolver() ) {
			jwtParserBuilder.setCompressionCodecResolver(getCompressionCodecResolver());
		}

		ret = jwtParserBuilder.build();
		PARSER_CONTEXT.put( key, ret);
		return ret;
	}


    public SignedWithSecretResolverJWTRepository() {
    }

    public SignedWithSecretResolverJWTRepository(SigningKeyResolver signingKeyResolver) {
    	this.signingKeyResolver = signingKeyResolver;
    }

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param secretKey		: Signing key
	 * @param keyId			: Key Id
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param roles			: The Roles
	 * @param permissions	: The Perms
	 * @param algorithm		: Supported algorithms：
	 *  <p> none: No digital signature or MAC performed </p>
	 *  <p> HS256: HMAC using SHA-256 </p>
	 *  <p> HS384: HMAC using SHA-384 </p>
     *  <p> HS512: HMAC using SHA-512 </p>
     *  <p> ES256: ECDSA using P-256 and SHA-256 </p>
     *  <p> ES384: ECDSA using P-384 and SHA-384 </p>
     *  <p> ES512: ECDSA using P-521 and SHA-512 </p>
     *  <p> RS256: RSASSA-PKCS-v1_5 using SHA-256 </p>
     *  <p> RS384: RSASSA-PKCS-v1_5 using SHA-384 </p>
     *  <p> RS512: RSASSA-PKCS-v1_5 using SHA-512 </p>
     *  <p> PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256 </p>
     *  <p> PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384 </p>
     *  <p> PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(Key secretKey, String keyId, String jwtId, String subject, String issuer, Set<String> audience,
			String roles, String permissions, String algorithm, long period)  throws JwtException {
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("roles", roles);
		claims.put("perms", permissions);

		return this.issueJwt(secretKey, keyId, jwtId, subject, issuer, audience, claims, algorithm, period);
	}

	/**
	 * Issue JSON Web Token (JWT)
	 * @author ：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param secretKey		: Signing key
	 * @param keyId			: Key Id
	 * @param jwtId			: Jwt Id
	 * @param subject		: Jwt Subject
	 * @param issuer 		: Jwt Issuer
	 * @param audience 		: Jwt Audience
	 * @param claims		: Jwt Claims
	 * @param algorithm		: Supported algorithms：
	 *  <p> none: No digital signature or MAC performed </p>
	 *  <p> HS256: HMAC using SHA-256 </p>
	 *  <p> HS384: HMAC using SHA-384 </p>
     *  <p> HS512: HMAC using SHA-512 </p>
     *  <p> ES256: ECDSA using P-256 and SHA-256 </p>
     *  <p> ES384: ECDSA using P-384 and SHA-384 </p>
     *  <p> ES512: ECDSA using P-521 and SHA-512 </p>
     *  <p> RS256: RSASSA-PKCS-v1_5 using SHA-256 </p>
     *  <p> RS384: RSASSA-PKCS-v1_5 using SHA-384 </p>
     *  <p> RS512: RSASSA-PKCS-v1_5 using SHA-512 </p>
     *  <p> PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256 </p>
     *  <p> PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384 </p>
     *  <p> PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512 </p>
     * @param period 		: Jwt Expiration Cycle
	 * @return JSON Web Token (JWT)
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public String issueJwt(Key secretKey, String keyId, String jwtId, String subject, String issuer, Set<String> audience,
			Map<String, Object> claims,	String algorithm, long period) throws JwtException {

		try {
			JwtBuilder builder = JJwtUtils
					.jwtBuilder(jwtId, subject, issuer, audience, claims, period)
					// 指定KeyID以便进行验证时，动态获取该ID对应的Key
					.setHeaderParam(JwsHeader.KEY_ID, StringUtils.isNoneBlank(keyId) ? keyId : Base64.getEncoder().encodeToString(secretKey.getEncoded()))
					// 压缩类型
					.compressWith(getCompressWith())
					// 设置算法（必须）
					.signWith(secretKey, SignatureAlgorithm.forName(algorithm));

			// 签发时间
			Date now = this.getClock().now();
			builder.setIssuedAt(now);
			// 有效期起始时间
			//builder.setNotBefore(now);
			// Token过期时间
			if (period >= 0) {
				// 有效时间
				Date expiration = new Date(now.getTime() + period);
				builder.setExpiration(expiration);
			}

			return builder.compact();
		} catch (InvalidKeyException e) {
			throw new JwtException(e);
		} catch (SignatureException e) {
			throw new JwtException(e);
		}
	}

	/**
	 * Verify the validity of JWT
	 * @author 				: <a href="https://github.com/hiwepy">hiwepy</a>
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return If Validity
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public boolean verify(String token, boolean checkExpiry) throws JwtException {

		try {

			// Retrieve / verify the JWT claims according to the app requirements
			JwtParser jwtParser = this.getJwtParser(signingKeyResolver, checkExpiry);

			// 解密JWT，如果无效则会抛出异常
			Jws<Claims> jws = jwtParser.parseClaimsJws(token);

			Claims claims = jws.getBody();

			Date issuedAt = claims.getIssuedAt();
			Date notBefore = claims.getNotBefore();
			Date expiration = claims.getExpiration();
			Date now = this.getClock().now();

			if (logger.isDebugEnabled()) {
				logger.debug("JWT IssuedAt:" + issuedAt);
				logger.debug("JWT NotBefore:" + notBefore);
				logger.debug("JWT Expiration:" + expiration);
				logger.debug("JWT Now:" + now);
			}

			if(notBefore != null && now.getTime() <= notBefore.getTime()) {
				throw new NotObtainedJwtException(String.format("JWT was not obtained before this timestamp : [%s].", notBefore));
			}
			if(expiration != null && expiration.getTime() < now.getTime()) {
				throw new ExpiredJwtException("Expired JWT value. ");
			}
			return true;
		} catch (MalformedJwtException e) {
			throw new IncorrectJwtException(e);
		} catch (MissingClaimException e) {
			throw new IncorrectJwtException(e);
		} catch (io.jsonwebtoken.ExpiredJwtException e) {
			throw new ExpiredJwtException(e);
		} catch (InvalidClaimException e) {
			throw new InvalidJwtToken(e);
		} catch (PrematureJwtException e) {
			throw new InvalidJwtToken(e);
		} catch (RequiredTypeException e) {
			throw new InvalidJwtToken(e);
		} catch (JwtException e) {
			throw new IncorrectJwtException(e);
		} catch (IllegalArgumentException e) {
			throw new IncorrectJwtException(e);
		}

	}

	/**
	 * Parser JSON Web Token (JWT)
	 * @author 		：<a href="https://github.com/hiwepy">hiwepy</a>
	 * @param token  		: JSON Web Token (JWT)
	 * @param checkExpiry 	: If Check validity.
	 * @return JwtPlayload {@link JwtPayload}
	 * @throws JwtException When Authentication Exception
	 */
	@Override
	public JwtPayload getPlayload(String token, boolean checkExpiry)  throws JwtException {
		try {

			// Retrieve / verify the JWT claims according to the app requirements
			JwtParser jwtParser = this.getJwtParser(signingKeyResolver, checkExpiry);

			Jws<Claims> jws = jwtParser.parseClaimsJws(token);

			return JJwtUtils.payload(jws.getBody());
		} catch (MalformedJwtException e) {
			throw new IncorrectJwtException(e);
		} catch (MissingClaimException e) {
			throw new IncorrectJwtException(e);
		} catch (io.jsonwebtoken.ExpiredJwtException e) {
			throw new ExpiredJwtException(e);
		} catch (InvalidClaimException e) {
			throw new InvalidJwtToken(e);
		} catch (PrematureJwtException e) {
			throw new InvalidJwtToken(e);
		} catch (RequiredTypeException e) {
			throw new InvalidJwtToken(e);
		} catch (JwtException e) {
			throw new IncorrectJwtException(e);
		} catch (IllegalArgumentException e) {
			throw new IncorrectJwtException(e);
		} catch (ParseException e) {
			throw new IncorrectJwtException(e);
		}
	}

	public long getAllowedClockSkewSeconds() {
		return allowedClockSkewSeconds;
	}

	public void setAllowedClockSkewSeconds(long allowedClockSkewSeconds) {
		this.allowedClockSkewSeconds = allowedClockSkewSeconds;
	}

	public CompressionCodec getCompressWith() {
		return compressWith;
	}

	public void setCompressWith(CompressionCodec compressWith) {
		this.compressWith = compressWith;
	}

	public CompressionCodecResolver getCompressionCodecResolver() {
		return compressionCodecResolver;
	}

	public void setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver) {
		this.compressionCodecResolver = compressionCodecResolver;
	}

	public Clock getClock() {
		return clock;
	}

	public void setClock(Clock clock) {
		this.clock = clock;
	}

	public void setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
		this.signingKeyResolver = signingKeyResolver;
	}


}
