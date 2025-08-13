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
package com.github.hiwepy.jwt.utils;

import com.github.hiwepy.jwt.JwtPayload;
import io.jsonwebtoken.*;
import io.jsonwebtoken.lang.Classes;
import org.apache.commons.lang3.StringUtils;

import java.security.Key;
import java.text.ParseException;
import java.util.*;
import java.util.Map.Entry;

/**
 * 基于JJwt组件的jwt工具对象
 *
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class JJwtUtils {

	public static final String ROLE_REFRESH_TOKEN = "ROLE_REFRESH_TOKEN";
	public static final String CLAIM_KEY_USER_ID = "user_id";
	public static final String CLAIM_KEY_AUTHORITIES = "scope";
	public static final String CLAIM_KEY_ACCOUNT_ENABLED = "enabled";
	public static final String CLAIM_KEY_ACCOUNT_NON_LOCKED = "non_locked";
	public static final String CLAIM_KEY_ACCOUNT_NON_EXPIRED = "non_expired";

	/**
     * Returns a new JwtParserBuilder instance that can be configured to create an immutable/thread-safe JwtParserBuilder.
     *
     * @return a new JwtParserBuilder instance that can be configured create an immutable/thread-saf JwtParserBuilder.
     */
    public static JwtParserBuilder parserBuilder() {
        return Classes.newInstance("io.jsonwebtoken.impl.NoExpirationJwtParserBuilder");
    }

	public static JwtBuilder jwtBuilder(String jwtId, String subject, String issuer, Set<String> audience, Map<String, Object> claims,
			long period) {

		// 当前时间戳
		long currentTimeMillis = System.currentTimeMillis();
		JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT");
		// 声明信息：调用setClaims需要在其他设置之前，不然会丢失数据
		if(claims != null) {
			builder.setClaims(claims);
		}
		// Jwt主键ID
		if (StringUtils.isNoneBlank(jwtId)) {
			builder.setId(jwtId);
			builder.claim(Claims.ID, jwtId);
		}
		// 用户名主题
		builder.setSubject(subject);
		builder.claim(Claims.SUBJECT, subject);
		// 接收对象
		if (Objects.nonNull(audience)) {
			builder.audience().add(audience);
			builder.claim(Claims.AUDIENCE, audience);
		}
		// 签发者
		if (StringUtils.isNoneBlank(issuer)) {
			builder.setIssuer(issuer);
			builder.claim(Claims.ISSUER, issuer);
		}
		// 默认签发时间
		Date now = new Date(currentTimeMillis);
		builder.setIssuedAt(now);
		// 默认有效期起始时间
		//builder.setNotBefore(now);
		// Token过期时间
		if (period >= 0) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period);
			builder.setExpiration(expiration);
		}

		return builder;
	}

	public static JwtBuilder jwtBuilder(String jwtId, String subject,
			String issuer, Set<String> audience, String roles, String permissions, long period) {

		JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT");

		// Jwt主键ID
		if (StringUtils.isNoneBlank(jwtId)) {
			builder.setId(jwtId);
			builder.claim(Claims.ID, jwtId);
		}
		// 用户名主题
		builder.setSubject(subject);
		builder.claim(Claims.SUBJECT, subject);
		// 接收对象
		if (Objects.nonNull(audience)) {
			builder.audience().add(audience);
			builder.claim(Claims.AUDIENCE, audience);
		}
		// 签发者
		if (StringUtils.isNoneBlank(issuer)) {
			builder.setIssuer(issuer);
			builder.claim(Claims.ISSUER, issuer);
		}
		// 角色
		if (StringUtils.isNoneBlank(roles)) {
			builder.claim("roles", roles);
		}
		// 权限
		if (StringUtils.isNoneBlank(permissions)) {
			builder.claim("perms", permissions);
		}
		return builder;
	}

	public static JwtPayload payload(Claims claims) throws ParseException {

		JwtPayload payload = new JwtPayload();

		payload.setTokenId(claims.getId());
		payload.setSubject(claims.getSubject());// 用户名
		payload.setIssuer(claims.getIssuer());// 签发者
		payload.setIssuedAt(claims.getIssuedAt());// 签发时间
		payload.setExpiration(claims.getExpiration()); // 过期时间
		payload.setNotBefore(claims.getNotBefore());

		payload.setAudience(claims.getAudience());// 接收方
		payload.setClaims(claims); // 访问主张

		return payload;
	}

	public static Claims parseJWT(Key secretKey, String token) {
		// 解析jwt串 :其中parseClaimsJws验证jwt字符串失败可能会抛出异常，需要捕获异常
		Claims claims = Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
		return claims;
	}

	public String genAccessToken(Key secretKey, String uid, String subject,
								 String issuer, Set<String> audience, Map<String, Object> claims, long access_token_expiration) {
		return jwtBuilder(uid, subject, issuer, audience, claims, access_token_expiration)
				// 压缩，可选GZIP
				.compressWith(CompressionCodecs.DEFLATE)
				// 设置算法（必须）
				.signWith(secretKey).compact();
	}

	public String genRefreshToken(Key secretKey, String uid, String subject,
			String issuer, Set<String> audience, Map<String, Object> claims, long refresh_token_expiration) {
		return jwtBuilder(uid, subject, issuer, audience, claims, refresh_token_expiration)
				// 压缩，可选GZIP
				.compressWith(CompressionCodecs.DEFLATE)
				// 设置算法（必须）
				.signWith(secretKey).compact();
	}

	public Boolean canTokenBeRefreshed(Key secretKey, String token, Date lastPasswordReset) {
		final Date created = getCreatedDateFromToken(secretKey, token);
		return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset) && (!isTokenExpired(secretKey, token));
	}

	public String refreshToken(Key secretKey, String token, long access_token_expiration) {
		String refreshedToken;
		try {
			final Claims claims = parseJWT(secretKey, token);
			Iterator<Entry<String, Object>> ite = claims.entrySet().iterator();
			Map<String, Object> claimMap = new HashMap<String, Object>();
			while (ite.hasNext()) {
				Entry<String, Object> entry = ite.next();
				claimMap.put(entry.getKey(), entry.getValue());
			}
			refreshedToken = genAccessToken(secretKey, claims.getId(), claims.getSubject(),

					claims.getIssuer(), claims.getAudience(), claimMap, access_token_expiration);
		} catch (Exception e) {
			refreshedToken = null;
		}
		return refreshedToken;
	}

	public long getUserIdFromToken(Key secretKey, String token) {
		long userId;
		try {
			final Claims claims = parseJWT(secretKey, token);
			userId = (Long) claims.get(CLAIM_KEY_USER_ID);
		} catch (Exception e) {
			userId = 0;
		}
		return userId;
	}

	public String getUsernameFromToken(Key secretKey, String token) {
		String username;
		try {
			final Claims claims = parseJWT(secretKey, token);
			username = claims.getSubject();
		} catch (Exception e) {
			username = null;
		}
		return username;
	}

	public Date getCreatedDateFromToken(Key secretKey, String token) {
		Date created;
		try {
			final Claims claims = parseJWT(secretKey, token);
			created = claims.getIssuedAt();
		} catch (Exception e) {
			created = null;
		}
		return created;
	}

	public static Date getExpirationDateFromToken(Key secretKey, String token) {
		Date expiration;
		try {
			final Claims claims = parseJWT(secretKey, token);
			expiration = claims.getExpiration();
		} catch (Exception e) {
			expiration = null;
		}
		return expiration;
	}


	public static Boolean isTokenExpired(Key secretKey, String token) {
		final Date expiration = getExpirationDateFromToken(secretKey, token);
		return expiration.before(new Date());
	}

	public static Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
		return (lastPasswordReset != null && created.before(lastPasswordReset));
	}

}
