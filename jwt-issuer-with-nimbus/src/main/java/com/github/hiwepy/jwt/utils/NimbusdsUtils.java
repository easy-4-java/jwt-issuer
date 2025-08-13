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
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections4.CollectionUtils;

import java.text.ParseException;
import java.util.*;
import java.util.Map.Entry;

/**
 * 基于Nimbusds组件的jwt工具对象
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class NimbusdsUtils {

	public static JWTClaimsSet.Builder claimsSet(String jwtId, String subject, String issuer, Set<String> audience, Map<String, Object> claims,
												 long period) {

		// Current TimeMillis
		long currentTimeMillis = System.currentTimeMillis();

		// Prepare JWT with claims set
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// Jwt主键ID
		if (StringUtils.isNoneBlank(jwtId)) {
			builder.jwtID(jwtId);
		}
		// 用户名主题
		builder.subject(subject);
		// 接收对象
		if (CollectionUtils.isNotEmpty(audience)) {
			builder.audience(new ArrayList<>(audience));
		}
		// 签发者
		if (StringUtils.isNoneBlank(issuer)) {
			builder.issuer(issuer);
		}
		// 声明信息
		if(claims != null) {
			Iterator<Entry<String, Object>> ite = claims.entrySet().iterator();
			while (ite.hasNext()) {
				Entry<String, Object> entry = ite.next();
				builder.claim(entry.getKey(), entry.getValue());
			}
		}
		// 默认签发时间
		Date now = new Date(currentTimeMillis);
		builder.issueTime(now);
		// 默认有效期起始时间
		builder.notBeforeTime(now);
		// Token过期时间
		if (period >= 0) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period );
			builder.expirationTime(expiration);
		}
		return builder;
	}


	public static JWTClaimsSet.Builder claimsSet(String jwtId, String subject, String issuer, Set<String> audience, String roles,
			String permissions, long period) {

		// Current TimeMillis
		long currentTimeMillis = System.currentTimeMillis();

		// Prepare JWT with claims set
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// Jwt主键ID
		if (StringUtils.isNoneBlank(jwtId)) {
			builder.jwtID(jwtId);
		}
		// 用户名主题
		builder.subject(subject);
		// 接收对象
		if (CollectionUtils.isNotEmpty(audience)) {
			builder.audience(new ArrayList<>(audience));
		}
		// 签发者
		if (StringUtils.isNoneBlank(issuer)) {
			builder.issuer(issuer);
		}
		// 角色
		if (StringUtils.isNoneBlank(roles)) {
			builder.claim("roles", roles);
		}
		// 权限
		if (StringUtils.isNoneBlank(permissions)) {
			builder.claim("perms", permissions);
		}
		// 默认签发时间
		Date now = new Date(currentTimeMillis);
		builder.issueTime(now);
		// 默认有效期起始时间
		builder.notBeforeTime(now);
		// Token过期时间
		if (period >= 0) {
			// 有效时间
			Date expiration = new Date(currentTimeMillis + period );
			builder.expirationTime(expiration);
		}
		return builder;
	}

	public static JwtPayload payload(JWTClaimsSet jwtClaims) throws ParseException {

		JwtPayload payload = new JwtPayload();
		payload.setTokenId(jwtClaims.getJWTID());
		payload.setSubject(jwtClaims.getSubject());// 用户名
		payload.setIssuer(jwtClaims.getIssuer());// 签发者
		payload.setIssuedAt(jwtClaims.getIssueTime());// 签发时间
		payload.setExpiration(jwtClaims.getExpirationTime()); // 过期时间
		payload.setNotBefore(jwtClaims.getNotBeforeTime());
		payload.setAudience(new HashSet<>(jwtClaims.getAudience()));// 接收方
		payload.setClaims(jwtClaims.getClaims()); // 访问主张

		return payload;
	}

}
