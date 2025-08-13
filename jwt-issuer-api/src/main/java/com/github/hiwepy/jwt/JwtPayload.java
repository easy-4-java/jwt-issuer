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
package com.github.hiwepy.jwt;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.alibaba.fastjson2.JSONArray;
import org.apache.commons.collections4.MapUtils;

import com.alibaba.fastjson2.JSONObject;
import com.github.hiwepy.jwt.utils.StringUtils;

/**
 * TODO
 *
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("unchecked")
public class JwtPayload {

	/**
	 * 令牌ID
	 */
	private String tokenId;
	/**
	 * 客户标识（用户名、账号）
	 */
	private String subject;
	/**
	 * 客户名称
	 */
	private String clientName;
	/**
	 * 签发者(JWT令牌此项有值)
	 */
	private String issuer;
	/**
	 * 签发时间
	 */
	private Date issuedAt;
	/**
	 * 过期时间
	 */
	private Date expiration;
	/**
	 * not-before 时间
	 */
	private Date notBefore;
	/**
	 * 接收方(JWT令牌此项有值)
	 */
	private Set<String> audience;
	/**
	 * 访问主张(JWT令牌此项有值)
	 */
	private Map<String, Object> claims;
	/**
	 * 客户地址
	 */
	private String host;
	/**
	 * 用户ID（用户来源表Id）
	 */
	private String uid;
	/**
	 * 用户UUID（用户唯一ID）
	 */
	private String uuid;
	/**
	 * 用户Key：用户业务表中的唯一ID
	 */
	private String ukey;
	/**
	 * 用户Code：用户业务表中的唯一编码
	 */
	private String ucode;
	/**
	 * 角色ID（角色表Id）
	 */
	private String rid;
	/**
	 * 角色Key：角色业务表中的唯一ID
	 */
	private String rkey;
	/**
	 * 角色Code：角色业务表中的唯一编码
	 */
	private String rcode;
	/**
   	 * 用户是否绑定信息
   	 */
    private boolean bound = Boolean.FALSE;
	/**
	 * 用户是否完善信息
	 */
	private boolean initial = Boolean.FALSE;
	/**
	 * 用户是否需要多因子验证
	 */
	private boolean verify = Boolean.FALSE;

	/**
	 * 兼容 Spring Security
	 */
	private boolean accountNonExpired = true;
	private boolean accountNonLocked = true;
	private boolean credentialsNonExpired = true;
	private boolean enabled = true;

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public String getClientName() {
		return StringUtils.isEmpty(clientName) ? MapUtils.getString(claims, JwtClaims.UNAME) : clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public Date getIssuedAt() {
		return issuedAt;
	}

	public void setIssuedAt(Date issuedAt) {
		this.issuedAt = issuedAt;
	}

	public Date getExpiration() {
		return expiration;
	}

	public void setExpiration(Date expiration) {
		this.expiration = expiration;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Set<String> getAudience() {
		return audience;
	}

	public void setAudience(Set<String> audience) {
		this.audience = audience;
	}

	public Map<String, Object> getClaims() {
		return claims == null ? new HashMap<String, Object>() : claims;
	}

	public void setClaims(Map<String, Object> claims) {
		this.claims = claims;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getUid() {
		return MapUtils.getString(claims, JwtClaims.UID, uid);
	}

	public void setUid(String uid) {
		this.uid = uid;
	}

	public String getUuid() {
		return MapUtils.getString(claims, JwtClaims.UUID, uuid);
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getUkey() {
		return MapUtils.getString(claims, JwtClaims.UKEY, ukey);
	}

	public void setUkey(String ukey) {
		this.ukey = ukey;
	}

	public String getUcode() {
		return MapUtils.getString(claims, JwtClaims.UCODE, ucode);
	}

	public void setUcode(String ucode) {
		this.ucode = ucode;
	}

	public String getRid() {
		return MapUtils.getString(claims, JwtClaims.RID, rid);
	}

	public void setRid(String rid) {
		this.rid = rid;
	}

	public String getRkey() {
		return StringUtils.defaultIfBlank(MapUtils.getString(claims, JwtClaims.RKEY,  rkey), JwtClaims.DEFAULT_ROLE);
	}

	public void setRkey(String rkey) {
		this.rkey = rkey;
	}

	public String getRcode() {
		return rcode;
	}

	public void setRcode(String rcode) {
		this.rcode = rcode;
	}

	public boolean isBound() {
		return MapUtils.getBoolean(claims, JwtClaims.BOUND, bound);
	}

	public void setBound(boolean bound) {
		this.bound = bound;
	}

	public boolean isInitial() {
		return MapUtils.getBoolean(claims, JwtClaims.INITIAL, initial);
	}

	public void setInitial(boolean initial) {
		this.initial = initial;
	}

	public void setVerify(boolean verify) {
		this.verify = verify;
	}

	public boolean isVerify() {
		return MapUtils.getBoolean(claims, JwtClaims.VERIFY, verify);
	}

	public List<RolePair> getRoles() {
		Object obj = MapUtils.getObject(claims, JwtClaims.ROLES);
		if (obj != null) {
			if (obj instanceof String) {
				return JSONArray.parseArray(String.valueOf(obj), RolePair.class);
			}
			return (List<RolePair>) obj;
		}
		return new ArrayList<>();
	}

	public Set<String> getPerms() {
		Object obj = MapUtils.getObject(claims, JwtClaims.PERMS);
		if (obj != null) {
			if (obj instanceof String) {
				return Stream.of(StringUtils.tokenizeToStringArray(String.valueOf(obj))).collect(Collectors.toSet());
			}
			return (Set<String>) obj;
		}
		return new HashSet<String>();
	}

	public Map<String, Object> getProfile() {
		Object obj = MapUtils.getObject(claims, JwtClaims.PROFILE);
		if (obj != null) {
			try {
				if (obj instanceof String) {
					return JSONObject.parseObject(String.valueOf(obj), Map.class);
				}
				return (Map<String, Object>) obj;
			} catch (Exception e) {
			}
		}
		return new HashMap<String, Object>();
	}

	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}

	public void setAccountNonExpired(boolean accountNonExpired) {
		this.accountNonExpired = accountNonExpired;
	}

	public boolean isAccountNonLocked() {
		return accountNonLocked;
	}

	public void setAccountNonLocked(boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}

	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	public void setCredentialsNonExpired(boolean credentialsNonExpired) {
		this.credentialsNonExpired = credentialsNonExpired;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	@SuppressWarnings("serial")
	public static class RolePair implements Serializable {

		/**
		 * 角色Id
		 */
		private String id;
		/**
		 * 角色唯一编码
		 */
		private String key;
		/**
		 * 角色是否需要多因子验证
		 */
		private boolean verify = Boolean.FALSE;
		/**
		 * 角色名称
		 */
		private String value;

		public RolePair() {

		}

		public RolePair(String id, String key, String value) {
			super();
			this.id = id;
			this.key = key;
			this.value = value;
		}

		public RolePair(String id, String key, String value, boolean verify) {
			super();
			this.id = id;
			this.key = key;
			this.value = value;
			this.verify = verify;
		}

		public String getId() {
			return id;
		}

		public void setId(String id) {
			this.id = id;
		}

		public String getKey() {
			return key;
		}

		public void setKey(String key) {
			this.key = key;
		}

		public String getValue() {
			return value;
		}

		public void setValue(String value) {
			this.value = value;
		}

		public void setVerify(boolean verify) {
			this.verify = verify;
		}

		public boolean isVerify() {
			return verify;
		}

	}

}
