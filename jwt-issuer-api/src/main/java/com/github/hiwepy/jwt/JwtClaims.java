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

public class JwtClaims {

	public static String DEFAULT_ROLE = "guest";
	
	/**
	 * 用户描述Id
	 */
	public static final String ID = "id";
	/**
	 * 用户ID（用户来源表Id）
	 */
	public static final String UID = "uid";
	/**
	 * 用户UUID（用户唯一ID）
	 */
	public static final String UUID = "uuid";
	/**
	 * 用户名
	 */
	public static final String UNAME = "uname";
	/**
	 * 用户Key：用户业务表中的唯一ID
	 */
	public static final String UKEY = "ukey";
	/**
	 * 用户Code：用户业务表中的唯一编码
	 */
	public static final String UCODE = "ucode";
	
	/**
	 * 角色ID（角色表Id）
	 */
	public static final String RID = "rid";
	/**
	 * 角色Key：角色业务表中的唯一ID
	 */
	public static final String RKEY = "rkey";
	/**
	 * 角色Code：角色业务表中的唯一编码
	 */
	public static final String RCODE = "rcode";
	/**
	 * 用户密码盐：用于密码加解密
	 */
	public static final String SALT = "salt";
	/**
	 * 用户秘钥：用于用户JWT加解密
	 */
	public static final String SECRET = "secret";
	/**
	 * 用户拥有角色列表
	 */
	public static final String ROLES = "roles";
	/**
	 * 用户权限标记列表
	 */
	public static final String PERMS = "perms";
	/**
	 * 用户数据
	 */
	public static final String PROFILE = "profile";
	/**
   	 * 用户是否绑定信息
   	 */
	public static final String BOUND = "bound";
	/**
   	 * 用户是否完善信息
   	 */
	public static final String INITIAL = "initial";
	/**
	 * 用户是否需要多因子验证
	 */
	public static final String VERIFY = "verify";
	/**
	 * 用户最新位置经度
	 */
	public static final String LONGITUDE = "longitude"; 
	/**
	 * 用户最新位置纬度
	 */
	public static final String LATITUDE = "latitude";
	/**
	 * 请求参数签名
	 */
	public static final String SIGN = "sign"; 
}
