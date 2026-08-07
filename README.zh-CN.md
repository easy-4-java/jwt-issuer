# jwt-issuer

[English](./README.md) | [简体中文](./README.zh-CN.md)

[![Java](https://img.shields.io/badge/Java-8-orange)](https://github.com/easy-4-java/jwt-issuer) [![License](https://img.shields.io/badge/license-Apache%202.0-green)](./LICENSE)

jwt-issuer 是 JWT 签发/校验工具集，用一个统一 API 屏蔽两个底层 JWT 库的差异。

> **项目状态**：`feature/1.0.x` 版本线维护中（JDK 8）。制品尚未发布到 Maven Central，通过项目私服与 GitHub Releases 分发。

## 目录

- [1. 项目概述](#1-项目概述)
- [2. 功能与状态](#2-功能与状态)
- [3. 环境要求与兼容性](#3-环境要求与兼容性)
- [4. 架构与模块](#4-架构与模块)
- [5. 安装](#5-安装)
- [6. 快速开始](#6-快速开始)
- [7. 配置](#7-配置)
- [8. 核心用法 / API](#8-核心用法--api)
- [9. 测试与构建](#9-测试与构建)
- [10. 版本与分支](#10-版本与分支)
- [11. 贡献与许可](#11-贡献与许可)

## 1. 项目概述

`jwt-issuer` 是 JWT 签发/校验工具集，用一个统一 API 屏蔽两个底层 JWT 库的差异。它是一个多模块项目：

- `jwt-issuer-api`——中立契约：`JwtRepository<S>`（签发 / 校验 / 载荷），富模型 `JwtPayload`（subject、issuer、audience、roles、perms、profile、兼容 Spring Security 的账户标志等）、`JwtClaims` 声明常量、用于时钟偏差处理的 `JwtTimeProvider`、`SecretKeyUtils` 密钥生成与异常体系；
- `jwt-issuer-with-jjwt`——基于 [jjwt 0.11.2](https://github.com/jwtk/jjwt) 的实现（`JwtRepository<Key>` 实现、`JJwtUtils` 构建器、`JwtClock`、`NoExpirationJwtParser` 变体）；
- `jwt-issuer-with-nimbus`——基于 [nimbus-jose-jwt 9.7](https://connect2id.com/products/nimbus-jose-jwt) 的实现（12 个 `JwtRepository<String>` 实现，覆盖 HMAC / EC / EdDSA / RSA 签名与可选 RSA / AES JWE 加密，以及扩展验证器）。

是什么：

- 统一的 `JwtRepository` SPI，应用可在 jjwt 与 Nimbus 之间切换而无需改动调用点；
- 面向用户/角色令牌的现成 `JwtPayload`（uid/uuid/ukey/ucode/rid/rkey/rcode、roles、perms、profile、bound/initial 标志）；
- 每次签发可指定算法（HS/RS/PS/ES/Ed）与有效期 `period`。

不是什么：

- 不是 JWT 库本身——它包装 jjwt / Nimbus；也不是 Spring Security 过滤器或 OAuth2 提供者——令牌消费（过滤器、拦截器）属于其他项目（如 `security-jwt-extension`）。

典型场景：

| 场景 | 模块 / 类 |
| :--- | :--- |
| 基于 jjwt 的 HMAC 签名令牌 | `jwt-issuer-with-jjwt` → `SignedWithSecretKeyJWTRepository`、`JJwtUtils` |
| 基于 Nimbus 的 HMAC / RSA / EC / Ed 令牌 | `jwt-issuer-with-nimbus` → `SignedWithHamcJWTRepository`、`SignedWithRsaJWTRepository`、`SignedWithEcJWTRepository`、`SignedWithEdJWTRepository` |
| 签名 + 加密（JWE）令牌 | `jwt-issuer-with-nimbus` → `SignedWith*AndEncryptedWith{Rsa,Aes}JWTRepository`（4 种签名 × 2 种加密组合） |
| 基于密钥对 / 密钥解析器签发 | `jwt-issuer-api` → `JwtKeyPairRepository`、`JwtKeyResolverRepository` |
| 自定义时钟处理偏差 | `jwt-issuer-api` → `JwtTimeProvider`、`DefaultJwtTimeProvider` |

## 2. 功能与状态

| 能力 | 状态 | 说明 |
| :--- | :--- | :--- |
| 统一签发/校验/载荷 SPI | 已实现 | `JwtRepository<S>`（4 个方法），位于 `jwt-issuer-api` |
| 富载荷模型 | 已实现 | `JwtPayload`（+ `JwtClaims` 常量、`RolePair`） |
| 时间提供者 | 已实现 | `JwtTimeProvider` / `DefaultJwtTimeProvider`（毫秒时间戳） |
| 密钥工具 | 已实现 | `SecretKeyUtils`（KeyPair / SecretKey / PBE / Base64 / 读写） |
| jjwt 实现 | 已实现 | `SignedWithSecretKeyJWTRepository`、`SignedWithSecretResolverJWTRepository`、`JJwtUtils`、`NoExpirationJwtParser(Builder)`、`JwtClock` |
| Nimbus 实现 | 已实现 | 12 个仓库（HMAC / EC / Ed / RSA 签名 × 可选 RSA / AES 加密）、`NimbusdsUtils`、4 个扩展验证器 |
| 异常体系 | 已实现 | `JwtException`、`ExpiredJwtException`、`IncorrectJwtException`、`InvalidJwtToken`、`NotObtainedJwtException` |
| 测试 | 已有 | `jwt-issuer-with-jjwt` 自带 `JWTTest`（JUnit 4），覆盖签发 + 解析 + 过期检查 |

## 3. 环境要求与兼容性

| 项目 | 要求 |
| :--- | :--- |
| JDK | 8+ |
| Maven | 3.0+（内置 Maven Wrapper `mvnw`） |
| `jwt-issuer-api` 依赖 | commons-lang3 3.20.0、commons-collections4 4.4、guava 30.0-jre、fastjson 2.0.62 |
| `jwt-issuer-with-jjwt` 依赖 | jjwt-api/impl/jackson 0.11.2、bcprov-jdk15on 1.60、`jwt-issuer-api` |
| `jwt-issuer-with-nimbus` 依赖 | nimbus-jose-jwt 9.7、`jwt-issuer-api` |
| 公共 | slf4j-api 2.0.18、javax.servlet-api 3.0.1（provided）、junit 4.13.2（测试） |

版本线：

| 分支 | JDK | 版本模式 |
| :--- | :---: | :--- |
| `feature/1.0.x` | 8 | `1.0.x.*` |
| `feature/2.0.x` | 17 | `2.0.x.*` |
| `feature/3.0.x` | 21 | `3.0.x.*` |

## 4. 架构与模块

```text
应用代码 (签发 / 校验 / 载荷)
        |
        v
io.github.easy4j.jwt (jwt-issuer-api: JwtRepository, JwtPayload, JwtClaims,
                      JwtTimeProvider, SecretKeyUtils, 异常)
        |
        +-----------------+------------------+
        |                                    |
        v                                    v
jwt-issuer-with-jjwt                  jwt-issuer-with-nimbus
  JwtRepository<Key>                    JwtRepository<String>
  JJwtUtils / JwtClock /                SignedWith{Hmac,Ec,Ed,Rsa}JWTRepository
  NoExpirationJwtParser                 + EncryptedWith{Rsa,Aes} 变体
        |                                    |   (JWE) + Extended*Verifiers
        v                                    v
   jjwt 0.11.2                        nimbus-jose-jwt 9.7
```

根模块 `jwt-issuer` 是纯 pom 聚合器。依赖方向：两个 `-with-*` 模块依赖 `jwt-issuer-api`，二者互不依赖。

| 模块 | 职责 | 可独立使用 |
| :--- | :--- | :--- |
| `jwt-issuer-api` | SPI + 载荷 + 时间提供者 + 密钥工具 + 异常 | 是（仅契约） |
| `jwt-issuer-with-jjwt` | jjwt 实现 + `JJwtUtils` | 是，需配合 `jwt-issuer-api` |
| `jwt-issuer-with-nimbus` | Nimbus 实现（12 种签名/加密组合） | 是，需配合 `jwt-issuer-api` |

## 5. 安装

按底层 JWT 库选择对应实现模块；两者都会传递引入 `jwt-issuer-api`。

jjwt 变体：

```xml
<dependency>
    <groupId>io.github.easy4j</groupId>
    <artifactId>jwt-issuer-with-jjwt</artifactId>
    <version>1.0.x.20260630-SNAPSHOT</version>
</dependency>
```

Nimbus 变体：

```xml
<dependency>
    <groupId>io.github.easy4j</groupId>
    <artifactId>jwt-issuer-with-nimbus</artifactId>
    <version>1.0.x.20260630-SNAPSHOT</version>
</dependency>
```

Gradle：

```groovy
implementation 'io.github.easy4j:jwt-issuer-with-jjwt:1.0.x.20260630-SNAPSHOT'
implementation 'io.github.easy4j:jwt-issuer-with-nimbus:1.0.x.20260630-SNAPSHOT'
```

快照版本由项目私服提供（见 pom 中 `distributionManagement`）。尚未发布 Maven Central 正式版。

## 6. 快速开始

使用 jjwt 变体签发并解析 JWT（真实 API，用法取自 `JWTTest`）：

```java
import java.util.UUID;
import javax.crypto.SecretKey;
import io.github.easy4j.jwt.JwtPayload;
import io.github.easy4j.jwt.utils.JJwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

String token = JJwtUtils.jwtBuilder(UUID.randomUUID().toString(), "subject-1", "issuer-1",
        "audience-1", java.util.Map.of("roles", "admin,stu", "perms", "user:del"), 1024)
        .compressWith(CompressionCodecs.DEFLATE)
        .signWith(secretKey)
        .compact();

Claims claims = JJwtUtils.parseJWT(secretKey, token);
JwtPayload payload = JJwtUtils.payload(claims);

boolean expired = JJwtUtils.isTokenExpired(secretKey, token);
```

`jwtBuilder(jwtId, subject, issuer, audience, claims, period)` 签发有效期 `period` 秒的令牌（示例为 1024 秒）；`JJwtUtils.payload(...)` 将 claims 映射为富模型 `JwtPayload`（tokenId、subject、issuer、audience、roles、perms 等）。

## 7. 配置

纯库组件，没有任何配置项或配置前缀。行为按调用配置：

- 签名密钥：`SecretKey` / `KeyPair` / 密钥解析器（`JwtRepository<Key>`），或 Base64 密钥字符串（Nimbus `JwtRepository<String>`）；
- 每次 `issueJwt(...)` 调用指定算法（HS256/384/512、RS256/384/512、PS256/384/512、ES256/384/512、Nimbus 侧支持 EdDSA、允许 `none`）；
- 有效期：传给 `issueJwt` 的 `period`（秒）；
- 时钟：可注入自定义 `JwtTimeProvider`（例如容错时钟偏差）；jjwt 侧提供 `JwtClock` 与 `setAllowedClockSkewSeconds`。

## 8. 核心用法 / API

### 8.1 jjwt 上的统一 SPI

```java
import io.github.easy4j.jwt.token.JwtRepository;
import io.github.easy4j.jwt.token.SignedWithSecretKeyJWTRepository;
import java.security.Key;

JwtRepository<Key> repository = new SignedWithSecretKeyJWTRepository();

String jwtId = UUID.randomUUID().toString();
String token = repository.issueJwt(secretKey, jwtId, "subject-1", "issuer-1",
        "audience-1", "admin,stu", "user:del", "HS256", 3600);

boolean ok = repository.verify(secretKey, token, true);        // 校验过期
JwtPayload payload = repository.getPlayload(secretKey, token, true);
```

### 8.2 Nimbus 上的签名 + 加密令牌

```java
import io.github.easy4j.jwt.token.SignedWithRsaAndEncryptedWithRsaJWTRepository;

JwtRepository<String> repository = new SignedWithRsaAndEncryptedWithRsaJWTRepository();

String token = repository.issueJwt(privateKeyBase64, "jwt-1", "subject-1", "issuer-1",
        "audience-1", java.util.Map.of("roles", "admin"), "RS256", 1800);
// 令牌为 JWE 包裹的 JWS：RSASSA-PKCS1-v1_5 签名 + RSA-OAEP 加密
```

## 9. 测试与构建

```bash
./mvnw clean verify
```

构建配置：

- JUnit 4（junit 4.13.2）+ Maven Surefire；`jwt-issuer-with-jjwt` 包含 `JWTTest`，覆盖 `JJwtUtils` 构建 / 解析 / 载荷 / 过期路径；
- JaCoCo 覆盖率报告 + 行覆盖率检查规则，最低目标 90%（`haltOnFailure=false`）；
- package 阶段附加源码包与 Javadoc 包；
- 提供 `central` 发布 profile（GPG 签名 + Central 发布插件），仅用于正式发布。

## 10. 版本与分支

三条并行版本线，各自绑定一个 JDK 基线：

| 分支 | JDK | 版本模式 | 维护状态 |
| :--- | :---: | :--- | :--- |
| `feature/1.0.x` | 8 | `1.0.x.*` | 当前开发线 |
| `feature/2.0.x` | 17 | `2.0.x.*` | 并行维护 |
| `feature/3.0.x` | 21 | `3.0.x.*` | 并行维护 |

所有模块共享同一版本（本分支为 `1.0.x.20260630-SNAPSHOT`）。正式版本通过 GitHub Releases 发布；Maven Central 发布已规划，尚未执行。

## 11. 贡献与许可

欢迎通过 GitHub Issue 或 Pull Request 参与贡献。所有源码基于 [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt) 许可。
