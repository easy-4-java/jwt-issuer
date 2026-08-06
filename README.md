# jwt-issuer

[English](./README.md) | [简体中文](./README.zh-CN.md)

[![Java](https://img.shields.io/badge/Java-8-orange)](https://github.com/easy-4-java/jwt-issuer) [![License](https://img.shields.io/badge/license-Apache%202.0-green)](./LICENSE)

> **Status**: maintained on the `feature/1.0.x` line (JDK 8). Artifacts are not yet published to Maven Central; they are distributed through the project's private repository and GitHub Releases.

## Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. Features & Status](#2-features--status)
- [3. Requirements & Compatibility](#3-requirements--compatibility)
- [4. Architecture & Modules](#4-architecture--modules)
- [5. Installation](#5-installation)
- [6. Quick Start](#6-quick-start)
- [7. Configuration](#7-configuration)
- [8. Core Usage / API](#8-core-usage--api)
- [9. Testing & Build](#9-testing--build)
- [10. Versioning & Branches](#10-versioning--branches)
- [11. Contributing & License](#11-contributing--license)

## 1. Project Overview

`jwt-issuer` is a JWT issuing/verification toolkit that hides the differences between two underlying JWT libraries behind one shared API. It is a multi-module project:

- `jwt-issuer-api` — the neutral contract: `JwtRepository<S>` (issue / verify / payload), the rich `JwtPayload` (subject, issuer, audience, roles, perms, profile, Spring-Security-compatible account flags, ...), `JwtClaims` claim-name constants, `JwtTimeProvider` for clock-skew handling, `SecretKeyUtils` key generation and the exception hierarchy;
- `jwt-issuer-with-jjwt` — implementation on [jjwt 0.11.2](https://github.com/jwtk/jjwt) (`JwtRepository<Key>` implementations, `JJwtUtils` builders, a `JwtClock`, and a `NoExpirationJwtParser` variant);
- `jwt-issuer-with-nimbus` — implementation on [nimbus-jose-jwt 9.7](https://connect2id.com/products/nimbus-jose-jwt) (12 `JwtRepository<String>` implementations covering HMAC / EC / EdDSA / RSA signing and optional RSA / AES JWE encryption, plus extended verifiers).

What it is:

- A uniform `JwtRepository` SPI so applications can switch between jjwt and Nimbus without changing call sites;
- A ready-made, security-oriented `JwtPayload` (uid/uuid/ukey/ucode/rid/rkey/rcode, roles, perms, profile, bound/initial flags) for user/role-centric tokens;
- Algorithm choice per issue call (HS/RS/PS/ES/Ed algorithms) and expiry control via `period`.

What it is not:

- Not a JWT library itself — it wraps jjwt / Nimbus; neither a Spring Security filter nor an OAuth2 provider — token *consumption* (filters, interceptors) lives in other projects (e.g. `security-jwt-extension`).

Typical scenarios:

| Scenario | Which module / class |
| :--- | :--- |
| HMAC-signed tokens on jjwt | `jwt-issuer-with-jjwt` → `SignedWithSecretKeyJWTRepository`, `JJwtUtils` |
| HMAC / RSA / EC / Ed tokens on Nimbus | `jwt-issuer-with-nimbus` → `SignedWithHamcJWTRepository`, `SignedWithRsaJWTRepository`, `SignedWithEcJWTRepository`, `SignedWithEdJWTRepository` |
| Signed + encrypted (JWE) tokens | `jwt-issuer-with-nimbus` → `SignedWith*AndEncryptedWith{Rsa,Aes}JWTRepository` (4 sign × 2 encryption combos) |
| Key-pair / key-resolver based issuing | `jwt-issuer-api` → `JwtKeyPairRepository`, `JwtKeyResolverRepository` |
| Custom clock for skew handling | `jwt-issuer-api` → `JwtTimeProvider`, `DefaultJwtTimeProvider` |

## 2. Features & Status

| Capability | Status | Notes |
| :--- | :--- | :--- |
| Uniform issue/verify/payload SPI | Implemented | `JwtRepository<S>` (4 methods) in `jwt-issuer-api` |
| Rich payload model | Implemented | `JwtPayload` (+ `JwtClaims` constants, `RolePair`) |
| Time provider | Implemented | `JwtTimeProvider` / `DefaultJwtTimeProvider` (epoch millis) |
| Key utilities | Implemented | `SecretKeyUtils` (KeyPair / SecretKey / PBE / Base64 / read-write) |
| jjwt implementation | Implemented | `SignedWithSecretKeyJWTRepository`, `SignedWithSecretResolverJWTRepository`, `JJwtUtils`, `NoExpirationJwtParser(Builder)`, `JwtClock` |
| Nimbus implementation | Implemented | 12 repositories (HMAC / EC / Ed / RSA signing × optional RSA / AES encryption), `NimbusdsUtils`, 4 extended verifiers |
| Exception hierarchy | Implemented | `JwtException`, `ExpiredJwtException`, `IncorrectJwtException`, `InvalidJwtToken`, `NotObtainedJwtException` |
| Tests | Present | `jwt-issuer-with-jjwt` ships `JWTTest` (JUnit 4) exercising issue + parse + expiry checks |

## 3. Requirements & Compatibility

| Item | Requirement |
| :--- | :--- |
| JDK | 8+ |
| Maven | 3.0+ (Maven Wrapper `mvnw` included) |
| `jwt-issuer-api` deps | commons-lang3 3.20.0, commons-collections4 4.4, guava 30.0-jre, fastjson 2.0.62 |
| `jwt-issuer-with-jjwt` deps | jjwt-api/impl/jackson 0.11.2, bcprov-jdk15on 1.60, `jwt-issuer-api` |
| `jwt-issuer-with-nimbus` deps | nimbus-jose-jwt 9.7, `jwt-issuer-api` |
| Shared | slf4j-api 2.0.18, javax.servlet-api 3.0.1 (provided), junit 4.13.2 (test) |

Version lines:

| Branch | JDK | Version pattern |
| :--- | :---: | :--- |
| `feature/1.0.x` | 8 | `1.0.x.*` |
| `feature/2.0.x` | 17 | `2.0.x.*` |
| `feature/3.0.x` | 21 | `3.0.x.*` |

## 4. Architecture & Modules

```text
Application code (issue / verify / payload)
        |
        v
io.github.easy4j.jwt (jwt-issuer-api: JwtRepository, JwtPayload, JwtClaims,
                      JwtTimeProvider, SecretKeyUtils, exceptions)
        |
        +-----------------+------------------+
        |                                    |
        v                                    v
jwt-issuer-with-jjwt                  jwt-issuer-with-nimbus
  JwtRepository<Key>                    JwtRepository<String>
  JJwtUtils / JwtClock /                SignedWith{Hmac,Ec,Ed,Rsa}JWTRepository
  NoExpirationJwtParser                 + EncryptedWith{Rsa,Aes} variants
        |                                    |   (JWE) + Extended*Verifiers
        v                                    v
   jjwt 0.11.2                        nimbus-jose-jwt 9.7
```

Root `jwt-issuer` is a pom-only aggregator. Dependency direction: the two `-with-*` modules depend on `jwt-issuer-api`; they are mutually independent.

| Module | Responsibility | Independent use |
| :--- | :--- | :--- |
| `jwt-issuer-api` | SPI + payload + time provider + key utils + exceptions | Yes (contract only) |
| `jwt-issuer-with-jjwt` | jjwt-backed implementation + `JJwtUtils` | Yes, with `jwt-issuer-api` |
| `jwt-issuer-with-nimbus` | Nimbus-backed implementation (12 signing/encryption combos) | Yes, with `jwt-issuer-api` |

## 5. Installation

Pick the implementation module matching your JWT library; both pull in `jwt-issuer-api` transitively.

jjwt variant:

```xml
<dependency>
    <groupId>io.github.easy4j</groupId>
    <artifactId>jwt-issuer-with-jjwt</artifactId>
    <version>1.0.x.20260630-SNAPSHOT</version>
</dependency>
```

Nimbus variant:

```xml
<dependency>
    <groupId>io.github.easy4j</groupId>
    <artifactId>jwt-issuer-with-nimbus</artifactId>
    <version>1.0.x.20260630-SNAPSHOT</version>
</dependency>
```

Gradle:

```groovy
implementation 'io.github.easy4j:jwt-issuer-with-jjwt:1.0.x.20260630-SNAPSHOT'
implementation 'io.github.easy4j:jwt-issuer-with-nimbus:1.0.x.20260630-SNAPSHOT'
```

Snapshots are served from the project's private repository (see `distributionManagement` in the pom). No Maven Central release is available yet.

## 6. Quick Start

Issue and parse a JWT with the jjwt variant (real API, pattern taken from `JWTTest`):

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

`jwtBuilder(jwtId, subject, issuer, audience, claims, period)` produces a token valid for `period` seconds (1024 s in the example); `JJwtUtils.payload(...)` maps the claims onto the rich `JwtPayload` (tokenId, subject, issuer, audience, roles, perms, ...).

## 7. Configuration

Plain library — no configuration properties or prefixes. Behavior is configured per call:

- signing key: `SecretKey` / `KeyPair` / key-resolver (`JwtRepository<Key>`), or Base64 secret string (Nimbus `JwtRepository<String>`);
- algorithm per `issueJwt(...)` call (HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA on Nimbus, `none` allowed);
- expiry: `period` (seconds) passed to `issueJwt`;
- clock: plug a custom `JwtTimeProvider` (e.g. for skew-tolerant clocks); jjwt side exposes `JwtClock` and `setAllowedClockSkewSeconds`.

## 8. Core Usage / API

### 8.1 Uniform SPI on jjwt

```java
import io.github.easy4j.jwt.token.JwtRepository;
import io.github.easy4j.jwt.token.SignedWithSecretKeyJWTRepository;
import java.security.Key;

JwtRepository<Key> repository = new SignedWithSecretKeyJWTRepository();

String jwtId = UUID.randomUUID().toString();
String token = repository.issueJwt(secretKey, jwtId, "subject-1", "issuer-1",
        "audience-1", "admin,stu", "user:del", "HS256", 3600);

boolean ok = repository.verify(secretKey, token, true);        // checks expiry
JwtPayload payload = repository.getPlayload(secretKey, token, true);
```

### 8.2 Signed + encrypted tokens on Nimbus

```java
import io.github.easy4j.jwt.token.SignedWithRsaAndEncryptedWithRsaJWTRepository;

JwtRepository<String> repository = new SignedWithRsaAndEncryptedWithRsaJWTRepository();

String token = repository.issueJwt(privateKeyBase64, "jwt-1", "subject-1", "issuer-1",
        "audience-1", java.util.Map.of("roles", "admin"), "RS256", 1800);
// token is a JWE-wrapped JWS: RSASSA-PKCS1-v1_5 signature, RSA-OAEP encrypted
```

## 9. Testing & Build

```bash
./mvnw clean verify
```

The build is configured with:

- JUnit 4 (junit 4.13.2) + Maven Surefire; `jwt-issuer-with-jjwt` includes `JWTTest` exercising `JJwtUtils` build / parse / payload / expiry paths;
- JaCoCo coverage reporting plus a line-coverage check rule with a 90% minimum target (`haltOnFailure=false`);
- Source and Javadoc jars attached at package time;
- a `central` release profile (GPG signing + Central publishing) reserved for official releases.

## 10. Versioning & Branches

Three parallel version lines, each bound to a JDK baseline:

| Branch | JDK | Version pattern | Maintenance |
| :--- | :---: | :--- | :--- |
| `feature/1.0.x` | 8 | `1.0.x.*` | Current development line |
| `feature/2.0.x` | 17 | `2.0.x.*` | Maintained in parallel |
| `feature/3.0.x` | 21 | `3.0.x.*` | Maintained in parallel |

All modules share one version (`1.0.x.20260630-SNAPSHOT` on this branch). Releases are cut via GitHub Releases; Maven Central publication is planned but has not happened yet.

## 11. Contributing & License

Contributions are welcome — open an issue or pull request on GitHub. All source files are licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt).
