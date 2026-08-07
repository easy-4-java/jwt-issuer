/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.jsonwebtoken.impl;

import java.io.InputStream;
import java.io.Reader;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtHandler;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.io.Decoders;

/**
 * 忽略过期时间的 JWT 解析器。
 *
 * <p>所有签名、加密和格式校验均委托给 JJWT 官方解析器。只有官方解析器在完成这些校验后
 * 抛出 {@link ExpiredJwtException} 时，才恢复其中已经解析完成的 Claims。</p>
 */
public class NoExpirationJwtParser implements JwtParser {

    private final JwtParser delegate;

    public NoExpirationJwtParser(JwtParser delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean isSigned(CharSequence compact) {
        return delegate.isSigned(compact);
    }

    @Override
    public Jwt<?, ?> parse(CharSequence compact) {
        try {
            return delegate.parse(compact);
        } catch (ExpiredJwtException ex) {
            if (ex.getHeader() instanceof JwsHeader) {
                return expiredJws(compact, ex);
            }
            return new DefaultJwt<>(ex.getHeader(), ex.getClaims());
        }
    }

    @Override
    public Jwt<?, ?> parse(CharSequence compact, int offset, int length) {
        return parse(compact.subSequence(offset, offset + length));
    }

    @Override
    public Jwt<?, ?> parse(Reader reader) {
        return delegate.parse(reader);
    }

    @Override
    public Jwt<?, ?> parse(InputStream inputStream) {
        return delegate.parse(inputStream);
    }

    @Override
    public <T> T parse(CharSequence compact, JwtHandler<T> handler) {
        return parse(compact).accept(handler);
    }

    @Override
    public Jwt<Header, byte[]> parseContentJwt(CharSequence compact) {
        return delegate.parseContentJwt(compact);
    }

    @Override
    public Jwt<Header, Claims> parseClaimsJwt(CharSequence compact) {
        try {
            return delegate.parseClaimsJwt(compact);
        } catch (ExpiredJwtException ex) {
            return new DefaultJwt<>(ex.getHeader(), ex.getClaims());
        }
    }

    @Override
    public Jws<byte[]> parseContentJws(CharSequence compact) {
        return delegate.parseContentJws(compact);
    }

    @Override
    public Jws<Claims> parseClaimsJws(CharSequence compact) {
        return parseSignedClaims(compact);
    }

    @Override
    public Jwt<Header, byte[]> parseUnsecuredContent(CharSequence compact) {
        return delegate.parseUnsecuredContent(compact);
    }

    @Override
    public Jwt<Header, Claims> parseUnsecuredClaims(CharSequence compact) {
        try {
            return delegate.parseUnsecuredClaims(compact);
        } catch (ExpiredJwtException ex) {
            return new DefaultJwt<>(ex.getHeader(), ex.getClaims());
        }
    }

    @Override
    public Jws<byte[]> parseSignedContent(CharSequence compact) {
        return delegate.parseSignedContent(compact);
    }

    @Override
    public Jws<byte[]> parseSignedContent(CharSequence compact, byte[] payload) {
        return delegate.parseSignedContent(compact, payload);
    }

    @Override
    public Jws<byte[]> parseSignedContent(CharSequence compact, InputStream payload) {
        return delegate.parseSignedContent(compact, payload);
    }

    @Override
    public Jws<Claims> parseSignedClaims(CharSequence compact) {
        try {
            return delegate.parseSignedClaims(compact);
        } catch (ExpiredJwtException ex) {
            return expiredJws(compact, ex);
        }
    }

    @Override
    public Jws<Claims> parseSignedClaims(CharSequence compact, byte[] payload) {
        try {
            return delegate.parseSignedClaims(compact, payload);
        } catch (ExpiredJwtException ex) {
            return expiredJws(compact, ex);
        }
    }

    @Override
    public Jws<Claims> parseSignedClaims(CharSequence compact, InputStream payload) {
        try {
            return delegate.parseSignedClaims(compact, payload);
        } catch (ExpiredJwtException ex) {
            return expiredJws(compact, ex);
        }
    }

    @Override
    public Jwe<byte[]> parseEncryptedContent(CharSequence compact) {
        return delegate.parseEncryptedContent(compact);
    }

    @Override
    public Jwe<Claims> parseEncryptedClaims(CharSequence compact) {
        return delegate.parseEncryptedClaims(compact);
    }

    private Jws<Claims> expiredJws(CharSequence compact, ExpiredJwtException ex) {
        String[] segments = compact.toString().split("\\.", -1);
        String signature = segments.length > 2 ? segments[2] : "";
        byte[] digest = signature.isEmpty() ? new byte[0] : Decoders.BASE64URL.decode(signature);
        return new DefaultJws<>((JwsHeader) ex.getHeader(), ex.getClaims(), digest, signature);
    }
}
