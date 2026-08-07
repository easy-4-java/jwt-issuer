/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package io.jsonwebtoken.impl;

import io.jsonwebtoken.JwtParser;

/**
 * 创建忽略过期时间、但仍执行签名和令牌结构校验的解析器。
 */
public class NoExpirationJwtParserBuilder extends DefaultJwtParserBuilder {

    @Override
    public JwtParser build() {
        return new NoExpirationJwtParser(super.build());
    }
}
