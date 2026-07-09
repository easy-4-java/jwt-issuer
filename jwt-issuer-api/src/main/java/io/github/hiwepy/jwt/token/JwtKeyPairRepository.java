package io.github.hiwepy.jwt.token;

import java.util.Map;

import io.github.hiwepy.jwt.exception.JwtException;
import io.github.hiwepy.jwt.JwtPayload;

public interface JwtKeyPairRepository<S, E> {

	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws JwtException;
	
	public abstract String issueJwt(S signingKey, E secretKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException;

	public abstract boolean verify(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;

	public abstract JwtPayload getPlayload(S signingKey, E secretKey, String token, boolean checkExpiry)
			throws JwtException;
}
