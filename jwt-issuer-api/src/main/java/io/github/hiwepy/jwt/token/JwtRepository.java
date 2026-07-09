package io.github.hiwepy.jwt.token;

import java.util.Map;

import io.github.hiwepy.jwt.JwtPayload;
import io.github.hiwepy.jwt.exception.JwtException;

public interface JwtRepository<S>{
	
	public abstract String issueJwt(S signingKey, String jwtId, String subject, String issuer, String audience,
			String roles, String permissions, String algorithm, long period) throws JwtException;

	public abstract String issueJwt(S signingKey, String jwtId, String subject, String issuer, String audience,
			Map<String, Object> claims, String algorithm, long period) throws JwtException;
	
	public abstract boolean verify(S signingKey, String token, boolean checkExpiry) throws JwtException;
	
	public abstract JwtPayload getPlayload(S signingKey, String token, boolean checkExpiry) throws JwtException;
	
}
