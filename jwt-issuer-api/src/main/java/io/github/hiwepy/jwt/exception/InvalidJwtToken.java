package io.github.hiwepy.jwt.exception;

@SuppressWarnings("serial")
public class InvalidJwtToken extends JwtException {
	
	public InvalidJwtToken() {
		super();
	}

	public InvalidJwtToken(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidJwtToken(String message) {
		super(message);
	}

	public InvalidJwtToken(Throwable cause) {
		super(cause);
	}
	
}
