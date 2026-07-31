package io.github.easy4j.jwt.exception;

@SuppressWarnings("serial")
public class IncorrectJwtException extends JwtException {
	
	public IncorrectJwtException() {
		super();
	}

	public IncorrectJwtException(String message, Throwable cause) {
		super(message, cause);
	}

	public IncorrectJwtException(String message) {
		super(message);
	}

	public IncorrectJwtException(Throwable cause) {
		super(cause);
	}
	
}
