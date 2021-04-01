package tech.itpark.http.exception;

public class InvalidRequestLineException extends RuntimeException {
    public InvalidRequestLineException() {
    }

    public InvalidRequestLineException(String message) {
        super(message);
    }

    public InvalidRequestLineException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidRequestLineException(Throwable cause) {
        super(cause);
    }

    public InvalidRequestLineException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
