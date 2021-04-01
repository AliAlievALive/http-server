package tech.itpark.http.exception;

public class MalFormedRequestException extends RuntimeException {
    public MalFormedRequestException() {
        super();
    }

    public MalFormedRequestException(String message) {
        super(message);
    }

    public MalFormedRequestException(String message, Throwable cause) {
        super(message, cause);
    }

    public MalFormedRequestException(Throwable cause) {
        super(cause);
    }

    protected MalFormedRequestException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
