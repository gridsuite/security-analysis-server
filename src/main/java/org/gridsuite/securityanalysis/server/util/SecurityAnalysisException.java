package org.gridsuite.securityanalysis.server.util;

import java.util.Objects;

public class SecurityAnalysisException extends RuntimeException {
    public enum Type {
        RESULT_NOT_FOUND,
        RUN_AS_ERROR
    }

    private final Type type;

    public SecurityAnalysisException(Type type) {
        super(Objects.requireNonNull(type.name()));
        this.type = type;
    }

    public SecurityAnalysisException(Type type, String message) {
        super(message);
        this.type = type;
    }

    public Type getType() {
        return type;
    }
}
