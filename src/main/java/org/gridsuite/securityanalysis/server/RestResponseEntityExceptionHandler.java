package org.gridsuite.securityanalysis.server;

import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class RestResponseEntityExceptionHandler {

    @ExceptionHandler(SecurityAnalysisException.class)
    protected ResponseEntity<Object> handleStudyException(SecurityAnalysisException exception) {
        if (SecurityAnalysisException.Type.RESULT_NOT_FOUND.equals(exception.getType())) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(exception.getType());
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
