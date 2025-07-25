/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import org.gridsuite.computation.ComputationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@ControllerAdvice
public class RestResponseEntityExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(RestResponseEntityExceptionHandler.class);

    @ExceptionHandler(ComputationException.class)
    protected ResponseEntity<Object> handleStudyException(ComputationException exception) {
        if (LOGGER.isErrorEnabled()) {
            LOGGER.error(exception.getMessage());
        }
        switch (exception.getExceptionType()) {
            case RESULT_NOT_FOUND, PARAMETERS_NOT_FOUND:
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(exception.getExceptionType());
            case INVALID_FILTER_FORMAT, INVALID_FILTER, INVALID_SORT_FORMAT:
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(exception.getExceptionType());
            default:
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(exception.getExceptionType());
        }
    }
}
