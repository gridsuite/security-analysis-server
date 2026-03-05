/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.security.SecurityAnalysisResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisOnCaseService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisParametersService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@RestController
@RequestMapping(value = "/" + SecurityAnalysisApi.API_VERSION + "/cases")
@Tag(name = "Security analysis server on case")
public class SecurityAnalysisOnCaseController {
    private final SecurityAnalysisOnCaseService securityAnalysisOnCaseService;

    public SecurityAnalysisOnCaseController(SecurityAnalysisOnCaseService securityAnalysisOnCaseService, SecurityAnalysisParametersService securityAnalysisParametersService) {
        this.securityAnalysisOnCaseService = securityAnalysisOnCaseService;
    }

    @PostMapping(value = "/{caseUuid}/run-and-save", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Run a security analysis on a case and store the result in the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
                                        description = "The security analysis has been performed and results have been saved to database",
                                        content = {@Content(mediaType = APPLICATION_JSON_VALUE,
                                                            schema = @Schema(implementation = SecurityAnalysisResult.class))})})
    public ResponseEntity<UUID> runAndSave(@Parameter(description = "Case UUID") @PathVariable("caseUuid") UUID caseUuid,
                                           @Parameter(description = "Execution UUID") @RequestParam(name = "executionUuid", required = false) UUID executionUuid,
                                           @Parameter(description = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                           @Parameter(description = "parametersUuid") @RequestParam(name = "parametersUuid", required = false) UUID parametersUuid,
                                           @Parameter(description = "loadFlow parameters uuid") @RequestParam(name = "loadFlowParametersUuid", required = false) UUID loadFlowParametersUuid) {
        securityAnalysisOnCaseService.runAndSaveResult(caseUuid, executionUuid, contigencyListNames, parametersUuid, loadFlowParametersUuid);
        return ResponseEntity.ok().build();
    }
}
