/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisParametersService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * @author Abdelsalem Hedhili <abdelsalem.hedhili at rte-france.com>
 */
@RestController
@RequestMapping(value = "/" + SecurityAnalysisApi.API_VERSION + "/parameters")
@Tag(name = "Security analysis parameters")
public class SecurityAnalysisParametersController {

    private final SecurityAnalysisParametersService parametersService;

    public SecurityAnalysisParametersController(SecurityAnalysisParametersService parametersService) {
        this.parametersService = parametersService;
    }

    @PostMapping(value = "", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Create parameters")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "parameters were created")})
    public ResponseEntity<UUID> createParameters(
            @Parameter(description = "parameters values") @RequestBody(required = false) SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        return ResponseEntity.ok().body(parametersService.createParameters(securityAnalysisParametersValues));
    }

    @PostMapping(value = "/duplicate", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Duplicate parameters")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "parameters were duplicated"),
        @ApiResponse(responseCode = "404", description = "source parameters were not found")})
    public ResponseEntity<UUID> duplicateParameters(
        @Parameter(description = "source parameters UUID") @RequestParam(name = "duplicateFrom") UUID sourceParametersUuid) {
        return parametersService.createParameters(sourceParametersUuid).map(duplicatedParametersUuid -> ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(duplicatedParametersUuid))
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Get parameters or default parameters if the id is not given")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "parameters were returned"),
        @ApiResponse(responseCode = "404", description = "parameters were not found")})
    public ResponseEntity<SecurityAnalysisParametersValues> getParameters(
            @Parameter(description = "parameters UUID") @RequestParam(value = "uuid", required = false) UUID parametersUuid) {
        return ResponseEntity.ok().body(parametersUuid == null ? SecurityAnalysisParametersService.getDefaultSecurityAnalysisParametersValues() : parametersService.getParameters(parametersUuid));
    }

    @PutMapping(value = "", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Update parameters")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "parameters were updated")})
    public ResponseEntity<UUID> updateParameters(
            @Parameter(description = "parameters UUID") @RequestParam(value = "uuid", required = false) UUID parametersUuid,
            @Parameter(description = "parameters values") @RequestBody(required = false) SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        return ResponseEntity.ok().body(parametersUuid == null ? parametersService.createParameters(securityAnalysisParametersValues) : parametersService.updateParameters(parametersUuid, securityAnalysisParametersValues));
    }

    @DeleteMapping(value = "/{uuid}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete parameters")
    @ApiResponse(responseCode = "200", description = "parameters were deleted")
    public ResponseEntity<Void> deleteParameters(
            @Parameter(description = "parameters UUID") @PathVariable("uuid") UUID parametersUuid) {
        parametersService.deleteParameters(parametersUuid);
        return ResponseEntity.ok().build();
    }
}
