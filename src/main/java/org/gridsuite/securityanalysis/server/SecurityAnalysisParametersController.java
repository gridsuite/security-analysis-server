/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
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
import org.gridsuite.securityanalysis.server.dto.LimitReductionsByVoltageLevel;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisParametersService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
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
            @Parameter(description = "parameters values") @RequestBody SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        return ResponseEntity.ok().body(parametersService.createParameters(securityAnalysisParametersValues));
    }

    @PostMapping(value = "/default", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Create default parameters")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "parameters were created")})
    public ResponseEntity<UUID> createDefaultParameters() {
        return ResponseEntity.ok().body(parametersService.createDefaultParameters());
    }

    @PostMapping(value = "", params = "duplicateFrom", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Duplicate parameters")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "parameters were duplicated"),
        @ApiResponse(responseCode = "404", description = "source parameters were not found")})
    public ResponseEntity<UUID> duplicateParameters(
        @Parameter(description = "source parameters UUID") @RequestParam(name = "duplicateFrom") UUID sourceParametersUuid) {
        return parametersService.duplicateParameters(sourceParametersUuid).map(duplicatedParametersUuid -> ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body(duplicatedParametersUuid))
            .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping(value = "/{uuid}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Get parameters with the given id")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "parameters were returned"),
        @ApiResponse(responseCode = "404", description = "parameters were not found")})
    public ResponseEntity<SecurityAnalysisParametersValues> getParameters(
            @Parameter(description = "parameters UUID") @PathVariable(value = "uuid") UUID parametersUuid) {
        return parametersService.getParameters(parametersUuid)
                .map(parametersValues -> ResponseEntity.ok().body(parametersValues))
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping(value = "/{uuid}", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Update parameters or reset them to default if no parameters are given")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "parameters were updated"),
        @ApiResponse(responseCode = "404", description = "parameters were not found")})
    public ResponseEntity<UUID> updateParameters(
            @Parameter(description = "parameters UUID") @PathVariable(value = "uuid") UUID parametersUuid,
            @Parameter(description = "parameters values") @RequestBody(required = false) SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        return ResponseEntity.ok().body(parametersService.updateParameters(parametersUuid, securityAnalysisParametersValues));
    }

    @DeleteMapping(value = "/{uuid}", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete parameters")
    @ApiResponse(responseCode = "200", description = "parameters were deleted")
    public ResponseEntity<Void> deleteParameters(
            @Parameter(description = "parameters UUID") @PathVariable("uuid") UUID parametersUuid) {
        parametersService.deleteParameters(parametersUuid);
        return ResponseEntity.ok().build();
    }

    @PatchMapping(value = "/{uuid}/provider")
    @Operation(summary = "Update provider")
    @ApiResponse(responseCode = "200", description = "provider was updated")
    public ResponseEntity<Void> updateProvider(
            @Parameter(description = "parameters UUID") @PathVariable("uuid") UUID parametersUuid,
            @RequestBody(required = false) String provider) {
        parametersService.updateProvider(parametersUuid, provider);
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/default-limit-reductions", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Get default limit reductions")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The default limit reductions")})
    public ResponseEntity<List<LimitReductionsByVoltageLevel>> getDefaultLimitReductions() {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(parametersService.getDefaultLimitReductions());
    }

}
