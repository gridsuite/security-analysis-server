/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Branch;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisResultService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisRunContext;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_PLAIN_VALUE;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@RestController
@RequestMapping(value = "/" + SecurityAnalysisApi.API_VERSION)
@Tag(name = "Security analysis server")
public class SecurityAnalysisController {
    private final SecurityAnalysisService securityAnalysisService;

    private final SecurityAnalysisResultService securityAnalysisResultService;

    private final SecurityAnalysisWorkerService workerService;

    public SecurityAnalysisController(SecurityAnalysisService securityAnalysisService, SecurityAnalysisWorkerService workerService, SecurityAnalysisResultService securityAnalysisResultService) {
        this.securityAnalysisService = securityAnalysisService;
        this.workerService = workerService;
        this.securityAnalysisResultService = securityAnalysisResultService;
    }

    @PostMapping(value = "/networks/{networkUuid}/run", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Run a security analysis on a network")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
                                        description = "The security analysis has been performed",
                                        content = {@Content(mediaType = APPLICATION_JSON_VALUE,
                                                            schema = @Schema(implementation = SecurityAnalysisResult.class))})})
    public ResponseEntity<SecurityAnalysisResult> run(@Parameter(description = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                            @Parameter(description = "Variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                            @Parameter(description = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                            @Parameter(description = "Provider") @RequestParam(name = "provider", required = false) String provider,
                                                            @Parameter(description = "reportUuid") @RequestParam(name = "reportUuid", required = false) UUID reportUuid,
                                                            @Parameter(description = "reporterId") @RequestParam(name = "reporterId", required = false) String reporterId,
                                                            @RequestBody(required = false) SecurityAnalysisParametersInfos parameters) {
        String providerToUse = provider != null ? provider : securityAnalysisService.getDefaultProvider();
        SecurityAnalysisResult result = workerService.run(new SecurityAnalysisRunContext(networkUuid, variantId, contigencyListNames, null, providerToUse, parameters, reportUuid, reporterId));

        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result);
    }

    @PostMapping(value = "/networks/{networkUuid}/run-and-save", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Run a security analysis on a network and save results in the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
                                        description = "The security analysis has been performed and results have been saved to database",
                                        content = {@Content(mediaType = APPLICATION_JSON_VALUE,
                                                            schema = @Schema(implementation = SecurityAnalysisResult.class))})})
    public ResponseEntity<UUID> runAndSave(@Parameter(description = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                 @Parameter(description = "Variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                 @Parameter(description = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                 @Parameter(description = "Result receiver") @RequestParam(name = "receiver", required = false) String receiver,
                                                 @Parameter(description = "Provider") @RequestParam(name = "provider", required = false) String provider,
                                                 @Parameter(description = "reportUuid") @RequestParam(name = "reportUuid", required = false) UUID reportUuid,
                                                 @Parameter(description = "reporterId") @RequestParam(name = "reporterId", required = false) String reporterId,
                                                 @RequestBody(required = false) SecurityAnalysisParametersInfos parameters) {
        String providerToUse = provider != null ? provider : securityAnalysisService.getDefaultProvider();
        UUID resultUuid = securityAnalysisService.runAndSaveResult(new SecurityAnalysisRunContext(networkUuid, variantId, contigencyListNames, receiver, providerToUse, parameters, reportUuid, reporterId));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(resultUuid);
    }

    @GetMapping(value = "/results/{resultUuid}/n-result", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - N result")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<List<PreContingencyLimitViolationResultDTO>> getNResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                                  @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String stringFilters,
                                                                                  Pageable pageable) {
        String decodedStringFilters = stringFilters != null ? URLDecoder.decode(stringFilters, StandardCharsets.UTF_8) : null;
        List<PreContingencyLimitViolationResultDTO> result = securityAnalysisResultService.findNResult(resultUuid, decodedStringFilters, pageable.getSort());

        return result != null
                ? ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result)
                : ResponseEntity.notFound().build();
    }

    @GetMapping(value = "/results/{resultUuid}/nmk-contingencies-result/paged", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - NMK contingencies result")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<Page<ContingencyResultDTO>> getNmKContingenciesResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                                    @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String stringFilters,
                                                                                    @Parameter(description = "Pagination parameters") Pageable pageable) {
        String decodedStringFilters = stringFilters != null ? URLDecoder.decode(stringFilters, StandardCharsets.UTF_8) : null;
        Page<ContingencyResultDTO> result = securityAnalysisResultService.findNmKContingenciesResult(resultUuid, decodedStringFilters, pageable);

        return result != null
            ? ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result)
            : ResponseEntity.notFound().build();
    }

    @GetMapping(value = "/results/{resultUuid}/nmk-constraints-result/paged", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - NMK contingencies result")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<Page<SubjectLimitViolationResultDTO>> getNmKConstraintsResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                                        @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String stringFilters,
                                                                                        @Parameter(description = "Pagination parameters") Pageable pageable) {
        String decodedStringFilters = stringFilters != null ? URLDecoder.decode(stringFilters, StandardCharsets.UTF_8) : null;
        Page<SubjectLimitViolationResultDTO> result = securityAnalysisResultService.findNmKConstraintsResult(resultUuid, decodedStringFilters, pageable);
        return result != null
            ? ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result)
            : ResponseEntity.notFound().build();
    }

    @DeleteMapping(value = "/results/{resultUuid}", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete a security analysis result from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result has been deleted")})
    public ResponseEntity<Void> deleteResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        securityAnalysisService.deleteResult(resultUuid);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping(value = "/results", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete all security analysis results from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "All security analysis results have been deleted")})
    public ResponseEntity<Void> deleteResults() {
        securityAnalysisService.deleteResults();
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/results/{resultUuid}/status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the security analysis status from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis status")})
    public ResponseEntity<SecurityAnalysisStatus> getStatus(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        SecurityAnalysisStatus result = securityAnalysisService.getStatus(resultUuid);
        return ResponseEntity.ok().body(result);
    }

    @PutMapping(value = "/results/invalidate-status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Invalidate the security analysis status from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis status has been invalidated")})
    public ResponseEntity<Void> invalidateStatus(@Parameter(description = "Result uuids") @RequestParam(name = "resultUuid") List<UUID> resultUuids) {
        securityAnalysisService.setStatus(resultUuids, SecurityAnalysisStatus.NOT_DONE);
        return ResponseEntity.ok().build();
    }

    @PutMapping(value = "/results/{resultUuid}/stop", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Stop a security analysis computation")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis has been stopped")})
    public ResponseEntity<Void> stop(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                           @Parameter(description = "Result receiver") @RequestParam(name = "receiver", required = false) String receiver) {
        securityAnalysisService.stop(resultUuid, receiver);
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/providers", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get all security analysis providers")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Security analysis providers have been found")})
    public ResponseEntity<List<String>> getProviders() {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(securityAnalysisService.getProviders());
    }

    @GetMapping(value = "/default-provider", produces = TEXT_PLAIN_VALUE)
    @Operation(summary = "Get security analysis default provider")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "The security analysis default provider has been found"))
    public ResponseEntity<String> getDefaultProvider() {
        return ResponseEntity.ok().body(securityAnalysisService.getDefaultProvider());
    }

    @GetMapping(value = "/limit-types", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get available limit types")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of available limit types"))
    public ResponseEntity<List<LimitViolationType>> getLimitTypes() {
        List<LimitViolationType> limitViolationTypesToRemove = List.of(LimitViolationType.HIGH_SHORT_CIRCUIT_CURRENT, LimitViolationType.LOW_SHORT_CIRCUIT_CURRENT, LimitViolationType.LOW_VOLTAGE_ANGLE, LimitViolationType.HIGH_VOLTAGE_ANGLE);
        return ResponseEntity.ok().body(Arrays.stream(LimitViolationType.values())
                .filter(lm -> !limitViolationTypesToRemove.contains(lm))
                .toList());
    }


    @GetMapping(value = "/branch-sides", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get available branch sides")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of available branch sides"))
    public ResponseEntity<Branch.Side[]> getBranchSides() {
        return ResponseEntity.ok().body(Branch.Side.values());
    }


    @GetMapping(value = "/computation-status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get available computation status")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of available computation status"))
    public ResponseEntity<LoadFlowResult.ComponentResult.Status[]> getComputationStatus() {
        return ResponseEntity.ok().body(LoadFlowResult.ComponentResult.Status.values());
    }
}
