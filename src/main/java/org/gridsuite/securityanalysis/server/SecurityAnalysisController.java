/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.results.PreContingencyResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisRunContext;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
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
    private final SecurityAnalysisService service;

    private final SecurityAnalysisWorkerService workerService;

    public SecurityAnalysisController(SecurityAnalysisService service, SecurityAnalysisWorkerService workerService) {
        this.service = service;
        this.workerService = workerService;
    }

    private static List<UUID> getNonNullOtherNetworkUuids(List<UUID> otherNetworkUuids) {
        return otherNetworkUuids != null ? otherNetworkUuids : Collections.emptyList();
    }

    @PostMapping(value = "/networks/{networkUuid}/run", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Run a security analysis on a network")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
                                        description = "The security analysis has been performed",
                                        content = {@Content(mediaType = APPLICATION_JSON_VALUE,
                                                            schema = @Schema(implementation = SecurityAnalysisResult.class))})})
    public ResponseEntity<SecurityAnalysisResult> run(@Parameter(description = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                            @Parameter(description = "Variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                            @Parameter(description = "Other networks UUID (to merge with main one))") @RequestParam(name = "networkUuid", required = false) List<UUID> otherNetworkUuids,
                                                            @Parameter(description = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                            @Parameter(description = "Provider") @RequestParam(name = "provider", required = false) String provider,
                                                            @Parameter(description = "reportUuid") @RequestParam(name = "reportUuid", required = false) UUID reportUuid,
                                                            @Parameter(description = "reporterId") @RequestParam(name = "reporterId", required = false) String reporterId,
                                                            @RequestBody(required = false) SecurityAnalysisParametersInfos parameters) {
        String providerToUse = provider != null ? provider : service.getDefaultProvider();
        List<UUID> nonNullOtherNetworkUuids = getNonNullOtherNetworkUuids(otherNetworkUuids);
        SecurityAnalysisResult result = workerService.run(new SecurityAnalysisRunContext(networkUuid, variantId, nonNullOtherNetworkUuids, contigencyListNames, null, providerToUse, parameters, reportUuid, reporterId));
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
                                                 @Parameter(description = "Other networks UUID (to merge with main one))") @RequestParam(name = "networkUuid", required = false) List<UUID> otherNetworkUuids,
                                                 @Parameter(description = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                 @Parameter(description = "Result receiver") @RequestParam(name = "receiver", required = false) String receiver,
                                                 @Parameter(description = "Provider") @RequestParam(name = "provider", required = false) String provider,
                                                 @Parameter(description = "reportUuid") @RequestParam(name = "reportUuid", required = false) UUID reportUuid,
                                                 @Parameter(description = "reporterId") @RequestParam(name = "reporterId", required = false) String reporterId,
                                                 @RequestBody(required = false) SecurityAnalysisParametersInfos parameters) {
        String providerToUse = provider != null ? provider : service.getDefaultProvider();
        List<UUID> nonNullOtherNetworkUuids = getNonNullOtherNetworkUuids(otherNetworkUuids);
        UUID resultUuid = service.runAndSaveResult(new SecurityAnalysisRunContext(networkUuid, variantId, nonNullOtherNetworkUuids, contigencyListNames, receiver, providerToUse, parameters, reportUuid, reporterId));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(resultUuid);
    }

    @GetMapping(value = "/results/{resultUuid}/n-result/paged", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - N result")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
            @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<PreContingencyResult> getNResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                           @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String stringFilters,
                                                           Pageable pageable) throws JsonProcessingException {
        List<FilterDTO> filters = FilterDTO.fromStringToList(stringFilters);
        PreContingencyResult result = service.getNResult(resultUuid, filters, pageable.getSort());

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
                                                                                      Pageable pageable) throws JsonProcessingException {
        List<FilterDTO> filters = FilterDTO.fromStringToList(stringFilters);
        Page<ContingencyResultDTO> result = service.getNmKContingenciesResult(resultUuid, filters, pageable);

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
                                                                                        Pageable pageable) throws JsonProcessingException {
        List<FilterDTO> filters = FilterDTO.fromStringToList(stringFilters);
        Page<SubjectLimitViolationResultDTO> result = service.getNmKConstraintsResult(resultUuid, filters, pageable);
        return result != null
            ? ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result)
            : ResponseEntity.notFound().build();
    }

    @DeleteMapping(value = "/results/{resultUuid}", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete a security analysis result from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result has been deleted")})
    public ResponseEntity<Void> deleteResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        service.deleteResult(resultUuid);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping(value = "/results", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete all security analysis results from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "All security analysis results have been deleted")})
    public ResponseEntity<Void> deleteResults() {
        service.deleteResults();
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/results/{resultUuid}/status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the security analysis status from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis status")})
    public ResponseEntity<SecurityAnalysisStatus> getStatus(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        SecurityAnalysisStatus result = service.getStatus(resultUuid);
        return ResponseEntity.ok().body(result);
    }

    @PutMapping(value = "/results/invalidate-status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Invalidate the security analysis status from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis status has been invalidated")})
    public ResponseEntity<Void> invalidateStatus(@Parameter(description = "Result uuids") @RequestParam(name = "resultUuid") List<UUID> resultUuids) {
        service.setStatus(resultUuids, SecurityAnalysisStatus.NOT_DONE);
        return ResponseEntity.ok().build();
    }

    @PutMapping(value = "/results/{resultUuid}/stop", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Stop a security analysis computation")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis has been stopped")})
    public ResponseEntity<Void> stop(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                           @Parameter(description = "Result receiver") @RequestParam(name = "receiver", required = false) String receiver) {
        service.stop(resultUuid, receiver);
        return ResponseEntity.ok().build();
    }

    @GetMapping(value = "/providers", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get all security analysis providers")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Security analysis providers have been found")})
    public ResponseEntity<List<String>> getProviders() {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(service.getProviders());
    }

    @GetMapping(value = "/default-provider", produces = TEXT_PLAIN_VALUE)
    @Operation(summary = "Get security analysis default provider")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "The security analysis default provider has been found"))
    public ResponseEntity<String> getDefaultProvider() {
        return ResponseEntity.ok().body(service.getDefaultProvider());
    }
}
