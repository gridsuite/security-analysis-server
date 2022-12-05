/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.security.SecurityAnalysisResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisRunContext;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

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

    private static SecurityAnalysisParameters getNonNullParameters(SecurityAnalysisParameters parameters) {
        return parameters != null ? parameters : new SecurityAnalysisParameters();
    }

    @PostMapping(value = "/networks/{networkUuid}/run", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Run a security analysis on a network")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
                                        description = "The security analysis has been performed",
                                        content = {@Content(mediaType = APPLICATION_JSON_VALUE,
                                                            schema = @Schema(implementation = SecurityAnalysisResult.class))})})
    public ResponseEntity<Mono<SecurityAnalysisResult>> run(@Parameter(description = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                            @Parameter(description = "Variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                            @Parameter(description = "Other networks UUID (to merge with main one))") @RequestParam(name = "networkUuid", required = false) List<UUID> otherNetworkUuids,
                                                            @Parameter(description = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                            @Parameter(description = "Provider") @RequestParam(name = "provider", required = false) String provider,
                                                            @Parameter(description = "reportUuid") @RequestParam(name = "reportUuid", required = false) UUID reportUuid,
                                                            @Parameter(description = "reporterId") @RequestParam(name = "reporterId", required = false) String reporterId,
                                                            @RequestBody(required = false) SecurityAnalysisParameters parameters) {
        SecurityAnalysisParameters nonNullParameters = getNonNullParameters(parameters);
        List<UUID> nonNullOtherNetworkUuids = getNonNullOtherNetworkUuids(otherNetworkUuids);
        Mono<SecurityAnalysisResult> result = workerService.run(new SecurityAnalysisRunContext(networkUuid, variantId, nonNullOtherNetworkUuids, contigencyListNames, null, provider, nonNullParameters, reportUuid, reporterId));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result);
    }

    @PostMapping(value = "/networks/{networkUuid}/run-and-save", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Run a security analysis on a network and save results in the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200",
                                        description = "The security analysis has been performed and results have been save to database",
                                        content = {@Content(mediaType = APPLICATION_JSON_VALUE,
                                                            schema = @Schema(implementation = SecurityAnalysisResult.class))})})
    public ResponseEntity<Mono<UUID>> runAndSave(@Parameter(description = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                 @Parameter(description = "Variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                 @Parameter(description = "Other networks UUID (to merge with main one))") @RequestParam(name = "networkUuid", required = false) List<UUID> otherNetworkUuids,
                                                 @Parameter(description = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                 @Parameter(description = "Result receiver") @RequestParam(name = "receiver", required = false) String receiver,
                                                 @Parameter(description = "Provider") @RequestParam(name = "provider", required = false) String provider,
                                                 @Parameter(description = "reportUuid") @RequestParam(name = "reportUuid", required = false) UUID reportUuid,
                                                 @Parameter(description = "reporterId") @RequestParam(name = "reporterId", required = false) String reporterId,
                                                 @RequestBody(required = false) SecurityAnalysisParameters parameters) {
        SecurityAnalysisParameters nonNullParameters = getNonNullParameters(parameters);
        List<UUID> nonNullOtherNetworkUuids = getNonNullOtherNetworkUuids(otherNetworkUuids);
        Mono<UUID> resultUuid = service.runAndSaveResult(new SecurityAnalysisRunContext(networkUuid, variantId, nonNullOtherNetworkUuids, contigencyListNames, receiver, provider, nonNullParameters, reportUuid, reporterId));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(resultUuid);
    }

    @GetMapping(value = "/results/{resultUuid}", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
                           @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public Mono<ResponseEntity<SecurityAnalysisResult>> getResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                  @Parameter(description = "Limit type") @RequestParam(name = "limitType", required = false) List<String> limitTypes) {
        Set<LimitViolationType> limitTypeSet = limitTypes != null ? limitTypes.stream().map(LimitViolationType::valueOf).collect(Collectors.toSet())
                                                                  : Collections.emptySet();
        Mono<SecurityAnalysisResult> result = service.getResult(resultUuid, limitTypeSet);
        return result.map(r -> ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(r))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @DeleteMapping(value = "/results/{resultUuid}", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete a security analysis result from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result has been deleted")})
    public ResponseEntity<Mono<Void>> deleteResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        Mono<Void> result = service.deleteResult(resultUuid);
        return ResponseEntity.ok().body(result);
    }

    @DeleteMapping(value = "/results", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete all security analysis results from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "All security analysis results have been deleted")})
    public ResponseEntity<Mono<Void>> deleteResults() {
        Mono<Void> result = service.deleteResults();
        return ResponseEntity.ok().body(result);
    }

    @GetMapping(value = "/results/{resultUuid}/status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the security analysis status from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis status")})
    public ResponseEntity<Mono<SecurityAnalysisStatus>> getStatus(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        Mono<SecurityAnalysisStatus> result = service.getStatus(resultUuid);
        return ResponseEntity.ok().body(result);
    }

    @PutMapping(value = "/results/invalidate-status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Invalidate the security analysis status from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis status has been invalidated")})
    public ResponseEntity<Mono<Void>> invalidateStatus(@Parameter(description = "Result uuids") @RequestParam(name = "resultUuid") List<UUID> resultUuids) {
        return ResponseEntity.ok().body(service.setStatus(resultUuids, SecurityAnalysisStatus.NOT_DONE));
    }

    @PutMapping(value = "/results/{resultUuid}/stop", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Stop a security analysis computation")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis has been stopped")})
    public ResponseEntity<Mono<Void>> stop(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                           @Parameter(description = "Result receiver") @RequestParam(name = "receiver", required = false) String receiver) {
        Mono<Void> result = service.stop(resultUuid, receiver);
        return ResponseEntity.ok().body(result);
    }
}
