/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.security.SecurityAnalysisResult;
import io.swagger.annotations.*;
import org.springframework.context.annotation.ComponentScan;
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
 */
@RestController
@RequestMapping(value = "/" + SecurityAnalysisApi.API_VERSION)
@Api(value = "Security analysis server")
@ComponentScan(basePackageClasses = {SecurityAnalysisService.class, NetworkStoreService.class})
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
    @ApiOperation(value = "Run a security analysis on a network", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @ApiResponses(value = {@ApiResponse(code = 200, message = "The security analysis has been performed")})
    public ResponseEntity<Mono<SecurityAnalysisResult>> run(@ApiParam(value = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                            @ApiParam(value = "Other networks UUID (to merge with main one))") @RequestParam(name = "networkUuid", required = false) List<UUID> otherNetworkUuids,
                                                            @ApiParam(value = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                            @RequestBody(required = false) SecurityAnalysisParameters parameters) {
        SecurityAnalysisParameters nonNullParameters = getNonNullParameters(parameters);
        List<UUID> nonNullOtherNetworkUuids = getNonNullOtherNetworkUuids(otherNetworkUuids);
        Mono<SecurityAnalysisResult> result = workerService.run(new SecurityAnalysisRunContext(networkUuid, nonNullOtherNetworkUuids, contigencyListNames, nonNullParameters));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result);
    }

    @PostMapping(value = "/networks/{networkUuid}/run-and-save", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @ApiOperation(value = "Run a security analysis on a network and save results in the database", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @ApiResponses(value = {@ApiResponse(code = 200, message = "The security analysis has been performed and results have been save to database")})
    public ResponseEntity<Mono<UUID>> runAndSave(@ApiParam(value = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                 @ApiParam(value = "Other networks UUID (to merge with main one))") @RequestParam(name = "networkUuid", required = false) List<UUID> otherNetworkUuids,
                                                 @ApiParam(value = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                 @RequestBody(required = false) SecurityAnalysisParameters parameters) {
        SecurityAnalysisParameters nonNullParameters = getNonNullParameters(parameters);
        List<UUID> nonNullOtherNetworkUuids = getNonNullOtherNetworkUuids(otherNetworkUuids);
        Mono<UUID> resultUuid = service.runAndSave(new SecurityAnalysisRunContext(networkUuid, nonNullOtherNetworkUuids, contigencyListNames, nonNullParameters));
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(resultUuid);
    }

    @GetMapping(value = "/results/{resultUuid}", produces = APPLICATION_JSON_VALUE)
    @ApiOperation(value = "Get a security analysis result from the database", produces = APPLICATION_JSON_VALUE)
    @ApiResponses(value = {@ApiResponse(code = 200, message = "The security analysis result")})
    public Mono<ResponseEntity<SecurityAnalysisResult>> getResult(@ApiParam(value = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                  @ApiParam(value = "Limit type") @RequestParam(name = "limitType", required = false) List<String> limitTypes) {
        Set<LimitViolationType> limitTypeSet = limitTypes != null ? limitTypes.stream().map(LimitViolationType::valueOf).collect(Collectors.toSet())
                                                                  : Collections.emptySet();
        Mono<SecurityAnalysisResult> result = service.getResult(resultUuid, limitTypeSet);
        return result.map(r -> ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(r))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @DeleteMapping(value = "/results/{resultUuid}", produces = APPLICATION_JSON_VALUE)
    @ApiOperation(value = "Delete a security analysis result from the database", produces = APPLICATION_JSON_VALUE)
    @ApiResponses(value = {@ApiResponse(code = 200, message = "The security analysis result has been deleted")})
    public ResponseEntity<Mono<Void>> deleteResult(@ApiParam(value = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        Mono<Void> result = service.deleteResult(resultUuid);
        return ResponseEntity.ok().body(result);
    }

    @DeleteMapping(value = "/results", produces = APPLICATION_JSON_VALUE)
    @ApiOperation(value = "Delete all security analysis results from the database", produces = APPLICATION_JSON_VALUE)
    @ApiResponses(value = {@ApiResponse(code = 200, message = "All security analysis results have been deleted")})
    public ResponseEntity<Mono<Void>> deleteResults() {
        Mono<Void> result = service.deleteResults();
        return ResponseEntity.ok().body(result);
    }
}
