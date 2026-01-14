/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.gridsuite.computation.dto.ReportInfos;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisParametersService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisResultService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.gridsuite.computation.service.NotificationService.HEADER_USER_ID;
import static org.springframework.http.MediaType.*;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@RestController
@RequestMapping(value = "/" + SecurityAnalysisApi.API_VERSION)
@Tag(name = "Security analysis server")
public class SecurityAnalysisController {
    private final SecurityAnalysisService securityAnalysisService;

    private final SecurityAnalysisParametersService securityAnalysisParametersService;

    private final SecurityAnalysisResultService securityAnalysisResultService;

    private final SecurityAnalysisWorkerService workerService;

    public SecurityAnalysisController(SecurityAnalysisService securityAnalysisService, SecurityAnalysisWorkerService workerService, SecurityAnalysisResultService securityAnalysisResultService, SecurityAnalysisParametersService securityAnalysisParametersService) {
        this.securityAnalysisService = securityAnalysisService;
        this.workerService = workerService;
        this.securityAnalysisResultService = securityAnalysisResultService;
        this.securityAnalysisParametersService = securityAnalysisParametersService;
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
                                                      @Parameter(description = "The type name for the report") @RequestParam(name = "reportType", required = false, defaultValue = "SecurityAnalysis") String reportType,
                                                      @Parameter(description = "parametersUuid") @RequestParam(name = "parametersUuid", required = false) UUID parametersUuid,
                                                      @Parameter(description = "loadFlow parameters uuid") @RequestParam(name = "loadFlowParametersUuid") UUID loadFlowParametersUuid,
                                                      @RequestHeader(HEADER_USER_ID) String userId) {
        SecurityAnalysisResult result = workerService.run(
                securityAnalysisParametersService.createRunContext(
                        networkUuid,
                        variantId,
                        new RunContextParametersInfos(contigencyListNames, parametersUuid, loadFlowParametersUuid),
                        null,
                        new ReportInfos(reportUuid, reporterId, reportType),
                        userId));
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
                                           @Parameter(description = "reportUuid") @RequestParam(name = "reportUuid", required = false) UUID reportUuid,
                                           @Parameter(description = "reporterId") @RequestParam(name = "reporterId", required = false) String reporterId,
                                           @Parameter(description = "The type name for the report") @RequestParam(name = "reportType", required = false, defaultValue = "SecurityAnalysis") String reportType,
                                           @Parameter(description = "parametersUuid") @RequestParam(name = "parametersUuid", required = false) UUID parametersUuid,
                                           @Parameter(description = "loadFlow parameters uuid") @RequestParam(name = "loadFlowParametersUuid") UUID loadFlowParametersUuid,
                                           @RequestHeader(HEADER_USER_ID) String userId) {
        UUID resultUuid = securityAnalysisService.runAndSaveResult(
                securityAnalysisParametersService.createRunContext(
                        networkUuid,
                        variantId,
                        new RunContextParametersInfos(contigencyListNames, parametersUuid, loadFlowParametersUuid),
                        receiver,
                        new ReportInfos(reportUuid, reporterId, reportType),
                        userId
                )
        );
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(resultUuid);
    }

    @GetMapping(value = "/results/{resultUuid}/n-result", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - N result")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<List<PreContingencyLimitViolationResultDTO>> getNResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                                  @Parameter(description = "network Uuid") @RequestParam(name = "networkUuid", required = false) UUID networkUuid,
                                                                                  @Parameter(description = "variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                                                  @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String stringFilters,
                                                                                  @Parameter(description = "Global Filters") @RequestParam(name = "globalFilters", required = false) String globalFilters,
                                                                                  @Parameter(description = "Pageable parameters for pagination and sorting") Sort sort) {
        String decodedStringFilters = stringFilters != null ? URLDecoder.decode(stringFilters, StandardCharsets.UTF_8) : null;
        String decodedStringGlobalFilters = globalFilters != null ? URLDecoder.decode(globalFilters, StandardCharsets.UTF_8) : null;
        List<PreContingencyLimitViolationResultDTO> result = securityAnalysisResultService.findNResult(
                resultUuid,
                networkUuid,
                variantId,
                decodedStringFilters,
                decodedStringGlobalFilters,
                sort);

        return result != null
                ? ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result)
                : ResponseEntity.notFound().build();
    }

    @PostMapping(value = "/results/{resultUuid}/n-result/csv", produces = APPLICATION_OCTET_STREAM_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - N result - CSV export")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result csv export"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<byte[]> getNResultZippedCsv(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                      @Parameter(description = "network Uuid") @RequestParam(name = "networkUuid", required = false) UUID networkUuid,
                                                      @Parameter(description = "variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                      @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String filters,
                                                      @Parameter(description = "Global Filters") @RequestParam(name = "globalFilters", required = false) String globalFilters,
                                                      @Parameter(description = "Translation properties") @RequestBody CsvTranslationDTO csvTranslations,
                                                      @Parameter(description = "Sort parameters") Sort sort) {
        String decodedStringFilters = filters != null ? URLDecoder.decode(filters, StandardCharsets.UTF_8) : null;
        String decodedStringGlobalFilters = globalFilters != null ? URLDecoder.decode(globalFilters, StandardCharsets.UTF_8) : null;
        return ResponseEntity.ok()
            .contentType(APPLICATION_OCTET_STREAM)
            .body(securityAnalysisResultService.findNResultZippedCsv(
                    resultUuid,
                    networkUuid,
                    variantId,
                    decodedStringFilters,
                    decodedStringGlobalFilters,
                    sort,
                    csvTranslations
            ));
    }

    @GetMapping(value = "/results/{resultUuid}/nmk-contingencies-result/paged", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - NMK contingencies result")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<Page<ContingencyResultDTO>> getNmKContingenciesResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                                @Parameter(description = "network Uuid") @RequestParam(name = "networkUuid", required = false) UUID networkUuid,
                                                                                @Parameter(description = "variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                                                @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String stringFilters,
                                                                                @Parameter(description = "Global Filters") @RequestParam(name = "globalFilters", required = false) String globalFilters,
                                                                                @Parameter(description = "Pagination parameters") Pageable pageable) {
        String decodedStringFilters = stringFilters != null ? URLDecoder.decode(stringFilters, StandardCharsets.UTF_8) : null;
        String decodedStringGlobalFilters = globalFilters != null ? URLDecoder.decode(globalFilters, StandardCharsets.UTF_8) : null;
        Page<ContingencyResultDTO> result = securityAnalysisResultService.findNmKContingenciesPaged(resultUuid, networkUuid, variantId, decodedStringFilters, decodedStringGlobalFilters, pageable);

        return result != null
            ? ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result)
            : ResponseEntity.notFound().build();
    }

    @PostMapping(value = "/results/{resultUuid}/nmk-contingencies-result/csv", produces = APPLICATION_OCTET_STREAM_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - NMK contingencies result - CSV export")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result csv export"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<byte[]> getNmKContingenciesResultZippedCsv(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                     @Parameter(description = "network Uuid") @RequestParam(name = "networkUuid", required = false) UUID networkUuid,
                                                                     @Parameter(description = "variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                                     @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String filters,
                                                                     @Parameter(description = "Global Filters") @RequestParam(name = "globalFilters", required = false) String globalFilters,
                                                                     @Parameter(description = "Translation properties") @RequestBody CsvTranslationDTO csvTranslations,
                                                                     @Parameter(description = "Sort parameters") Sort sort) {
        String decodedStringFilters = filters != null ? URLDecoder.decode(filters, StandardCharsets.UTF_8) : null;
        String decodedStringGlobalFilters = globalFilters != null ? URLDecoder.decode(globalFilters, StandardCharsets.UTF_8) : null;
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .body(securityAnalysisResultService.findNmKContingenciesResultZippedCsv(
                    resultUuid,
                    networkUuid,
                    variantId,
                    decodedStringFilters,
                    decodedStringGlobalFilters,
                    sort,
                    csvTranslations
            ));
    }

    @GetMapping(value = "/results/{resultUuid}/nmk-constraints-result/paged", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - NMK constraints result")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<Page<SubjectLimitViolationResultDTO>> getNmKConstraintsResult(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                                        @Parameter(description = "network Uuid") @RequestParam(name = "networkUuid", required = false) UUID networkUuid,
                                                                                        @Parameter(description = "variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                                                        @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String stringFilters,
                                                                                        @Parameter(description = "Global Filters") @RequestParam(name = "globalFilters", required = false) String globalFilters,
                                                                                        @Parameter(description = "Pagination parameters") Pageable pageable) {
        String decodedStringFilters = stringFilters != null ? URLDecoder.decode(stringFilters, StandardCharsets.UTF_8) : null;
        String decodedStringGlobalFilters = globalFilters != null ? URLDecoder.decode(globalFilters, StandardCharsets.UTF_8) : null;
        Page<SubjectLimitViolationResultDTO> result = securityAnalysisResultService.findNmKConstraintsResultPaged(resultUuid, networkUuid, variantId, decodedStringFilters, decodedStringGlobalFilters, pageable);
        return result != null
            ? ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result)
            : ResponseEntity.notFound().build();
    }

    @PostMapping(value = "/results/{resultUuid}/nmk-constraints-result/csv", produces = APPLICATION_OCTET_STREAM_VALUE, consumes = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get a security analysis result from the database - NMK constraints result - CSV export")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "The security analysis result csv export"),
        @ApiResponse(responseCode = "404", description = "Security analysis result has not been found")})
    public ResponseEntity<byte[]> getNmKContraintsResultZippedCsv(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid,
                                                                  @Parameter(description = "network Uuid") @RequestParam(name = "networkUuid", required = false) UUID networkUuid,
                                                                  @Parameter(description = "variant Id") @RequestParam(name = "variantId", required = false) String variantId,
                                                                  @Parameter(description = "Filters") @RequestParam(name = "filters", required = false) String filters,
                                                                  @Parameter(description = "Global Filters") @RequestParam(name = "globalFilters", required = false) String globalFilters,
                                                                  @Parameter(description = "Translation properties") @RequestBody CsvTranslationDTO csvTranslations,
                                                                  @Parameter(description = "Sort parameters") Sort sort) {
        String decodedStringFilters = filters != null ? URLDecoder.decode(filters, StandardCharsets.UTF_8) : null;
        String decodedStringGlobalFilters = globalFilters != null ? URLDecoder.decode(globalFilters, StandardCharsets.UTF_8) : null;
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(securityAnalysisResultService.findNmKConstraintsResultZippedCsv(
                        resultUuid,
                        networkUuid,
                        variantId,
                        decodedStringFilters,
                        decodedStringGlobalFilters,
                        sort,
                        csvTranslations
                ));
    }

    @DeleteMapping(value = "/results", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Delete all security analysis results from the database")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "All security analysis results have been deleted")})
    public ResponseEntity<Void> deleteResults(@Parameter(description = "Results UUID") @RequestParam(value = "resultsUuids", required = false) List<UUID> resultsUuids) {
        securityAnalysisService.deleteResults(resultsUuids);
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
                                     @Parameter(description = "Result receiver") @RequestParam(name = "receiver", required = false) String receiver,
                                     @RequestHeader(HEADER_USER_ID) String userId) {
        securityAnalysisService.stop(resultUuid, receiver, userId);
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

    @GetMapping(value = "/results/{resultUuid}/n-limit-types", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the list of limit types values - N results")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of limit types values by result - N results"))
    public ResponseEntity<List<LimitViolationType>> getNResultLimitTypes(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(securityAnalysisService.getNResultLimitTypes(resultUuid));
    }

    @GetMapping(value = "/results/{resultUuid}/nmk-limit-types", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the list of limit types values  - NmK results")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of limit types values by result - NmK results"))
    public ResponseEntity<List<LimitViolationType>> getNmKResultLimitTypes(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(securityAnalysisService.getNmKResultLimitTypes(resultUuid));
    }

    @GetMapping(value = "/results/{resultUuid}/n-branch-sides", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the list of branch sides values - N results")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of branch sides values by result - N results"))
    public ResponseEntity<List<ThreeSides>> getNResultBranchSides(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(securityAnalysisService.getNResultBranchSides(resultUuid));
    }

    @GetMapping(value = "/results/{resultUuid}/nmk-branch-sides", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the list of branch sides values - NmK results")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of branch sides values by result - NmK results"))
    public ResponseEntity<List<ThreeSides>> getNmKResultBranchSides(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(securityAnalysisService.getNmKResultBranchSides(resultUuid));
    }

    @GetMapping(value = "/results/{resultUuid}/nmk-computation-status", produces = APPLICATION_JSON_VALUE)
    @Operation(summary = "Get the list of computation status values - NmK results")
    @ApiResponses(@ApiResponse(responseCode = "200", description = "List of computation status values by result - NmK results"))
    public ResponseEntity<List<com.powsybl.loadflow.LoadFlowResult.ComponentResult.Status>> getNmKResultComputationStatus(@Parameter(description = "Result UUID") @PathVariable("resultUuid") UUID resultUuid) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(securityAnalysisService.getNmKComputationStatus(resultUuid));
    }
}
