/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.commons.datasource.MemDataSource;
import com.powsybl.commons.report.ReportNode;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.LineContingency;
import com.powsybl.iidm.network.Network;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisReport;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.SecurityAnalysisRunParameters;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisOnCaseWorkerService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisOnCaseWorkerService.class);

    private final NetworkConversionService networkConversionService;
    private final NotificationOnCaseService notificationOnCaseService;
    private final ReportOnCaseService reportOnCaseService;
    private final SecurityAnalysisResultService resultService;

    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;
    private final String caseExportFormat = "XIIDM";

    public SecurityAnalysisOnCaseWorkerService(NetworkConversionService networkConversionService,
                                               NotificationOnCaseService notificationOnCaseService,
                                               SecurityAnalysisResultService resultService,
                                               ReportOnCaseService reportOnCaseService,
                                               ObjectMapper objectMapper,
                                               RestTemplateBuilder restTemplateBuilder,
                                               @Value("${powsybl.services.case-server.base-uri:http://case-server}") String caseServerBaseUri) {
        this.networkConversionService = networkConversionService;
        this.notificationOnCaseService = notificationOnCaseService;
        this.reportOnCaseService = reportOnCaseService;
        this.resultService = resultService;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplateBuilder.rootUri(caseServerBaseUri).build();
    }

    private void saveResult(Network network, UUID resultUuid, SecurityAnalysisResult result) {
        resultService.insert(network,
            resultUuid,
            result,
            result.getPreContingencyResult().getStatus() == LoadFlowResult.ComponentResult.Status.CONVERGED
                ? SecurityAnalysisStatus.CONVERGED
                : SecurityAnalysisStatus.DIVERGED);
    }

    private Network loadNetworkFromCase(UUID caseUuid, ReportNode reportNode) {
        return networkConversionService.createNetwork(caseUuid, reportNode);
    }

    private UUID save(Resource resource) {
        String uri = "/v1/cases";

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        body.add("file", resource);
        HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

        return restTemplate.postForObject(uri, request, UUID.class);
    }

    private UUID save(Network network) throws IOException {
        MemDataSource memDataSource = new MemDataSource();
        network.write(this.caseExportFormat, null, memDataSource);

        Set<String> listNames = memDataSource.listNames(".*");
        String caseFileName = "security-analysis-output." + this.caseExportFormat.toLowerCase();
        return save(new ByteArrayResource(memDataSource.getData(listNames.toArray()[0].toString())) {
            @Override
            public String getFilename() {
                return caseFileName;
            }
        });
    }

    @Bean
    public Consumer<Message<String>> consumeCaseRun() {
        return message -> {
            UUID executionUuid = null;
            UUID resultCaseUuid = null;
            UUID reportUuid = null;
            UUID resultUuid = null;
            String status = "COMPLETED";

            try {
                SecurityAnalysisCaseContext context = SecurityAnalysisCaseContext.fromMessage(message, objectMapper);
                UUID caseUuid = context.getCaseUuid();
                executionUuid = context.getExecutionUuid();
                List<String> contingencyListNames = context.getContigencyListNames();

                ReportNode rootReport = ReportNode.newRootReportNode()
                    .withAllResourceBundlesFromClasspath()
                    .withMessageTemplate("security.analysis.server.caseUuid")
                    .withUntypedValue("caseUuid", caseUuid.toString())
                    .build();

                LOGGER.info("Run security analysis on case {}", caseUuid);

                // create network from case
                Network network = loadNetworkFromCase(caseUuid, rootReport);

                // run security analysis
                List<Contingency> contingencyList = contingencyListNames.stream().map(id -> new Contingency(id, new LineContingency(id))).toList();
                SecurityAnalysisRunParameters runParameters = new SecurityAnalysisRunParameters().setReportNode(rootReport);
                SecurityAnalysisReport saReport = SecurityAnalysis.find("OpenLoadFlow").run(network, contingencyList, runParameters);
                SecurityAnalysisResult result = saReport.getResult();

                // save result
                resultUuid = UUID.randomUUID();
                saveResult(network, resultUuid, result);

                // send report to report server
                reportUuid = UUID.randomUUID();
                reportOnCaseService.sendReport(reportUuid, rootReport);

                // save network in case server
                resultCaseUuid = save(network);
            } catch (Exception e) {
                status = "FAILED";
            } finally {
                // send notification
                notificationOnCaseService.sendMessage(MessageBuilder.withPayload(new CaseResultInfos(resultCaseUuid, executionUuid, reportUuid, resultUuid, "SECURITY_ANALYSIS", status)).build(), "CaseResult-out-0");
            }
        };
    }
}
