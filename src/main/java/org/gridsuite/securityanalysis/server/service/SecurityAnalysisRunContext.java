/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.commons.PowsyblException;
import com.powsybl.commons.extensions.Extension;
import com.powsybl.loadflow.LoadFlowParameters;
import com.powsybl.loadflow.LoadFlowProvider;
import com.powsybl.security.SecurityAnalysisParameters;
import lombok.Getter;
import org.gridsuite.securityanalysis.server.dto.LoadFlowParametersValues;
import org.gridsuite.securityanalysis.server.dto.ReportInfos;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Getter
public class SecurityAnalysisRunContext {

    private final UUID networkUuid;

    private final String variantId;

    private final List<String> contingencyListNames;

    private final String receiver;

    private final String provider;

    private final SecurityAnalysisParameters parameters;

    private final UUID reportUuid;

    private final String reporterId;

    private final String userId;

    private final String reportType;

    public SecurityAnalysisRunContext(UUID networkUuid, String variantId, List<String> contingencyListNames,
                                      String receiver, String provider, SecurityAnalysisParameters parameters, LoadFlowParametersValues loadFlowParametersValues,
                                      ReportInfos reportInfos, String userId) {
        this(
                networkUuid,
                variantId,
                contingencyListNames,
                receiver,
                provider,
                buildParameters(parameters, loadFlowParametersValues, provider),
                new ReportInfos(reportInfos.getReportUuid(), reportInfos.getReporterId(), reportInfos.getReportType()),
                userId
        );
    }

    public SecurityAnalysisRunContext(UUID networkUuid, String variantId, List<String> contingencyListNames,
                                      String receiver, String provider, SecurityAnalysisParameters parameters,
                                      ReportInfos reportInfos, String userId) {
        this.networkUuid = Objects.requireNonNull(networkUuid);
        this.variantId = variantId;
        this.contingencyListNames = Objects.requireNonNull(contingencyListNames);
        this.receiver = receiver;
        this.provider = provider;
        this.parameters = Objects.requireNonNull(parameters);
        this.reportUuid = reportInfos.getReportUuid();
        this.reporterId = reportInfos.getReporterId();
        this.userId = userId;
        this.reportType = reportInfos.getReportType();
    }

    private static SecurityAnalysisParameters buildParameters(SecurityAnalysisParameters securityAnalysisParameters,
                                                              LoadFlowParametersValues loadFlowParametersValues,
                                                              String provider) {
        Objects.requireNonNull(loadFlowParametersValues);
        if (loadFlowParametersValues.getCommonParameters() == null) {
            securityAnalysisParameters.setLoadFlowParameters(new LoadFlowParameters());
        } else {
            securityAnalysisParameters.setLoadFlowParameters(loadFlowParametersValues.getCommonParameters());
        }

        if (loadFlowParametersValues.getSpecificParameters() == null || loadFlowParametersValues.getSpecificParameters().isEmpty()) {
            return securityAnalysisParameters; // no specific LF params
        }
        LoadFlowProvider lfProvider = LoadFlowProvider.findAll().stream()
                .filter(p -> p.getName().equals(provider))
                .findFirst().orElseThrow(() -> new PowsyblException("Security analysis provider not found " + provider));
        Extension<LoadFlowParameters> extension = lfProvider.loadSpecificParameters(loadFlowParametersValues.getSpecificParameters())
                .orElseThrow(() -> new PowsyblException("Cannot add specific loadflow parameters with security analysis provider " + provider));
        securityAnalysisParameters.getLoadFlowParameters().addExtension((Class) extension.getClass(), extension);
        return securityAnalysisParameters;
    }
}
