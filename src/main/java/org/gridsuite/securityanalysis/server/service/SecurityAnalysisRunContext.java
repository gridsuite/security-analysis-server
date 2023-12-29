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
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisAdditionalParametersInfos;

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
                                      String receiver, String provider, SecurityAnalysisParameters parameters, SecurityAnalysisAdditionalParametersInfos additionalParameters,
                                      UUID reportUuid, String reporterId, String reportType, String userId) {
        this(networkUuid, variantId, contingencyListNames, receiver, provider, buildParameters(parameters, additionalParameters, provider), reportUuid, reporterId, reportType, userId);
    }

    public SecurityAnalysisRunContext(UUID networkUuid, String variantId, List<String> contingencyListNames,
                                      String receiver, String provider, SecurityAnalysisParameters parameters,
                                      UUID reportUuid, String reporterId, String reportType, String userId) {
        this.networkUuid = Objects.requireNonNull(networkUuid);
        this.variantId = variantId;
        this.contingencyListNames = Objects.requireNonNull(contingencyListNames);
        this.receiver = receiver;
        this.provider = provider;
        this.parameters = Objects.requireNonNull(parameters);
        this.reportUuid = reportUuid;
        this.reporterId = reporterId;
        this.userId = userId;
        this.reportType = reportType;
    }

    private static SecurityAnalysisParameters buildParameters(SecurityAnalysisParameters securityAnalysisParameters,
                                                              SecurityAnalysisAdditionalParametersInfos securityAnalysisAdditionalParametersInfos,
                                                              String provider) {
        if (securityAnalysisAdditionalParametersInfos == null || securityAnalysisAdditionalParametersInfos.getLoadFlowParameters() == null) {
            securityAnalysisParameters.setLoadFlowParameters(new LoadFlowParameters());
        } else {
            securityAnalysisParameters.setLoadFlowParameters(securityAnalysisAdditionalParametersInfos.getLoadFlowParameters());
        }

        if (securityAnalysisAdditionalParametersInfos == null || securityAnalysisAdditionalParametersInfos.getSpecificLoadFlowParameters() == null || securityAnalysisAdditionalParametersInfos.getSpecificLoadFlowParameters().isEmpty()) {
            return securityAnalysisParameters; // no specific LF params
        }
        LoadFlowProvider lfProvider = LoadFlowProvider.findAll().stream()
                .filter(p -> p.getName().equals(provider))
                .findFirst().orElseThrow(() -> new PowsyblException("Security analysis provider not found " + provider));
        Extension<LoadFlowParameters> extension = lfProvider.loadSpecificParameters(securityAnalysisAdditionalParametersInfos.getSpecificLoadFlowParameters())
                .orElseThrow(() -> new PowsyblException("Cannot add specific loadflow parameters with security analysis provider " + provider));
        securityAnalysisParameters.getLoadFlowParameters().addExtension((Class) extension.getClass(), extension);
        return securityAnalysisParameters;
    }

    public UUID getNetworkUuid() {
        return networkUuid;
    }

    public String getVariantId() {
        return variantId;
    }

    public List<String> getContingencyListNames() {
        return contingencyListNames;
    }

    public String getReceiver() {
        return receiver;
    }

    public String getProvider() {
        return provider;
    }

    public SecurityAnalysisParameters getParameters() {
        return parameters;
    }

    public UUID getReportUuid() {
        return reportUuid;
    }

    public String getReporterId() {
        return reporterId;
    }

    public String getReportType() {
        return reportType;
    }
}
