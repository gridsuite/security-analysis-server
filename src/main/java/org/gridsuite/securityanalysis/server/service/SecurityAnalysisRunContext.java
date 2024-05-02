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
import lombok.Setter;
import org.gridsuite.securityanalysis.server.computation.dto.ReportInfos;
import org.gridsuite.securityanalysis.server.computation.service.AbstractComputationRunContext;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.dto.LoadFlowParametersValues;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Getter
public class SecurityAnalysisRunContext extends AbstractComputationRunContext<SecurityAnalysisParameters> {

    private final List<String> contingencyListNames;
    @Setter
    private List<ContingencyInfos> contingencies;

    public SecurityAnalysisRunContext(UUID networkUuid, String variantId, List<String> contingencyListNames,
                                      String receiver, String provider, SecurityAnalysisParameters parameters, LoadFlowParametersValues loadFlowParametersValues,
                                      ReportInfos reportContext, String userId) {
        this(
                networkUuid,
                variantId,
                contingencyListNames,
                receiver,
                provider,
                buildParameters(parameters, loadFlowParametersValues, provider),
                new ReportInfos(reportContext.reportUuid(), reportContext.reporterId(), reportContext.computationType()),
                userId
        );
    }

    public SecurityAnalysisRunContext(UUID networkUuid, String variantId, List<String> contingencyListNames,
                                      String receiver, String provider, SecurityAnalysisParameters parameters,
                                      ReportInfos reportContext, String userId) {
        super(networkUuid, variantId, receiver, reportContext, userId, provider, parameters, null);
        this.contingencyListNames = Objects.requireNonNull(contingencyListNames);
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
