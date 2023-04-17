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
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersInfos;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisRunContext {

    private final UUID networkUuid;

    private final String variantId;

    private final List<UUID> otherNetworkUuids;

    private final List<String> contingencyListNames;

    private final String receiver;

    private final String provider;

    private final SecurityAnalysisParameters parameters;

    private final UUID reportUuid;

    private final String reporterId;

    public SecurityAnalysisRunContext(UUID networkUuid, String variantId, List<UUID> otherNetworkUuids, List<String> contingencyListNames,
                                      String receiver, String provider, SecurityAnalysisParametersInfos parameters, UUID reportUuid, String reporterId) {
        this.networkUuid = Objects.requireNonNull(networkUuid);
        this.variantId = variantId;
        this.otherNetworkUuids = Objects.requireNonNull(otherNetworkUuids);
        this.contingencyListNames = Objects.requireNonNull(contingencyListNames);
        this.receiver = receiver;
        this.provider = provider;
        this.parameters = buildParameters(parameters, provider);
        this.reportUuid = reportUuid;
        this.reporterId = reporterId;
    }

    public SecurityAnalysisRunContext(UUID networkUuid, String variantId, List<UUID> otherNetworkUuids, List<String> contingencyListNames,
                                      String receiver, String provider, SecurityAnalysisParameters parameters, UUID reportUuid, String reporterId) {
        this.networkUuid = Objects.requireNonNull(networkUuid);
        this.variantId = variantId;
        this.otherNetworkUuids = Objects.requireNonNull(otherNetworkUuids);
        this.contingencyListNames = Objects.requireNonNull(contingencyListNames);
        this.receiver = receiver;
        this.provider = provider;
        this.parameters = Objects.requireNonNull(parameters);
        this.reportUuid = reportUuid;
        this.reporterId = reporterId;
    }

    private SecurityAnalysisParameters buildParameters(SecurityAnalysisParametersInfos parameters, String provider) {
        SecurityAnalysisParameters params = parameters == null || parameters.getParameters() == null ?
                SecurityAnalysisParameters.load() : parameters.getParameters();
        if (parameters == null || parameters.getLoadFlowSpecificParameters() == null || parameters.getLoadFlowSpecificParameters().isEmpty()) {
            return params; // no specific LF params
        }
        LoadFlowProvider lfProvider = LoadFlowProvider.findAll().stream()
                .filter(p -> p.getName().equals(provider))
                .findFirst().orElseThrow(() -> new PowsyblException("Security analysis provider not found " + provider));
        Extension<LoadFlowParameters> extension = lfProvider.loadSpecificParameters(parameters.getLoadFlowSpecificParameters())
                .orElseThrow(() -> new PowsyblException("Cannot add specific loadflow parameters with security analysis provider " + provider));
        params.getLoadFlowParameters().addExtension((Class) extension.getClass(), extension);
        return params;
    }

    public UUID getNetworkUuid() {
        return networkUuid;
    }

    public String getVariantId() {
        return variantId;
    }

    public List<UUID> getOtherNetworkUuids() {
        return otherNetworkUuids;
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
}
