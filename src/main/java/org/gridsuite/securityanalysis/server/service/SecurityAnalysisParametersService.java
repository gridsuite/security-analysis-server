/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.ws.commons.computation.dto.ReportInfos;
import org.gridsuite.securityanalysis.server.dto.LoadFlowParametersValues;
import org.gridsuite.securityanalysis.server.dto.RunContextParametersInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisParametersRepository;
import org.gridsuite.securityanalysis.server.util.LimitReductionConfig;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static org.gridsuite.securityanalysis.server.util.SecurityAnalysisException.Type.PARAMETERS_NOT_FOUND;

/**
 * @author Abdelsalem HEDHILI <abdelsalem.hedhili@rte-france.com>
 */
@Service
public class SecurityAnalysisParametersService {

    private final SecurityAnalysisParametersRepository securityAnalysisParametersRepository;

    private final LoadFlowService loadFlowService;

    private final String defaultProvider;

    private final LimitReductionConfig limitReductionConfig;

    private static final double DEFAULT_FLOW_PROPORTIONAL_THRESHOLD = 0.1; // meaning 10.0 %
    private static final double DEFAULT_LOW_VOLTAGE_PROPORTIONAL_THRESHOLD = 0.01; // meaning 1.0 %
    private static final double DEFAULT_HIGH_VOLTAGE_PROPORTIONAL_THRESHOLD = 0.01; // meaning 1.0 %
    private static final double DEFAULT_LOW_VOLTAGE_ABSOLUTE_THRESHOLD = 1.0; // 1.0 kV
    private static final double DEFAULT_HIGH_VOLTAGE_ABSOLUTE_THRESHOLD = 1.0; // 1.0 kV

    public SecurityAnalysisParametersService(SecurityAnalysisParametersRepository securityAnalysisParametersRepository, LoadFlowService loadFlowService,
                                             @Value("${security-analysis.default-provider}") String defaultProvider, LimitReductionConfig limitReductionConfig) {
        this.securityAnalysisParametersRepository = Objects.requireNonNull(securityAnalysisParametersRepository);
        this.loadFlowService = loadFlowService;
        this.defaultProvider = defaultProvider;
        this.limitReductionConfig = limitReductionConfig;
    }

    public SecurityAnalysisRunContext createRunContext(UUID networkUuid, String variantId, RunContextParametersInfos runContextParametersInfos,
                                                       String receiver, ReportInfos reportInfos, String userId) {
        Optional<SecurityAnalysisParametersEntity> securityAnalysisParametersEntity = Optional.empty();
        if (runContextParametersInfos.getSecurityAnalysisParametersUuid() != null) {
            securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(runContextParametersInfos.getSecurityAnalysisParametersUuid());
        }

        String provider = securityAnalysisParametersEntity.map(SecurityAnalysisParametersEntity::getProvider).orElse(null);
        String providerToUse = provider != null ? provider : defaultProvider;
        LoadFlowParametersValues loadFlowParametersValues = null;
        if (runContextParametersInfos.getLoadFlowParametersUuid() != null) {
            loadFlowParametersValues = loadFlowService.getLoadFlowParameters(runContextParametersInfos.getLoadFlowParametersUuid(), providerToUse);
        }

        SecurityAnalysisParameters parameters = toSecurityAnalysisParameters(securityAnalysisParametersEntity.orElse(null));
        List<List<Double>> limitReductions = securityAnalysisParametersEntity
                .map(SecurityAnalysisParametersEntity::toLimitReductionsValues)
                .orElse(limitReductionConfig.getDefaultValues());
        return new SecurityAnalysisRunContext(
                networkUuid,
                variantId,
                runContextParametersInfos.getContingencyListNames(),
                receiver,
                providerToUse,
                parameters,
                loadFlowParametersValues,
                new ReportInfos(reportInfos.reportUuid(), reportInfos.reporterId(), reportInfos.computationType()),
                userId,
                limitReductions);
    }

    public static SecurityAnalysisParameters toSecurityAnalysisParameters(SecurityAnalysisParametersEntity entity) {
        if (entity == null) {
            return SecurityAnalysisParameters.load()
                    // the default values are overloaded
                    .setIncreasedViolationsParameters(getIncreasedViolationsParameters(DEFAULT_FLOW_PROPORTIONAL_THRESHOLD, DEFAULT_LOW_VOLTAGE_PROPORTIONAL_THRESHOLD, DEFAULT_LOW_VOLTAGE_ABSOLUTE_THRESHOLD, DEFAULT_HIGH_VOLTAGE_PROPORTIONAL_THRESHOLD, DEFAULT_HIGH_VOLTAGE_ABSOLUTE_THRESHOLD));
        }
        SecurityAnalysisParameters securityAnalysisParameters = new SecurityAnalysisParameters();
        securityAnalysisParameters.setIncreasedViolationsParameters(getIncreasedViolationsParameters(entity.getFlowProportionalThreshold(), entity.getLowVoltageProportionalThreshold(), entity.getLowVoltageAbsoluteThreshold(), entity.getHighVoltageProportionalThreshold(), entity.getHighVoltageAbsoluteThreshold()));
        return securityAnalysisParameters;
    }

    public static SecurityAnalysisParameters.IncreasedViolationsParameters getIncreasedViolationsParameters(double flowProportionalThreshold, double lowVoltageProportionalThreshold, double lowVoltageAbsoluteThreshold, double highVoltageProportionalThreshold, double highVoltageAbsoluteThreshold) {
        SecurityAnalysisParameters.IncreasedViolationsParameters increasedViolationsParameters = new SecurityAnalysisParameters.IncreasedViolationsParameters();
        increasedViolationsParameters.setFlowProportionalThreshold(flowProportionalThreshold);
        increasedViolationsParameters.setLowVoltageAbsoluteThreshold(lowVoltageAbsoluteThreshold);
        increasedViolationsParameters.setLowVoltageProportionalThreshold(lowVoltageProportionalThreshold);
        increasedViolationsParameters.setHighVoltageAbsoluteThreshold(highVoltageAbsoluteThreshold);
        increasedViolationsParameters.setHighVoltageProportionalThreshold(highVoltageProportionalThreshold);
        return increasedViolationsParameters;
    }

    public static SecurityAnalysisParametersValues getDefaultSecurityAnalysisParametersValues(String provider, LimitReductionConfig limitReductionConfig) {
        List<List<Double>> limitReductions = Optional.ofNullable(limitReductionConfig)
                .map(LimitReductionConfig::getDefaultValues)
                .orElseGet(Collections::emptyList);
        return SecurityAnalysisParametersValues.builder()
                .provider(provider)
                .lowVoltageAbsoluteThreshold(DEFAULT_LOW_VOLTAGE_ABSOLUTE_THRESHOLD)
                .lowVoltageProportionalThreshold(DEFAULT_LOW_VOLTAGE_PROPORTIONAL_THRESHOLD)
                .highVoltageAbsoluteThreshold(DEFAULT_HIGH_VOLTAGE_ABSOLUTE_THRESHOLD)
                .highVoltageProportionalThreshold(DEFAULT_HIGH_VOLTAGE_PROPORTIONAL_THRESHOLD)
                .flowProportionalThreshold(DEFAULT_FLOW_PROPORTIONAL_THRESHOLD)
                .limitReductionsValues(limitReductions)
                .build();
    }

    public Optional<SecurityAnalysisParametersValues> getParameters(UUID parametersUuid) {
        return securityAnalysisParametersRepository.findById(parametersUuid)
                .map(SecurityAnalysisParametersEntity::toSecurityAnalysisParametersValues)
                .map(p -> {
                    p.setLimitReductions(limitReductionConfig.createLimitReductions(p.getLimitReductionsValues()));
                    return p;
                });
    }

    public UUID createParameters(SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        return securityAnalysisParametersRepository.save(securityAnalysisParametersValues.toEntity()).getId();
    }

    public UUID createDefaultParameters() {
        return securityAnalysisParametersRepository.save(getDefaultSecurityAnalysisParametersValues(defaultProvider, limitReductionConfig).toEntity()).getId();
    }

    public Optional<UUID> duplicateParameters(UUID sourceParametersUuid) {
        Optional<SecurityAnalysisParametersValues> securityAnalysisParametersValuesOptional = securityAnalysisParametersRepository.findById(sourceParametersUuid).map(SecurityAnalysisParametersEntity::toSecurityAnalysisParametersValues);
        return securityAnalysisParametersValuesOptional.map(parametersValues -> securityAnalysisParametersRepository.save(new SecurityAnalysisParametersEntity(parametersValues)).getId());
    }

    @Transactional
    public UUID updateParameters(UUID parametersUuid, SecurityAnalysisParametersValues parametersInfos) {
        SecurityAnalysisParametersEntity securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(parametersUuid).orElseThrow(() -> new SecurityAnalysisException(PARAMETERS_NOT_FOUND));
        //if the parameters is null it means it's a reset to defaultValues but we need to keep the provider because it's updated separately
        if (parametersInfos == null) {
            securityAnalysisParametersEntity.update(getDefaultSecurityAnalysisParametersValues(securityAnalysisParametersEntity.getProvider(), limitReductionConfig));
        } else {
            securityAnalysisParametersEntity.update(parametersInfos);
        }
        return securityAnalysisParametersEntity.getId();
    }

    public void deleteParameters(UUID parametersUuid) {
        securityAnalysisParametersRepository.deleteById(parametersUuid);
    }

    @Transactional
    public void updateProvider(UUID parametersUuid, String provider) {
        securityAnalysisParametersRepository.findById(parametersUuid)
            .orElseThrow()
            .updateProvider(provider != null ? provider : defaultProvider);
    }
}
