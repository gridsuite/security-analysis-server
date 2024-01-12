/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.security.SecurityAnalysisParameters;
import org.gridsuite.securityanalysis.server.dto.LoadFlowParametersInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisParametersRepository;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static org.gridsuite.securityanalysis.server.util.SecurityAnalysisException.Type.PARAMETERS_NOT_FOUND;

/**
 * @author Abdelsalem HEDHILI <abdelsalem.hedhili@rte-france.com>
 */
@Service
public class SecurityAnalysisParametersService {

    private final SecurityAnalysisParametersRepository securityAnalysisParametersRepository;

    private static final double DEFAULT_FLOW_PROPORTIONAL_THRESHOLD = 0.1; // meaning 10.0 %
    private static final double DEFAULT_LOW_VOLTAGE_PROPORTIONAL_THRESHOLD = 0.01; // meaning 1.0 %
    private static final double DEFAULT_HIGH_VOLTAGE_PROPORTIONAL_THRESHOLD = 0.01; // meaning 1.0 %
    private static final double DEFAULT_LOW_VOLTAGE_ABSOLUTE_THRESHOLD = 1.0; // 1.0 kV
    private static final double DEFAULT_HIGH_VOLTAGE_ABSOLUTE_THRESHOLD = 1.0; // 1.0 kV

    public SecurityAnalysisParametersService(SecurityAnalysisParametersRepository securityAnalysisParametersRepository) {
        this.securityAnalysisParametersRepository = Objects.requireNonNull(securityAnalysisParametersRepository);
    }

    public SecurityAnalysisRunContext createRunContext(UUID networkUuid, String variantId, List<String> contingencyListNames,
                                                       String receiver, String provider, UUID parametersUuid,
                                                       LoadFlowParametersInfos loadFlowParametersInfos,
                                                       UUID reportUuid, String reporterId, String userId, String reportType) {
        Optional<SecurityAnalysisParametersEntity> securityAnalysisParametersEntity = Optional.empty();
        if (parametersUuid != null) {
            securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(parametersUuid);
        }
        SecurityAnalysisParameters parameters = toSecurityAnalysisParameters(securityAnalysisParametersEntity.orElse(null));
        return new SecurityAnalysisRunContext(
                networkUuid,
                variantId,
                contingencyListNames,
                receiver,
                provider,
                parameters,
                loadFlowParametersInfos,
                reportUuid,
                reporterId,
                reportType,
                userId);

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

    public static SecurityAnalysisParametersValues fromEntity(SecurityAnalysisParametersEntity entity) {
        Objects.requireNonNull(entity);
        return SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(entity.getLowVoltageAbsoluteThreshold())
                .lowVoltageProportionalThreshold(entity.getLowVoltageProportionalThreshold())
                .highVoltageAbsoluteThreshold(entity.getHighVoltageAbsoluteThreshold())
                .highVoltageProportionalThreshold(entity.getHighVoltageProportionalThreshold())
                .flowProportionalThreshold(entity.getFlowProportionalThreshold())
                .build();
    }

    public static SecurityAnalysisParametersValues getDefaultSecurityAnalysisParametersValues() {
        return SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(DEFAULT_LOW_VOLTAGE_ABSOLUTE_THRESHOLD)
                .lowVoltageProportionalThreshold(DEFAULT_LOW_VOLTAGE_PROPORTIONAL_THRESHOLD)
                .highVoltageAbsoluteThreshold(DEFAULT_HIGH_VOLTAGE_ABSOLUTE_THRESHOLD)
                .highVoltageProportionalThreshold(DEFAULT_HIGH_VOLTAGE_PROPORTIONAL_THRESHOLD)
                .flowProportionalThreshold(DEFAULT_FLOW_PROPORTIONAL_THRESHOLD)
                .build();
    }

    public SecurityAnalysisParametersValues getParameters(UUID parametersUuid) {
        var params = securityAnalysisParametersRepository.findById(parametersUuid).orElseThrow(() -> new SecurityAnalysisException(PARAMETERS_NOT_FOUND));
        return SecurityAnalysisParametersService.fromEntity(params);
    }

    public UUID createParameters(SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        return securityAnalysisParametersRepository.save(securityAnalysisParametersValues.toEntity()).getId();
    }

    public UUID createDefaultParameters() {
        return securityAnalysisParametersRepository.save(getDefaultSecurityAnalysisParametersValues().toEntity()).getId();
    }

    public Optional<UUID> createParameters(UUID sourceParametersId) {
        Optional<SecurityAnalysisParametersValues> securityAnalysisParametersValuesOptional = securityAnalysisParametersRepository.findById(sourceParametersId).map(SecurityAnalysisParametersEntity::toSecurityAnalysisParametersValues);
        if (securityAnalysisParametersValuesOptional.isPresent()) {
            SecurityAnalysisParametersEntity entity = new SecurityAnalysisParametersEntity(securityAnalysisParametersValuesOptional.get());
            securityAnalysisParametersRepository.save(entity);
            return Optional.of(entity.getId());
        }
        return Optional.empty();
    }

    @Transactional
    public UUID updateParameters(UUID parametersUuid, SecurityAnalysisParametersValues parametersInfos) {
        SecurityAnalysisParametersEntity securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(parametersUuid).orElseThrow(() -> new SecurityAnalysisException(PARAMETERS_NOT_FOUND));
        //if the parameters is null it means it's a reset to defaultValues
        if (parametersInfos == null) {
            securityAnalysisParametersEntity.update(getDefaultSecurityAnalysisParametersValues());
        } else {
            securityAnalysisParametersEntity.update(parametersInfos);
        }
        return securityAnalysisParametersEntity.getId();
    }

    public void deleteParameters(UUID parametersUuid) {
        securityAnalysisParametersRepository.deleteById(parametersUuid);
    }
}
