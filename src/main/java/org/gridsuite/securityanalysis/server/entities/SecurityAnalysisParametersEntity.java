/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import lombok.*;

import jakarta.persistence.*;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author Abdelsalem HEDHILI <abdelsalem.hedhili@rte-france.com>
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Entity
@Builder
@Table(name = "securityAnalysisParameters")
public class SecurityAnalysisParametersEntity {

    public SecurityAnalysisParametersEntity(SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        this(null,
                securityAnalysisParametersValues.getProvider(),
                securityAnalysisParametersValues.getLowVoltageAbsoluteThreshold(),
                securityAnalysisParametersValues.getLowVoltageProportionalThreshold(),
                securityAnalysisParametersValues.getHighVoltageAbsoluteThreshold(),
                securityAnalysisParametersValues.getHighVoltageProportionalThreshold(),
                securityAnalysisParametersValues.getFlowProportionalThreshold(),
                securityAnalysisParametersValues.getLimitReductions().stream().map(LimitReductionEntity::new).toList());
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private UUID id;

    @Column(name = "provider")
    private String provider;

    @Column(name = "lowVoltageAbsoluteThreshold")
    private double lowVoltageAbsoluteThreshold;

    @Column(name = "lowVoltageProportionalThreshold")
    private double lowVoltageProportionalThreshold;

    @Column(name = "highVoltageAbsoluteThreshold")
    private double highVoltageAbsoluteThreshold;

    @Column(name = "highVoltageProportionalThreshold")
    private double highVoltageProportionalThreshold;

    @Column(name = "flowProportionalThreshold")
    private double flowProportionalThreshold;

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "security_analysis_parameters_id", foreignKey = @ForeignKey(name = "securityAnalysisParametersEntity_limitReductions_fk"))
    @OrderColumn(name = "index")
    private List<LimitReductionEntity> limitReductions;

    public SecurityAnalysisParametersValues toSecurityAnalysisParametersValues() {
        return SecurityAnalysisParametersValues.builder()
                .provider(this.provider)
                .flowProportionalThreshold(this.flowProportionalThreshold)
                .highVoltageAbsoluteThreshold(this.highVoltageAbsoluteThreshold)
                .highVoltageProportionalThreshold(this.highVoltageProportionalThreshold)
                .lowVoltageAbsoluteThreshold(this.lowVoltageAbsoluteThreshold)
                .lowVoltageProportionalThreshold(this.lowVoltageProportionalThreshold)
                .limitReductions(this.limitReductions.stream()
                        .map(limitReductionEntity -> new ArrayList<>(limitReductionEntity.getValues()))
                        .collect(Collectors.toList()))
                .build();
    }

    public void update(@NonNull SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        updateProvider(securityAnalysisParametersValues.getProvider());
        this.flowProportionalThreshold = securityAnalysisParametersValues.getFlowProportionalThreshold();
        this.highVoltageAbsoluteThreshold = securityAnalysisParametersValues.getHighVoltageAbsoluteThreshold();
        this.highVoltageProportionalThreshold = securityAnalysisParametersValues.getHighVoltageProportionalThreshold();
        this.lowVoltageAbsoluteThreshold = securityAnalysisParametersValues.getLowVoltageAbsoluteThreshold();
        this.lowVoltageProportionalThreshold = securityAnalysisParametersValues.getLowVoltageProportionalThreshold();
        this.limitReductions.clear();
        this.limitReductions.addAll(securityAnalysisParametersValues.getLimitReductions().stream().map(LimitReductionEntity::new).toList());
    }

    public void updateProvider(String provider) {
        this.provider = provider;
    }
}

