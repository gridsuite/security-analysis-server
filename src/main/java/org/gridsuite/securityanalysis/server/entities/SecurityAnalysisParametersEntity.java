/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.*;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;

import java.util.*;
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
                securityAnalysisParametersValues.getLimitReductionsValues().stream().map(LimitReductionEntity::new).toList());
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
                .limitReductionsValues(toLimitReductionsValues())
                .build();
    }

    public List<List<Double>> toLimitReductionsValues() {
        return this.limitReductions.stream().map(LimitReductionEntity::getReductions).map(ArrayList::new).collect(Collectors.toList());
    }

    public void update(@NonNull SecurityAnalysisParametersValues securityAnalysisParametersValues) {
        updateProvider(securityAnalysisParametersValues.getProvider());
        this.flowProportionalThreshold = securityAnalysisParametersValues.getFlowProportionalThreshold();
        this.highVoltageAbsoluteThreshold = securityAnalysisParametersValues.getHighVoltageAbsoluteThreshold();
        this.highVoltageProportionalThreshold = securityAnalysisParametersValues.getHighVoltageProportionalThreshold();
        this.lowVoltageAbsoluteThreshold = securityAnalysisParametersValues.getLowVoltageAbsoluteThreshold();
        this.lowVoltageProportionalThreshold = securityAnalysisParametersValues.getLowVoltageProportionalThreshold();
        updateLimitReductions(securityAnalysisParametersValues.getLimitReductionsValues());
    }

    private void updateLimitReductions(List<List<Double>> values) {
        this.limitReductions.clear();
        this.limitReductions.addAll(values.stream().map(LimitReductionEntity::new).toList());
    }

    public void updateProvider(String provider) {
        this.provider = provider;
    }
}

