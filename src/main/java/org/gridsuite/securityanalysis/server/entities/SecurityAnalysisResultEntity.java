/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Network;
import com.powsybl.security.SecurityAnalysisResult;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldNameConstants;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.jgrapht.alg.util.Pair;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@NoArgsConstructor
@Getter
@Entity
@AllArgsConstructor
@FieldNameConstants
@Builder
@Table(name = "security_analysis_result")
public class SecurityAnalysisResultEntity {
    @Id
    private UUID id;

    @Setter
    private SecurityAnalysisStatus status;

    private String preContingencyStatus;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ContingencyEntity> contingencies;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PreContingencyLimitViolationEntity> preContingencyLimitViolations;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SubjectLimitViolationEntity> subjectLimitViolations;

    public SecurityAnalysisResultEntity(UUID id) {
        this.id = id;
    }

    public static SecurityAnalysisResultEntity toEntity(Network network, UUID resultUuid, SecurityAnalysisResult securityAnalysisResult, SecurityAnalysisStatus securityAnalysisStatus) {
        Map<String, SubjectLimitViolationEntity> subjectLimitViolationsBySubjectId = getUniqueSubjectLimitViolationsFromResult(securityAnalysisResult)
            .stream().collect(Collectors.toMap(
                SubjectLimitViolationEntity::getSubjectId,
                subjectLimitViolation -> subjectLimitViolation)
            );

        List<ContingencyEntity> contingencies = securityAnalysisResult.getPostContingencyResults().stream()
            .map(postContingencyResult -> ContingencyEntity.toEntity(network, postContingencyResult, subjectLimitViolationsBySubjectId)).collect(Collectors.toList());

        List<PreContingencyLimitViolationEntity> preContingencyLimitViolations = PreContingencyLimitViolationEntity.toEntityList(network, securityAnalysisResult.getPreContingencyResult(), subjectLimitViolationsBySubjectId);

        List<SubjectLimitViolationEntity> subjectLimitViolations = Stream.concat(
                contingencies.stream().flatMap(c -> c.getContingencyLimitViolations().stream()),
                preContingencyLimitViolations.stream()
            ).map(AbstractLimitViolationEntity::getSubjectLimitViolation)
            .distinct()
            .filter(Objects::nonNull)
            .collect(Collectors.toList());

        SecurityAnalysisResultEntity securityAnalysisResultEntity = SecurityAnalysisResultEntity.builder()
            .id(resultUuid)
            .status(securityAnalysisStatus)
            .preContingencyStatus(securityAnalysisResult.getPreContingencyResult().getStatus().name())
            .contingencies(contingencies)
            .preContingencyLimitViolations(preContingencyLimitViolations)
            .subjectLimitViolations(subjectLimitViolations)
            .build();

        //bidirectionnal associations
        contingencies.forEach(c -> c.setResult(securityAnalysisResultEntity));
        preContingencyLimitViolations.forEach(lm -> lm.setResult(securityAnalysisResultEntity));
        subjectLimitViolations.forEach(subjectLimitViolation -> subjectLimitViolation.setResult(securityAnalysisResultEntity));
        return securityAnalysisResultEntity;
    }

    private static List<SubjectLimitViolationEntity> getUniqueSubjectLimitViolationsFromResult(SecurityAnalysisResult securityAnalysisResult) {
        return Stream.concat(
                securityAnalysisResult.getPostContingencyResults().stream().flatMap(pcr -> pcr.getLimitViolationsResult().getLimitViolations().stream()),
                securityAnalysisResult.getPreContingencyResult().getLimitViolationsResult().getLimitViolations().stream())
            .map(lm -> new Pair<>(lm.getSubjectId(), lm.getSubjectName()))
            .distinct()
            .map(pair -> new SubjectLimitViolationEntity(pair.getFirst(), pair.getSecond()))
            .toList();
    }
}
