/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.security.SecurityAnalysisResult;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisResultService;

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

    public SecurityAnalysisResultEntity(UUID id, SecurityAnalysisStatus status, String preContingencyStatus, List<ContingencyEntity> contingencies, List<PreContingencyLimitViolationEntity> preContingencyLimitViolations) {
        this.id = id;
        this.status = status;
        this.preContingencyStatus = preContingencyStatus;
        setContingencies(contingencies);
        setPreContingencyLimitViolations(preContingencyLimitViolations);

        // extracting unique subject limit violations from all limit violations
        setSubjectLimitViolations(
            Stream.concat(
                this.contingencies.stream().flatMap(c -> c.getContingencyLimitViolations().stream()),
                this.preContingencyLimitViolations.stream()
            ).map(AbstractLimitViolationEntity::getSubjectLimitViolation)
            .distinct()
            .filter(Objects::nonNull)
            .collect(Collectors.toList())
        );
    }

    private void setContingencies(List<ContingencyEntity> contingencies) {
        if (contingencies != null) {
            this.contingencies = contingencies;
            this.contingencies.forEach(c -> c.setResult(this));
        }
    }

    private void setPreContingencyLimitViolations(List<PreContingencyLimitViolationEntity> preContingencyLimitViolations) {
        if (preContingencyLimitViolations != null) {
            this.preContingencyLimitViolations = preContingencyLimitViolations;
            this.preContingencyLimitViolations.forEach(lm -> lm.setResult(this));
        }
    }

    private void setSubjectLimitViolations(List<SubjectLimitViolationEntity> subjectLimitViolations) {
        if (subjectLimitViolations != null) {
            this.subjectLimitViolations = subjectLimitViolations;
            subjectLimitViolations.forEach(subjectLimitViolation -> subjectLimitViolation.setResult(this));
        }
    }

    public static SecurityAnalysisResultEntity toEntity(UUID resultUuid, SecurityAnalysisResult securityAnalysisResult, SecurityAnalysisStatus securityAnalysisStatus) {
        Map<String, SubjectLimitViolationEntity> subjectLimitViolationsBySubjectId = SecurityAnalysisResultService.getUniqueSubjectLimitViolationsFromResult(securityAnalysisResult)
            .stream().collect(Collectors.toMap(
                SubjectLimitViolationEntity::getSubjectId,
                subjectLimitViolation -> subjectLimitViolation)
            );

        List<ContingencyEntity> contingencies = securityAnalysisResult.getPostContingencyResults().stream()
            .map(postContingencyResult -> ContingencyEntity.toEntity(postContingencyResult, subjectLimitViolationsBySubjectId)).collect(Collectors.toList());

        List<PreContingencyLimitViolationEntity> preContingencyLimitViolations = PreContingencyLimitViolationEntity.toEntityList(securityAnalysisResult.getPreContingencyResult(), subjectLimitViolationsBySubjectId);

        return new SecurityAnalysisResultEntity(resultUuid, securityAnalysisStatus, securityAnalysisResult.getPreContingencyResult().getStatus().name(), contingencies, preContingencyLimitViolations);
    }
}
