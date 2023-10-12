/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.contingency.*;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.*;
import com.powsybl.security.results.NetworkResult;
import com.powsybl.security.results.PostContingencyResult;
import com.powsybl.security.results.PreContingencyResult;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.*;
import org.gridsuite.securityanalysis.server.repositories.*;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisResultService {
    private final SecurityAnalysisResultRepository securityAnalysisResultRepository;
    private final ContingencyRepository contingencyRepository;
    private final PreContingencyLimitViolationRepository preContingencyLimitViolationRepository;
    private final ConstraintRepository constraintRepository;

    public SecurityAnalysisResultService(SecurityAnalysisResultRepository securityAnalysisResultRepository,
                                         ContingencyRepository contingencyRepository,
                                         PreContingencyLimitViolationRepository preContingencyLimitViolationRepository,
                                         ConstraintRepository constraintRepository) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
        this.contingencyRepository = contingencyRepository;
        this.preContingencyLimitViolationRepository = preContingencyLimitViolationRepository;
        this.constraintRepository = constraintRepository;
    }

    @Transactional(readOnly = true)
    public PreContingencyResult findNResult(UUID resultUuid) {
        Optional<SecurityAnalysisResultEntity> securityAnalysisResult = securityAnalysisResultRepository.findById(resultUuid);
        if (securityAnalysisResult.isEmpty()) {
            return null;
        }
        List<PreContingencyLimitViolationEntity> preContingencyLimitViolationEntities = preContingencyLimitViolationRepository.findByResultId(resultUuid);

        List<LimitViolation> preContingencyLimitViolations = preContingencyLimitViolationEntities.stream()
            .map(preContingencyLimitViolation -> fromEntity(preContingencyLimitViolation))
            .collect(Collectors.toList());

        return new PreContingencyResult(
            LoadFlowResult.ComponentResult.Status.valueOf(securityAnalysisResult.get().getPreContingencyStatus()),
            new LimitViolationsResult(preContingencyLimitViolations),
            new NetworkResult(Collections.emptyList(), Collections.emptyList(), Collections.emptyList())
        );
    }

    @Transactional(readOnly = true)
    public List<ContingencyToConstraintDTO> findNmKContingenciesResult(UUID resultUuid) {
        assertResultExists(resultUuid);
        List<ContingencyEntity> contingencies = contingencyRepository.findByResultIdAndStatusOrderByContingencyId(resultUuid, LoadFlowResult.ComponentResult.Status.CONVERGED.name());
        return contingencies.stream().map(contingency -> {
            List<ConstraintFromContingencyDTO> constraints = contingency.getContingencyLimitViolations().stream()
                .map(ConstraintFromContingencyDTO::toDto)
                .collect(Collectors.toList());
            return new ContingencyToConstraintDTO(
                contingency.getContingencyId(),
                contingency.getStatus(),
                contingency.getContingencyElements().stream().map(ContingencyElementDTO::toDto).collect(Collectors.toList()),
                constraints
            );
        }).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<ConstraintToContingencyDTO> findNmKConstraintsResult(UUID resultUuid) {
        assertResultExists(resultUuid);
        List<ConstraintEntity> constraints = constraintRepository.findByResultIdOrderBySubjectId(resultUuid);

        return constraints.stream().map(constraint -> {
            // we only keep converged contingencies here
            List<ContingencyFromConstraintDTO> contingencies = constraint.getContingencyLimitViolations().stream()
                .filter(lm -> LoadFlowResult.ComponentResult.Status.CONVERGED.name().equals(lm.getContingency().getStatus()))
                .map(ContingencyFromConstraintDTO::toDto)
                .collect(Collectors.toList());

            return new ConstraintToContingencyDTO(constraint.getSubjectId(), contingencies);
        }).collect(Collectors.toList());
    }

    public void assertResultExists(UUID resultUuid) {
        if (securityAnalysisResultRepository.findById(resultUuid).isEmpty()) {
            throw new SecurityAnalysisException(SecurityAnalysisException.Type.RESULT_NOT_FOUND);
        }
    }

    @Transactional
    public void insert(UUID resultUuid, SecurityAnalysisResult result, SecurityAnalysisStatus status) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(result);

        SecurityAnalysisResultEntity securityAnalysisResult = toEntity(resultUuid, result, status);
        securityAnalysisResultRepository.save(securityAnalysisResult);
    }

    @Transactional
    public void insertStatus(List<UUID> resultUuids, SecurityAnalysisStatus status) {
        Objects.requireNonNull(resultUuids);
        resultUuids.forEach(resultUuid -> {
            SecurityAnalysisResultEntity securityAnalysisResult = securityAnalysisResultRepository.findById(resultUuid).orElse(new SecurityAnalysisResultEntity(resultUuid));
            securityAnalysisResult.setStatus(status);
            securityAnalysisResultRepository.save(securityAnalysisResult);
        });
    }

    @Transactional
    public void delete(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        securityAnalysisResultRepository.deleteById(resultUuid);
    }

    @Transactional
    public void deleteAll() {
        securityAnalysisResultRepository.deleteAll();
    }

    @Transactional(readOnly = true)
    public SecurityAnalysisStatus findStatus(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        Optional<SecurityAnalysisResultEntity> securityAnalysisResult = securityAnalysisResultRepository.findById(resultUuid);
        if (securityAnalysisResult.isEmpty()) {
            return null;
        }

        return securityAnalysisResult.get().getStatus();
    }

    private static LimitViolation fromEntity(AbstractLimitViolationEntity limitViolationEntity) {
        String subjectId = limitViolationEntity.getConstraint() != null
            ? limitViolationEntity.getConstraint().getSubjectId()
            : null;

        return new LimitViolation(subjectId, limitViolationEntity.getLimitType(), limitViolationEntity.getLimitName(), limitViolationEntity.getAcceptableDuration(),
            limitViolationEntity.getLimit(), limitViolationEntity.getLimitReduction(), limitViolationEntity.getValue(), limitViolationEntity.getSide());
    }

    private static SecurityAnalysisResultEntity toEntity(UUID resultUuid, SecurityAnalysisResult securityAnalysisResult, SecurityAnalysisStatus securityAnalysisStatus) {
        Map<String, ConstraintEntity> constraintsBySubjectId = getUniqueConstraintsFromResult(securityAnalysisResult)
            .stream().collect(Collectors.toMap(
                ConstraintEntity::getSubjectId,
                constraint -> constraint)
            );

        List<ContingencyEntity> contingencies = securityAnalysisResult.getPostContingencyResults().stream()
            .map(postContingencyResult -> toEntity(postContingencyResult, constraintsBySubjectId)).collect(Collectors.toList());

        List<PreContingencyLimitViolationEntity> preContingencyLimitViolations = toEntity(securityAnalysisResult.getPreContingencyResult(), constraintsBySubjectId);

        return new SecurityAnalysisResultEntity(resultUuid, securityAnalysisStatus, securityAnalysisResult.getPreContingencyResult().getStatus().name(), contingencies, preContingencyLimitViolations);
    }

    private static List<ConstraintEntity> getUniqueConstraintsFromResult(SecurityAnalysisResult securityAnalysisResult) {
        return Stream.concat(
                securityAnalysisResult.getPostContingencyResults().stream().flatMap(pcr -> pcr.getLimitViolationsResult().getLimitViolations().stream()),
                securityAnalysisResult.getPreContingencyResult().getLimitViolationsResult().getLimitViolations().stream())
            .map(LimitViolation::getSubjectId)
            .distinct()
            .map(ConstraintEntity::new)
            .collect(Collectors.toList());
    }

    private static List<PreContingencyLimitViolationEntity> toEntity(PreContingencyResult preContingencyResult, Map<String, ConstraintEntity> constraintsBySubjectId) {
        return preContingencyResult.getLimitViolationsResult().getLimitViolations().stream().map(limitViolation -> toPreContingencyLimitViolationEntity(limitViolation, constraintsBySubjectId.get(limitViolation.getSubjectId()))).collect(Collectors.toList());
    }

    private static ContingencyEntity toEntity(PostContingencyResult postContingencyResult, Map<String, ConstraintEntity> constraintsBySubjectId) {
        List<ContingencyElementEmbeddable> contingencyElements = postContingencyResult.getContingency().getElements().stream().map(contingencyElement -> toEntity(contingencyElement)).collect(Collectors.toList());

        List<ContingencyLimitViolationEntity> contingencyLimitViolations = postContingencyResult.getLimitViolationsResult().getLimitViolations().stream()
            .map(limitViolation -> toContingencyLimitViolationEntity(limitViolation, constraintsBySubjectId.get(limitViolation.getSubjectId())))
            .collect(Collectors.toList());
        return new ContingencyEntity(postContingencyResult.getContingency().getId(), postContingencyResult.getStatus().name(), contingencyElements, contingencyLimitViolations);
    }

    private static ContingencyLimitViolationEntity toContingencyLimitViolationEntity(LimitViolation limitViolation, ConstraintEntity constraint) {
        return new ContingencyLimitViolationEntity(constraint,
            limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
            limitViolation.getLimitType(), limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
            limitViolation.getSide());
    }

    private static PreContingencyLimitViolationEntity toPreContingencyLimitViolationEntity(LimitViolation limitViolation, ConstraintEntity constraint) {
        return new PreContingencyLimitViolationEntity(constraint,
            limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
            limitViolation.getLimitType(), limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
            limitViolation.getSide());
    }

    private static ContingencyElementEmbeddable toEntity(ContingencyElement contingencyElement) {
        return new ContingencyElementEmbeddable(contingencyElement.getType(), contingencyElement.getId());
    }
}
