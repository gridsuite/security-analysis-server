/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.*;
import com.powsybl.security.results.NetworkResult;
import com.powsybl.security.results.PreContingencyResult;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.*;
import org.gridsuite.securityanalysis.server.repositories.*;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Stream;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisResultService {
    private final SecurityAnalysisResultRepository securityAnalysisResultRepository;
    private final ContingencyRepository contingencyRepository;
    private final PreContingencyLimitViolationRepository preContingencyLimitViolationRepository;
    private final SubjectLimitViolationRepository subjectLimitViolationRepository;

    public SecurityAnalysisResultService(SecurityAnalysisResultRepository securityAnalysisResultRepository,
                                         ContingencyRepository contingencyRepository,
                                         PreContingencyLimitViolationRepository preContingencyLimitViolationRepository,
                                         SubjectLimitViolationRepository subjectLimitViolationRepository) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
        this.contingencyRepository = contingencyRepository;
        this.preContingencyLimitViolationRepository = preContingencyLimitViolationRepository;
        this.subjectLimitViolationRepository = subjectLimitViolationRepository;
    }

    @Transactional(readOnly = true)
    public PreContingencyResult findNResult(UUID resultUuid) {
        Optional<SecurityAnalysisResultEntity> securityAnalysisResult = securityAnalysisResultRepository.findById(resultUuid);
        if (securityAnalysisResult.isEmpty()) {
            return null;
        }
        List<PreContingencyLimitViolationEntity> preContingencyLimitViolationEntities = preContingencyLimitViolationRepository.findByResultId(resultUuid);

        List<LimitViolation> preContingencyLimitViolations = preContingencyLimitViolationEntities.stream()
            .map(AbstractLimitViolationEntity::toLimitViolation)
            .toList();

        return new PreContingencyResult(
            LoadFlowResult.ComponentResult.Status.valueOf(securityAnalysisResult.get().getPreContingencyStatus()),
            new LimitViolationsResult(preContingencyLimitViolations),
            new NetworkResult(Collections.emptyList(), Collections.emptyList(), Collections.emptyList())
        );
    }

    @Transactional(readOnly = true)
    public Page<ContingencyToSubjectLimitViolationDTO> findNmKContingenciesResult(UUID resultUuid, ResultsSelectorDTO resultsSelector, Pageable pageable) {
        assertResultExists(resultUuid);

        Specification<ContingencyEntity> specification = ContingencyRepository.getSpecification(
            resultUuid,
            resultsSelector.getContingencyId(),
            resultsSelector.getStatus(),
            resultsSelector.getSubjectId(),
            resultsSelector.getLimitType(),
            resultsSelector.getLimitName(),
            resultsSelector.getSide(),
            resultsSelector.getAcceptableDuration(),
            resultsSelector.getLimit(),
            resultsSelector.getLimitReduction(),
            resultsSelector.getValue());

        Page<ContingencyEntity> contingenciesPageable = contingencyRepository.findAll(specification, pageable);
        return contingenciesPageable.map(contingency -> {
            List<SubjectLimitViolationFromContingencyDTO> subjectLimitViolations = contingency.getContingencyLimitViolations().stream()
                .map(SubjectLimitViolationFromContingencyDTO::toDto)
                .toList();
            return new ContingencyToSubjectLimitViolationDTO(
                contingency.getContingencyId(),
                contingency.getStatus(),
                contingency.getContingencyElements().stream().map(ContingencyElementDTO::toDto).toList(),
                subjectLimitViolations
            );
        });
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationToContingencyDTO> findNmKConstraintsResult(UUID resultUuid, ResultsSelectorDTO resultsSelector, Pageable pageable) {
        assertResultExists(resultUuid);
        Specification<SubjectLimitViolationEntity> specification = SubjectLimitViolationRepository.getSpecification(
            resultUuid,
            resultsSelector.getSubjectId(),
            resultsSelector.getContingencyId(),
            resultsSelector.getStatus(),
            resultsSelector.getLimitType(),
            resultsSelector.getLimitName(),
            resultsSelector.getSide(),
            resultsSelector.getAcceptableDuration(),
            resultsSelector.getLimit(),
            resultsSelector.getLimitReduction(),
            resultsSelector.getValue());

        Page<SubjectLimitViolationEntity> subjectLimitViolations = subjectLimitViolationRepository.findAll(specification, pageable);

        return subjectLimitViolations.map(subjectLimitViolation -> {
            List<ContingencyFromSubjectLimitViolationDTO> contingencies = subjectLimitViolation.getContingencyLimitViolations().stream()
                .map(ContingencyFromSubjectLimitViolationDTO::toDto)
                .toList();

            return new SubjectLimitViolationToContingencyDTO(subjectLimitViolation.getSubjectId(), contingencies);
        });
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

        SecurityAnalysisResultEntity securityAnalysisResult = SecurityAnalysisResultEntity.toEntity(resultUuid, result, status);
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

    public static List<SubjectLimitViolationEntity> getUniqueSubjectLimitViolationsFromResult(SecurityAnalysisResult securityAnalysisResult) {
        return Stream.concat(
                securityAnalysisResult.getPostContingencyResults().stream().flatMap(pcr -> pcr.getLimitViolationsResult().getLimitViolations().stream()),
                securityAnalysisResult.getPreContingencyResult().getLimitViolationsResult().getLimitViolations().stream())
            .map(LimitViolation::getSubjectId)
            .distinct()
            .map(SubjectLimitViolationEntity::new)
            .toList();
    }

}
