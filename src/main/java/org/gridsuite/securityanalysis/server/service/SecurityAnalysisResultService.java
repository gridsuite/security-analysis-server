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
            .map(AbstractLimitViolationEntity::fromEntity)
            .toList();

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
                .toList();
            return new ContingencyToConstraintDTO(
                contingency.getContingencyId(),
                contingency.getStatus(),
                contingency.getContingencyElements().stream().map(ContingencyElementDTO::toDto).toList(),
                constraints
            );
        }).toList();
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
                .toList();

            return new ConstraintToContingencyDTO(constraint.getSubjectId(), contingencies);
        }).toList();
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

    public static List<ConstraintEntity> getUniqueConstraintsFromResult(SecurityAnalysisResult securityAnalysisResult) {
        return Stream.concat(
                securityAnalysisResult.getPostContingencyResults().stream().flatMap(pcr -> pcr.getLimitViolationsResult().getLimitViolations().stream()),
                securityAnalysisResult.getPreContingencyResult().getLimitViolationsResult().getLimitViolations().stream())
            .map(LimitViolation::getSubjectId)
            .distinct()
            .map(ConstraintEntity::new)
            .toList();
    }

}
