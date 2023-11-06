/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.jgrapht.alg.util.Pair;
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
    private final ObjectMapper objectMapper;
    private final SecurityAnalysisResultService self;

    public SecurityAnalysisResultService(SecurityAnalysisResultRepository securityAnalysisResultRepository,
                                         ContingencyRepository contingencyRepository,
                                         PreContingencyLimitViolationRepository preContingencyLimitViolationRepository,
                                         SubjectLimitViolationRepository subjectLimitViolationRepository,
                                         SecurityAnalysisResultService securityAnalysisResultService,
                                         ObjectMapper objectMapper) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
        this.contingencyRepository = contingencyRepository;
        this.preContingencyLimitViolationRepository = preContingencyLimitViolationRepository;
        this.subjectLimitViolationRepository = subjectLimitViolationRepository;
        this.objectMapper = objectMapper;
        this.self = securityAnalysisResultService;
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
    public Page<ContingencyResultDTO> findNmKContingenciesResult(UUID resultUuid, String stringFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        Page<ContingencyEntity> contingencyPageBis = self.findContingenciesPage(resultUuid, fromStringFiltersToDTO(stringFilters), pageable);
        return contingencyPageBis.map(ContingencyResultDTO::toDto);
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationResultDTO> findNmKConstraintsResult(UUID resultUuid, String stringFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        Page<SubjectLimitViolationEntity> subjectLimitViolationsPage = self.findSubjectLimitViolationsPage(resultUuid, fromStringFiltersToDTO(stringFilters), pageable);
        return subjectLimitViolationsPage.map(SubjectLimitViolationResultDTO::toDto);
    }

    private List<ResourceFilterDTO> fromStringFiltersToDTO(String stringFilters) {
        if (stringFilters == null || stringFilters.isEmpty()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(stringFilters, new TypeReference<>() {
            });
        } catch (JsonProcessingException e) {
            throw new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_FILTER_FORMAT);
        }
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

    @Transactional(readOnly = true)
    public Page<ContingencyEntity> findContingenciesPage(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        Specification<ContingencyEntity> specification = contingencyRepository.getParentsSpecifications(resultUuid, resourceFilters);
        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch
        Page<ContingencyEntity> contingenciesPage = contingencyRepository.findAll(specification, pageable);
        if (contingenciesPage.hasContent()) {
            this.appendLimitViolationsToContingenciesResult(contingenciesPage, resourceFilters);
        }
        return contingenciesPage;
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationEntity> findSubjectLimitViolationsPage(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationRepository.getParentsSpecifications(resultUuid, resourceFilters);
        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch
        Page<SubjectLimitViolationEntity> subjectLimitViolationsPage = subjectLimitViolationRepository.findAll(specification, pageable);
        if (subjectLimitViolationsPage.hasContent()) {
            appendLimitViolationsToSubjectLimitViolationsResult(subjectLimitViolationsPage, resourceFilters);
        }
        return subjectLimitViolationsPage;
    }

    private void appendLimitViolationsToContingenciesResult(Page<ContingencyEntity> contingencies, List<ResourceFilterDTO> resourceFilters) {

        // using the the Hibernate First-Level Cache or Persistence Context
        // cf.https://vladmihalcea.com/spring-data-jpa-multiplebagfetchexception/
        if (!contingencies.isEmpty()) {
            List<UUID> contingencyUuids = contingencies.stream()
                .map(c -> c.getUuid())
                .toList();
            Specification<ContingencyEntity> specification = contingencyRepository.getLimitViolationsSpecifications(contingencyUuids, resourceFilters);
            contingencyRepository.findAll(specification);
        }
    }

    private void appendLimitViolationsToSubjectLimitViolationsResult(Page<SubjectLimitViolationEntity> subjectLimitViolations, List<ResourceFilterDTO> resourceFilters) {

        // using the the Hibernate First-Level Cache or Persistence Context
        // cf.https://vladmihalcea.com/spring-data-jpa-multiplebagfetchexception/
        if (!subjectLimitViolations.isEmpty()) {
            List<UUID> subjectLimitViolationsUuids = subjectLimitViolations.stream()
                .map(c -> c.getId())
                .toList();
            Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationRepository.getLimitViolationsSpecifications(subjectLimitViolationsUuids, resourceFilters);
            subjectLimitViolationRepository.findAll(specification);
        }
    }

    public static List<SubjectLimitViolationEntity> getUniqueSubjectLimitViolationsFromResult(SecurityAnalysisResult securityAnalysisResult) {
        return Stream.concat(
                securityAnalysisResult.getPostContingencyResults().stream().flatMap(pcr -> pcr.getLimitViolationsResult().getLimitViolations().stream()),
                securityAnalysisResult.getPreContingencyResult().getLimitViolationsResult().getLimitViolations().stream())
            .map(lm -> new Pair<>(lm.getSubjectId(), lm.getSubjectName()))
            .distinct()
            .map(pair -> new SubjectLimitViolationEntity(pair.getFirst(), pair.getSecond()))
            .toList();
    }
}
