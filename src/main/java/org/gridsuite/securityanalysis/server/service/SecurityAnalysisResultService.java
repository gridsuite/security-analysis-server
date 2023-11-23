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
import com.powsybl.security.SecurityAnalysisResult;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.gridsuite.securityanalysis.server.repositories.ContingencyRepository;
import org.gridsuite.securityanalysis.server.repositories.PreContingencyLimitViolationRepository;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.gridsuite.securityanalysis.server.repositories.SubjectLimitViolationRepository;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

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
    private SecurityAnalysisResultService self;

    @Autowired
    public SecurityAnalysisResultService(SecurityAnalysisResultRepository securityAnalysisResultRepository,
                                         ContingencyRepository contingencyRepository,
                                         PreContingencyLimitViolationRepository preContingencyLimitViolationRepository,
                                         SubjectLimitViolationRepository subjectLimitViolationRepository,
                                         @Lazy SecurityAnalysisResultService self,
                                         ObjectMapper objectMapper) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
        this.contingencyRepository = contingencyRepository;
        this.preContingencyLimitViolationRepository = preContingencyLimitViolationRepository;
        this.subjectLimitViolationRepository = subjectLimitViolationRepository;
        this.objectMapper = objectMapper;
        this.self = self;
    }

    @Transactional(readOnly = true)
    public List<PreContingencyLimitViolationResultDTO> findNResult(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Sort sort) {
        assertResultExists(resultUuid);
        assertPreContingenciesSortAllowed(sort);
        Specification<PreContingencyLimitViolationEntity> specification = preContingencyLimitViolationRepository.getParentsSpecifications(resultUuid, resourceFilters);
        Sort newSort = createNResultSort(sort);
        List<PreContingencyLimitViolationEntity> preContingencyLimitViolation = preContingencyLimitViolationRepository.findAll(specification, newSort);
        return preContingencyLimitViolation.stream()
                .map(PreContingencyLimitViolationResultDTO::toDto)
                .toList();
    }

    private Sort createNResultSort(Sort sort) {
        List<Sort.Order> newOrders = new ArrayList<>();
        sort.forEach(order -> {
            String property = order.getProperty();
            if (preContingencyLimitViolationRepository.isParentFilter(property)) {
                newOrders.add(new Sort.Order(order.getDirection(), "subjectLimitViolation." + property));
            } else {
                newOrders.add(order);
            }
        });
        return Sort.by(newOrders);
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

    private void assertNmKContingenciesSortAllowed(Sort sort) {
        List<String> allowedSortProperties = List.of(ResourceFilterDTO.Column.CONTINGENCY_ID, ResourceFilterDTO.Column.STATUS)
            .stream().map(ResourceFilterDTO.Column::getColumnName)
            .toList();
        assertSortAllowed(sort, allowedSortProperties);
    }

    private void assertPreContingenciesSortAllowed(Sort sort) {
        List<String> allowedSortProperties = ResourceFilterDTO.getAllColumnNames().stream()
                .filter(columnName -> !columnName.equals(ResourceFilterDTO.Column.CONTINGENCY_ID.getColumnName())
                        && !columnName.equals(ResourceFilterDTO.Column.STATUS.getColumnName()))
                .toList();
        assertSortAllowed(sort, allowedSortProperties);
    }

    private void assertNmKSubjectLimitViolationsSortAllowed(Sort sort) {
        List<String> allowedSortProperties = List.of(ResourceFilterDTO.Column.SUBJECT_ID)
            .stream().map(ResourceFilterDTO.Column::getColumnName)
            .toList();
        assertSortAllowed(sort, allowedSortProperties);
    }

    private void assertSortAllowed(Sort sort, List<String> allowedSortProperties) {
        if (!sort.stream().allMatch(order -> allowedSortProperties.contains(order.getProperty()))) {
            throw new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_SORT_FORMAT);
        }
    }

    public List<ResourceFilterDTO> fromStringFiltersToDTO(String stringFilters) {
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
        assertNmKContingenciesSortAllowed(pageable.getSort());
        Specification<ContingencyEntity> specification = contingencyRepository.getParentsSpecifications(resultUuid, resourceFilters);
        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch

        // First, we fetch contingencies UUIDs, with all the filters and pagination
        Page<ContingencyRepository.EntityUuid> uuidPage = contingencyRepository.findBy(specification, q ->
            q.project("uuid")
                .as(ContingencyRepository.EntityUuid.class)
                .sortBy(pageable.getSort())
                .page(pageable)
        );

        if (!uuidPage.hasContent()) {
            return Page.empty();
        } else {
            List<UUID> uuids = uuidPage.map(u -> u.getUuid()).toList();
            // Then we fetch the main entities data for each UUID
            List<ContingencyEntity> contingencies = contingencyRepository.findAllByUuidIn(uuids);
            contingencies.sort(Comparator.comparing(c -> uuids.indexOf(c.getUuid())));
            Page<ContingencyEntity> contingenciesPage = new PageImpl<>(contingencies, pageable, uuidPage.getTotalElements());

            // then we append the missing data, and filter some of the Lazy Loaded collections
            appendLimitViolationsAndElementsToContingenciesResult(contingenciesPage, resourceFilters);

            return contingenciesPage;
        }
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationEntity> findSubjectLimitViolationsPage(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        assertNmKSubjectLimitViolationsSortAllowed(pageable.getSort());
        Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationRepository.getParentsSpecifications(resultUuid, resourceFilters);
        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch
        Page<SubjectLimitViolationRepository.EntityId> uuidPage = subjectLimitViolationRepository.findBy(specification, q ->
            q.project("id")
                .as(SubjectLimitViolationRepository.EntityId.class)
                .sortBy(pageable.getSort())
                .page(pageable)
        );

        if (!uuidPage.hasContent()) {
            return Page.empty();
        } else {
            List<UUID> uuids = uuidPage.map(u -> u.getId()).toList();
            // Then we fetch the main entities data for each UUID
            List<SubjectLimitViolationEntity> subjectLimitViolations = subjectLimitViolationRepository.findAllByIdIn(uuids);
            subjectLimitViolations.sort(Comparator.comparing(lm -> uuids.indexOf(lm.getId())));
            Page<SubjectLimitViolationEntity> subjectLimitViolationPage = new PageImpl<>(subjectLimitViolations, pageable, uuidPage.getTotalElements());

            // then we append the missing data, and filter some of the Lazy Loaded collections
            appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResult(subjectLimitViolationPage, resourceFilters);

            return subjectLimitViolationPage;
        }
    }

    private void appendLimitViolationsAndElementsToContingenciesResult(Page<ContingencyEntity> contingencies, List<ResourceFilterDTO> resourceFilters) {

        // using the the Hibernate First-Level Cache or Persistence Context
        // cf.https://vladmihalcea.com/spring-data-jpa-multiplebagfetchexception/
        if (!contingencies.isEmpty()) {
            List<UUID> contingencyUuids = contingencies.stream()
                .map(c -> c.getUuid())
                .toList();
            Specification<ContingencyEntity> specification = contingencyRepository.getLimitViolationsSpecifications(contingencyUuids, resourceFilters);
            contingencyRepository.findAll(specification);
            // we fetch contingencyElements here to prevent N+1 query
            contingencyRepository.findAllWithContingencyElementsByUuidIn(contingencyUuids);
        }
    }

    private void appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResult(Page<SubjectLimitViolationEntity> subjectLimitViolations, List<ResourceFilterDTO> resourceFilters) {

        // using the the Hibernate First-Level Cache or Persistence Context
        // cf.https://vladmihalcea.com/spring-data-jpa-multiplebagfetchexception/
        if (!subjectLimitViolations.isEmpty()) {
            List<UUID> subjectLimitViolationsUuids = subjectLimitViolations.stream()
                .map(c -> c.getId())
                .toList();
            Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationRepository.getLimitViolationsSpecifications(subjectLimitViolationsUuids, resourceFilters);
            subjectLimitViolationRepository.findAll(specification);

            List<UUID> contingencyUuids = subjectLimitViolations.map(SubjectLimitViolationEntity::getContingencyLimitViolations).flatMap(List::stream)
                .map(lm -> lm.getContingency().getUuid())
                .toList();
            // we fetch contingencyElements for each contingency here to prevent N+1 query
            contingencyRepository.findAllWithContingencyElementsByUuidIn(contingencyUuids);
        }
    }
}
