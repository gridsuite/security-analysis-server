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
import org.gridsuite.securityanalysis.server.repositories.*;
import org.gridsuite.securityanalysis.server.util.CsvExportUtils;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisResultService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisResultService.class);
    private final SecurityAnalysisResultRepository securityAnalysisResultRepository;
    private final ContingencyRepository contingencyRepository;
    private final PreContingencyLimitViolationRepository preContingencyLimitViolationRepository;
    private final SubjectLimitViolationRepository subjectLimitViolationRepository;
    private final ContingencyLimitViolationRepository contingencyLimitViolationRepository;
    private final ObjectMapper objectMapper;
    private SecurityAnalysisResultService self;

    private static final String DEFAULT_CONTINGENCY_SORT_COLUMN = "uuid";

    private static final String DEFAULT_SUBJECT_LIMIT_VIOLATION_SORT_COLUMN = "id";

    private static final Sort.Direction DEFAULT_SORT_DIRECTION = Sort.Direction.ASC;

    @Autowired
    public SecurityAnalysisResultService(SecurityAnalysisResultRepository securityAnalysisResultRepository,
                                         ContingencyRepository contingencyRepository,
                                         PreContingencyLimitViolationRepository preContingencyLimitViolationRepository,
                                         SubjectLimitViolationRepository subjectLimitViolationRepository,
                                         ContingencyLimitViolationRepository contingencyLimitViolationRepository,
                                         @Lazy SecurityAnalysisResultService self,
                                         ObjectMapper objectMapper) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
        this.contingencyRepository = contingencyRepository;
        this.preContingencyLimitViolationRepository = preContingencyLimitViolationRepository;
        this.subjectLimitViolationRepository = subjectLimitViolationRepository;
        this.contingencyLimitViolationRepository = contingencyLimitViolationRepository;
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

    @Transactional(readOnly = true)
    public byte[] findNResultZippedCsv(UUID resultUuid, CsvTranslationDTO csvTranslations) {
        List<PreContingencyLimitViolationResultDTO> result = self.findNResult(resultUuid, List.of(), Sort.by(Sort.Direction.ASC, ResourceFilterDTO.Column.SUBJECT_ID.getColumnName()));

        return CsvExportUtils.csvRowsToZippedCsv(csvTranslations.headers(), result.stream().map(r -> r.toCsvRow(csvTranslations.enumValueTranslations())).toList());
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
    public Page<ContingencyResultDTO> findNmKContingenciesPaged(UUID resultUuid, String stringFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        Page<ContingencyEntity> contingencyPageBis = self.findContingenciesPage(resultUuid, fromStringFiltersToDTO(stringFilters), pageable);
        return contingencyPageBis.map(ContingencyResultDTO::toDto);
    }

    @Transactional(readOnly = true)
    public List<ContingencyResultDTO> findNmKContingenciesResult(UUID resultUuid) {
        assertResultExists(resultUuid);

        List<ContingencyEntity> contingencies = contingencyRepository.findAllByResultId(resultUuid);
        List<UUID> uuids = contingencies.stream().map(ContingencyEntity::getUuid).toList();
        // fetching contingency elements to prevent n+1 requests
        contingencyRepository.findAllWithContingencyElementsByUuidIn(uuids);
        // fetching contingency limitViolations to prevent n+1 requests
        contingencyRepository.findAllWithContingencyLimitViolationsByUuidIn(uuids);

        return contingencies.stream().map(ContingencyResultDTO::toDto).toList();
    }

    @Transactional(readOnly = true)
    public byte[] findNmKContingenciesResultZippedCsv(UUID resultUuid, CsvTranslationDTO csvTranslations) {
        List<ContingencyResultDTO> result = self.findNmKContingenciesResult(resultUuid);

        return CsvExportUtils.csvRowsToZippedCsv(csvTranslations.headers(), result.stream().map(r -> r.toCsvRows(csvTranslations.enumValueTranslations())).flatMap(List::stream).toList());
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationResultDTO> findNmKConstraintsResultPaged(UUID resultUuid, String stringFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        Page<SubjectLimitViolationEntity> subjectLimitViolationsPage = self.findSubjectLimitViolationsPage(resultUuid, fromStringFiltersToDTO(stringFilters), pageable);
        return subjectLimitViolationsPage.map(SubjectLimitViolationResultDTO::toDto);
    }

    @Transactional(readOnly = true)
    public List<SubjectLimitViolationResultDTO> findNmKConstraintsResult(UUID resultUuid) {
        assertResultExists(resultUuid);

        List<SubjectLimitViolationEntity> subjectLimitViolations = subjectLimitViolationRepository.findAllByResultId(resultUuid);
        List<UUID> uuids = subjectLimitViolations.stream().map(SubjectLimitViolationEntity::getId).toList();
        subjectLimitViolationRepository.findAllWithContingencyContingencyLimitViolationsByIdIn(uuids);
        List<UUID> contingencyUuids = subjectLimitViolations.stream().map(SubjectLimitViolationEntity::getContingencyLimitViolations).flatMap(List::stream)
            .map(lm -> lm.getContingency().getUuid())
            .toList();
        // we fetch contingencyElements for each contingency here to prevent N+1 query
        contingencyRepository.findAllWithContingencyElementsByUuidIn(contingencyUuids);

        return subjectLimitViolations.stream().map(SubjectLimitViolationResultDTO::toDto).toList();
    }

    @Transactional(readOnly = true)
    public byte[] findNmKConstraintsResultZippedCsv(UUID resultUuid, CsvTranslationDTO csvTranslations) {
        List<SubjectLimitViolationResultDTO> result = self.findNmKConstraintsResult(resultUuid);

        return CsvExportUtils.csvRowsToZippedCsv(csvTranslations.headers(), result.stream().map(r -> r.toCsvRows(csvTranslations.enumValueTranslations())).flatMap(List::stream).toList());
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
        AtomicReference<Long> startTime = new AtomicReference<>();
        startTime.set(System.nanoTime());
        Objects.requireNonNull(resultUuid);
        deleteSecurityAnalysisResult(resultUuid);
        LOGGER.info("Security analysis result '{}' has been deleted in {}ms", resultUuid, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime.get()));
    }

    // We manually delete the results here using SQL queries to improve performances.
    // source : https://www.baeldung.com/spring-data-jpa-deleteby
    // "The @Query method creates a single SQL query against the database. By comparison, the deleteBy methods execute a read query, then delete each of the items one by one."
    // Note : we use native SQL instead of JPQL because there is no cascade even on embeddable collections so we keep total control on launched queries.
    private void deleteSecurityAnalysisResult(UUID resultId) {
        Set<UUID> contingencyUuids = contingencyRepository.findAllUuidsByResultId(resultId);
        contingencyLimitViolationRepository.deleteAllByContingencyUuidIn(contingencyUuids);
        contingencyRepository.deleteAllContingencyElementsByContingencyUuidIn(contingencyUuids);
        contingencyRepository.deleteAllByResultId(resultId);
        preContingencyLimitViolationRepository.deleteAllByResultId(resultId);
        subjectLimitViolationRepository.deleteAllByResultId(resultId);
        securityAnalysisResultRepository.deleteById(resultId);
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
        Pageable modifiedPageable = addDefaultSort(pageable, DEFAULT_CONTINGENCY_SORT_COLUMN);
        Specification<ContingencyEntity> specification = contingencyRepository.getParentsSpecifications(resultUuid, resourceFilters);
        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch

        // First, we fetch contingencies UUIDs, with all the filters and pagination
        Page<ContingencyRepository.EntityUuid> uuidPage = contingencyRepository.findBy(specification, q ->
            q.project("uuid")
                .as(ContingencyRepository.EntityUuid.class)
                .sortBy(modifiedPageable.getSort())
                .page(modifiedPageable)
        );

        if (!uuidPage.hasContent()) {
            return Page.empty();
        } else {
            List<UUID> uuids = uuidPage.map(ContingencyRepository.EntityUuid::getUuid).toList();
            // Then we fetch the main entities data for each UUID
            List<ContingencyEntity> contingencies = contingencyRepository.findAllByUuidIn(uuids);
            contingencies.sort(Comparator.comparing(c -> uuids.indexOf(c.getUuid())));
            Page<ContingencyEntity> contingenciesPage = new PageImpl<>(contingencies, modifiedPageable, uuidPage.getTotalElements());

            // then we append the missing data, and filter some of the Lazy Loaded collections
            appendLimitViolationsAndElementsToContingenciesResult(contingenciesPage, resourceFilters);

            return contingenciesPage;
        }
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationEntity> findSubjectLimitViolationsPage(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        assertNmKSubjectLimitViolationsSortAllowed(pageable.getSort());
        Pageable modifiedPageable = addDefaultSort(pageable, DEFAULT_SUBJECT_LIMIT_VIOLATION_SORT_COLUMN);
        Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationRepository.getParentsSpecifications(resultUuid, resourceFilters);
        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch
        Page<SubjectLimitViolationRepository.EntityId> uuidPage = subjectLimitViolationRepository.findBy(specification, q ->
            q.project("id")
                .as(SubjectLimitViolationRepository.EntityId.class)
                .sortBy(modifiedPageable.getSort())
                .page(modifiedPageable)
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

    private Pageable addDefaultSort(Pageable pageable, String defaultSortColumn) {
        if (pageable.isPaged() && pageable.getSort().getOrderFor(defaultSortColumn) == null) {
            //if it's already sorted by our defaultColumn we don't add another sort by the same column
            Sort finalSort = pageable.getSort().and(Sort.by(DEFAULT_SORT_DIRECTION, defaultSortColumn));
            return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), finalSort);
        }
        //nothing to do if the request is not paged
        return pageable;
    }
}
