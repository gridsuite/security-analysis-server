/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisResult;
import lombok.Getter;
import org.gridsuite.computation.ComputationException;
import org.gridsuite.computation.dto.GlobalFilter;
import org.gridsuite.computation.dto.ResourceFilterDTO;
import org.gridsuite.computation.service.AbstractComputationResultService;
import org.gridsuite.computation.utils.SpecificationUtils;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.*;
import org.gridsuite.securityanalysis.server.repositories.*;
import org.gridsuite.securityanalysis.server.repositories.specifications.ContingencySpecificationBuilder;
import org.gridsuite.securityanalysis.server.repositories.specifications.PreContingencyLimitViolationSpecificationBuilder;
import org.gridsuite.securityanalysis.server.repositories.specifications.SubjectLimitViolationSpecificationBuilder;
import org.gridsuite.securityanalysis.server.util.CsvExportUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.gridsuite.computation.utils.FilterUtils.fromStringFiltersToDTO;
import static org.gridsuite.computation.utils.FilterUtils.fromStringGlobalFiltersToDTO;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisResultService extends AbstractComputationResultService<SecurityAnalysisStatus> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisResultService.class);
    private final SecurityAnalysisResultRepository securityAnalysisResultRepository;
    private final ContingencyRepository contingencyRepository;
    private final PreContingencyLimitViolationRepository preContingencyLimitViolationRepository;
    private final SubjectLimitViolationRepository subjectLimitViolationRepository;
    private final ContingencyLimitViolationRepository contingencyLimitViolationRepository;
    private final ContingencySpecificationBuilder contingencySpecificationBuilder;
    private final SubjectLimitViolationSpecificationBuilder subjectLimitViolationSpecificationBuilder;
    private final PreContingencyLimitViolationSpecificationBuilder preContingencyLimitViolationSpecificationBuilder;
    @Getter
    private final ObjectMapper objectMapper;
    private final FilterService filterService;
    private final SecurityAnalysisResultService self;

    private static final Sort.Direction DEFAULT_SORT_DIRECTION = Sort.Direction.ASC;

    private static final List<String> ALLOWED_NMK_CONTINGENCIES_RESULT_SORT_PROPERTIES = List.of(
        ContingencyEntity.Fields.contingencyId,
        ContingencyEntity.Fields.status,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.locationId,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitName,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limit,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.value,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.loading,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.acceptableDuration,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side,
        ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId
    );

    private static final List<String> ALLOWED_NMK_SUBJECT_LIMIT_VIOLATIONS_RESULT_SORT_PROPERTIES = List.of(
        SubjectLimitViolationEntity.Fields.subjectId,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.locationId,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitName,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limit,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.value,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.loading,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.acceptableDuration,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.contingency + SpecificationUtils.FIELD_SEPARATOR + ContingencyEntity.Fields.contingencyId,
        SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.contingency + SpecificationUtils.FIELD_SEPARATOR + ContingencyEntity.Fields.status
    );

    private static final List<String> ALLOWED_PRECONTINGENCIES_RESULT_SORT_PROPERTIES = List.of(
        AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId,
        AbstractLimitViolationEntity.Fields.limitType,
        AbstractLimitViolationEntity.Fields.limitName,
        AbstractLimitViolationEntity.Fields.limit,
        AbstractLimitViolationEntity.Fields.value,
        AbstractLimitViolationEntity.Fields.loading,
        AbstractLimitViolationEntity.Fields.acceptableDuration,
        AbstractLimitViolationEntity.Fields.side,
        AbstractLimitViolationEntity.Fields.locationId
            );

    public SecurityAnalysisResultService(SecurityAnalysisResultRepository securityAnalysisResultRepository,
                                         ContingencyRepository contingencyRepository,
                                         PreContingencyLimitViolationRepository preContingencyLimitViolationRepository,
                                         SubjectLimitViolationRepository subjectLimitViolationRepository,
                                         ContingencyLimitViolationRepository contingencyLimitViolationRepository,
                                         PreContingencyLimitViolationSpecificationBuilder preContingencyLimitViolationSpecificationBuilder,
                                         ContingencySpecificationBuilder contingencySpecificationBuilder,
                                         SubjectLimitViolationSpecificationBuilder subjectLimitViolationSpecificationBuilder,
                                         @Lazy SecurityAnalysisResultService self,
                                         FilterService filterService,
                                         ObjectMapper objectMapper) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
        this.contingencyRepository = contingencyRepository;
        this.preContingencyLimitViolationRepository = preContingencyLimitViolationRepository;
        this.subjectLimitViolationRepository = subjectLimitViolationRepository;
        this.contingencyLimitViolationRepository = contingencyLimitViolationRepository;
        this.preContingencyLimitViolationSpecificationBuilder = preContingencyLimitViolationSpecificationBuilder;
        this.contingencySpecificationBuilder = contingencySpecificationBuilder;
        this.subjectLimitViolationSpecificationBuilder = subjectLimitViolationSpecificationBuilder;
        this.filterService = filterService;
        this.objectMapper = objectMapper;
        this.self = self;
    }

    @Transactional(readOnly = true)
    public List<PreContingencyLimitViolationResultDTO> findNResult(UUID resultUuid, UUID networkUuid, String variantId, List<ResourceFilterDTO> resourceFilters, GlobalFilter globalFilter, Sort sort) {
        assertResultExists(resultUuid);
        assertPreContingenciesSortAllowed(sort);
        List<ResourceFilterDTO> allResourceFilters = new ArrayList<>();
        if (resourceFilters != null) {
            allResourceFilters.addAll(resourceFilters);
        }
        if (globalFilter != null) {
            Optional<ResourceFilterDTO> resourceGlobalFilters = filterService.getResourceFilterN(networkUuid, variantId, globalFilter);
            resourceGlobalFilters.ifPresent(allResourceFilters::add);
        }
        Specification<PreContingencyLimitViolationEntity> specification = preContingencyLimitViolationSpecificationBuilder.buildSpecification(resultUuid, allResourceFilters);

        List<PreContingencyLimitViolationEntity> preContingencyLimitViolation = preContingencyLimitViolationRepository.findAll(specification, sort);
        return preContingencyLimitViolation.stream()
                .map(PreContingencyLimitViolationResultDTO::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public byte[] findNResultZippedCsv(UUID resultUuid, CsvTranslationDTO csvTranslations) {
        List<PreContingencyLimitViolationResultDTO> result = self.findNResult(resultUuid, null, null, List.of(), null, Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId));

        return CsvExportUtils.csvRowsToZippedCsv(csvTranslations.headers(), result.stream().map(r -> r.toCsvRow(csvTranslations.enumValueTranslations())).toList());
    }

    @Transactional(readOnly = true)
    public Page<ContingencyResultDTO> findNmKContingenciesPaged(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        Page<ContingencyEntity> contingencyPageBis = self.findContingenciesPage(resultUuid, networkUuid, variantId, fromStringFiltersToDTO(stringFilters, objectMapper), fromStringGlobalFiltersToDTO(stringGlobalFilters, objectMapper), pageable);
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
    public Page<SubjectLimitViolationResultDTO> findNmKConstraintsResultPaged(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        Page<SubjectLimitViolationEntity> subjectLimitViolationsPage = self.findSubjectLimitViolationsPage(resultUuid, networkUuid, variantId, fromStringFiltersToDTO(stringFilters, objectMapper), fromStringGlobalFiltersToDTO(stringGlobalFilters, objectMapper), pageable);
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
        assertSortAllowed(sort, ALLOWED_NMK_CONTINGENCIES_RESULT_SORT_PROPERTIES);
    }

    private void assertPreContingenciesSortAllowed(Sort sort) {
        assertSortAllowed(sort, ALLOWED_PRECONTINGENCIES_RESULT_SORT_PROPERTIES);
    }

    private void assertNmKSubjectLimitViolationsSortAllowed(Sort sort) {
        assertSortAllowed(sort, ALLOWED_NMK_SUBJECT_LIMIT_VIOLATIONS_RESULT_SORT_PROPERTIES);
    }

    private void assertSortAllowed(Sort sort, List<String> allowedSortProperties) {
        if (!sort.stream().allMatch(order -> allowedSortProperties.contains(order.getProperty()))) {
            throw new ComputationException(ComputationException.Type.INVALID_SORT_FORMAT);
        }
    }

    public void assertResultExists(UUID resultUuid) {
        if (securityAnalysisResultRepository.findById(resultUuid).isEmpty()) {
            throw new ComputationException(ComputationException.Type.RESULT_NOT_FOUND);
        }
    }

    @Transactional
    public void insert(Network network, UUID resultUuid, SecurityAnalysisResult result, SecurityAnalysisStatus status) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(result);

        SecurityAnalysisResultEntity securityAnalysisResult = SecurityAnalysisResultEntity.toEntity(network, resultUuid, result, status);
        securityAnalysisResultRepository.save(securityAnalysisResult);
    }

    @Override
    @Transactional
    public void insertStatus(List<UUID> resultUuids, SecurityAnalysisStatus status) {
        Objects.requireNonNull(resultUuids);
        resultUuids.forEach(resultUuid -> {
            SecurityAnalysisResultEntity securityAnalysisResult = securityAnalysisResultRepository.findById(resultUuid).orElse(new SecurityAnalysisResultEntity(resultUuid));
            securityAnalysisResult.setStatus(status);
            securityAnalysisResultRepository.save(securityAnalysisResult);
        });
    }

    @Override
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

    @Override
    @Transactional
    public void deleteAll() {
        securityAnalysisResultRepository.deleteAll();
    }

    @Override
    @Transactional(readOnly = true)
    public SecurityAnalysisStatus findStatus(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        Optional<SecurityAnalysisResultEntity> securityAnalysisResult = securityAnalysisResultRepository.findById(resultUuid);
        if (securityAnalysisResult.isEmpty()) {
            return null;
        }

        return securityAnalysisResult.get().getStatus();
    }

    private static Page<?> emptyPage(Pageable pageable) {
        return new PageImpl<>(List.of(), pageable, 0);
    }

    @Transactional(readOnly = true)
    public Page<ContingencyEntity> findContingenciesPage(UUID resultUuid, UUID networkUuid, String variantId, List<ResourceFilterDTO> resourceFilters, GlobalFilter globalFilter, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        assertNmKContingenciesSortAllowed(pageable.getSort());
        Pageable modifiedPageable = addDefaultSortAndRemoveChildrenSorting(pageable, ContingencyEntity.Fields.uuid);
        List<ResourceFilterDTO> allResourceFilters = new ArrayList<>();
        if (resourceFilters != null) {
            allResourceFilters.addAll(resourceFilters);
        }
        if (globalFilter != null) {
            Optional<ResourceFilterDTO> resourceGlobalFilters = filterService.getResourceFilterContingencies(networkUuid, variantId, globalFilter);
            resourceGlobalFilters.ifPresent(allResourceFilters::add);
        }
        Specification<ContingencyEntity> specification = contingencySpecificationBuilder.buildSpecification(resultUuid, allResourceFilters);
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
            // Since springboot 3.2, the return value of Page.empty() is not serializable. See https://github.com/spring-projects/spring-data-commons/issues/2987
            return (Page<ContingencyEntity>) emptyPage(pageable);
        } else {
            List<UUID> uuids = uuidPage.map(ContingencyRepository.EntityUuid::getUuid).toList();
            // Then we fetch the main entities data for each UUID
            List<ContingencyEntity> contingencies = contingencyRepository.findAllByUuidIn(uuids);
            contingencies.sort(Comparator.comparing(c -> uuids.indexOf(c.getUuid())));
            Page<ContingencyEntity> contingenciesPage = new PageImpl<>(contingencies, pageable, uuidPage.getTotalElements());

            // then we append the missing data, and filter some of the Lazy Loaded collections
            appendLimitViolationsAndElementsToContingenciesResult(contingenciesPage, allResourceFilters);

            return contingenciesPage;
        }
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationEntity> findSubjectLimitViolationsPage(UUID resultUuid, UUID networkUuid, String variantId, List<ResourceFilterDTO> resourceFilters, GlobalFilter globalFilter, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        assertNmKSubjectLimitViolationsSortAllowed(pageable.getSort());
        Pageable modifiedPageable = addDefaultSortAndRemoveChildrenSorting(pageable, SubjectLimitViolationEntity.Fields.id);
        List<ResourceFilterDTO> allResourceFilters = new ArrayList<>();
        if (resourceFilters != null) {
            allResourceFilters.addAll(resourceFilters);
        }
        if (globalFilter != null) {
            Optional<ResourceFilterDTO> resourceGlobalFilters = filterService.getResourceFilterSubjectLimitViolations(networkUuid, variantId, globalFilter);
            resourceGlobalFilters.ifPresent(allResourceFilters::add);
        }
        Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationSpecificationBuilder.buildSpecification(resultUuid, allResourceFilters);
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
            // Since springboot 3.2, the return value of Page.empty() is not serializable. See https://github.com/spring-projects/spring-data-commons/issues/2987
            return (Page<SubjectLimitViolationEntity>) emptyPage(pageable);
        } else {
            List<UUID> uuids = uuidPage.map(u -> u.getId()).toList();
            // Then we fetch the main entities data for each UUID
            List<SubjectLimitViolationEntity> subjectLimitViolations = subjectLimitViolationRepository.findAllByIdIn(uuids);
            subjectLimitViolations.sort(Comparator.comparing(lm -> uuids.indexOf(lm.getId())));
            Page<SubjectLimitViolationEntity> subjectLimitViolationPage = new PageImpl<>(subjectLimitViolations, pageable, uuidPage.getTotalElements());

            // then we append the missing data, and filter some of the Lazy Loaded collections
            appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResult(subjectLimitViolationPage, allResourceFilters);

            return subjectLimitViolationPage;
        }
    }

    @Transactional(readOnly = true)
    public List<LimitViolationType> findNResultLimitTypes(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return preContingencyLimitViolationRepository.findLimitTypes(resultUuid);
    }

    @Transactional(readOnly = true)
    public List<LimitViolationType> findNmKResultLimitTypes(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return contingencyLimitViolationRepository.findLimitTypes(resultUuid);
    }

    @Transactional(readOnly = true)
    public List<ThreeSides> findNResultBranchSides(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return preContingencyLimitViolationRepository.findBranchSides(resultUuid);
    }

    @Transactional(readOnly = true)
    public List<ThreeSides> findNmKResultBranchSides(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return contingencyLimitViolationRepository.findBranchSides(resultUuid);
    }

    @Transactional(readOnly = true)
    public List<com.powsybl.loadflow.LoadFlowResult.ComponentResult.Status> findNmKComputingStatus(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return contingencyRepository.findComputingStatus(resultUuid);
    }

    private void appendLimitViolationsAndElementsToContingenciesResult(Page<ContingencyEntity> contingencies, List<ResourceFilterDTO> resourceFilters) {

        // using the the Hibernate First-Level Cache or Persistence Context
        // cf.https://vladmihalcea.com/spring-data-jpa-multiplebagfetchexception/
        if (!contingencies.isEmpty()) {
            List<UUID> contingencyUuids = contingencies.stream()
                .map(c -> c.getUuid())
                .toList();
            Specification<ContingencyEntity> specification = contingencySpecificationBuilder.buildLimitViolationsSpecification(contingencyUuids, resourceFilters);
            contingencyRepository.findAll(specification);
            // we fetch contingencyElements here to prevent N+1 query
            contingencyRepository.findAllWithContingencyElementsByUuidIn(contingencyUuids);

            sortLimitViolationsInContingencies(contingencies);
        }
    }

    private void appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResult(Page<SubjectLimitViolationEntity> subjectLimitViolations, List<ResourceFilterDTO> resourceFilters) {

        // using the the Hibernate First-Level Cache or Persistence Context
        // cf.https://vladmihalcea.com/spring-data-jpa-multiplebagfetchexception/
        if (!subjectLimitViolations.isEmpty()) {
            List<UUID> subjectLimitViolationsUuids = subjectLimitViolations.stream()
                .map(c -> c.getId())
                .toList();
            Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationSpecificationBuilder.buildLimitViolationsSpecification(subjectLimitViolationsUuids, resourceFilters);
            subjectLimitViolationRepository.findAll(specification);

            List<UUID> contingencyUuids = subjectLimitViolations.map(SubjectLimitViolationEntity::getContingencyLimitViolations).flatMap(List::stream)
                .map(lm -> lm.getContingency().getUuid())
                .toList();
            // we fetch contingencyElements for each contingency here to prevent N+1 query
            contingencyRepository.findAllWithContingencyElementsByUuidIn(contingencyUuids);

            sortLimitViolationsInSubjectLimitViolations(subjectLimitViolations);
        }
    }

    private void sortLimitViolationsInContingencies(Page<ContingencyEntity> contingencies) {
        Optional<Sort.Order> lvSortOrder = contingencies.getSort().get()
            // we filter sort on nested limit violations
            .filter(sortOrder ->
                sortOrder.getProperty().startsWith(ContingencyEntity.Fields.contingencyLimitViolations))
            // for now, only one children sort possible
            .findFirst();

        Comparator<ContingencyLimitViolationEntity> comparator = getLimitViolationComparatorForContingencies(lvSortOrder);

        boolean isSortOrderAscending = lvSortOrder.map(Sort.Order::isAscending).orElse(true);

        contingencies.forEach(contingency -> contingency
            .getContingencyLimitViolations()
            .sort(isSortOrderAscending ?
                comparator :
                comparator.reversed()));
    }

    private void sortLimitViolationsInSubjectLimitViolations(Page<SubjectLimitViolationEntity> subjectLimitViolations) {
        Optional<Sort.Order> lvSortOrder = subjectLimitViolations.getSort().get()
            // we filter sort on nested limit violations
            .filter(sortOrder ->
                sortOrder.getProperty().startsWith(SubjectLimitViolationEntity.Fields.contingencyLimitViolations))
            // for now, only one children sort possible
            .findFirst();

        Comparator<ContingencyLimitViolationEntity> comparator = getLimitViolationComparatorForSubjectLimitViolations(lvSortOrder);

        boolean isSortOrderAscending = lvSortOrder.map(Sort.Order::isAscending).orElse(true);

        subjectLimitViolations.forEach(subjectLimitViolation -> subjectLimitViolation
            .getContingencyLimitViolations()
            .sort(isSortOrderAscending ?
                comparator :
                comparator.reversed()));
    }

    private static Comparator<ContingencyLimitViolationEntity> getLimitViolationComparatorForContingencies(Optional<Sort.Order> lvSortOrder) {
        if (lvSortOrder.isPresent()) {
            String field = lvSortOrder.get().getProperty()
                .replaceFirst(ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR, "");
            return switch (field) {
                case AbstractLimitViolationEntity.Fields.subjectLimitViolation
                    + SpecificationUtils.FIELD_SEPARATOR
                    + SubjectLimitViolationEntity.Fields.subjectId ->
                    Comparator.comparing(value -> value.getSubjectLimitViolation().getSubjectId(), Comparator.nullsLast(Comparator.naturalOrder()));
                default -> getCommonComparator(field);
            };
        } else {
            return Comparator.comparing(limitViolation -> limitViolation.getSubjectLimitViolation().getSubjectId());
        }
    }

    private static Comparator<ContingencyLimitViolationEntity> getLimitViolationComparatorForSubjectLimitViolations(Optional<Sort.Order> lvSortOrder) {
        if (lvSortOrder.isPresent()) {
            String field = lvSortOrder.get().getProperty()
                .replaceFirst(SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR, "");
            return switch (field) {
                case ContingencyLimitViolationEntity.Fields.contingency
                    + SpecificationUtils.FIELD_SEPARATOR
                    + ContingencyEntity.Fields.contingencyId ->
                    Comparator.comparing(value -> value.getContingency().getContingencyId(), Comparator.nullsLast(Comparator.naturalOrder()));
                case ContingencyLimitViolationEntity.Fields.contingency
                    + SpecificationUtils.FIELD_SEPARATOR
                    + ContingencyEntity.Fields.status ->
                    Comparator.comparing(value -> value.getContingency().getStatus(), Comparator.nullsLast(Comparator.naturalOrder()));
                default -> getCommonComparator(field);
            };
        } else {
            return Comparator.comparing(limitViolation -> limitViolation.getContingency().getContingencyId());
        }
    }

    private static Comparator<ContingencyLimitViolationEntity> getCommonComparator(String field) {
        return switch (field) {
            case AbstractLimitViolationEntity.Fields.limit ->
                Comparator.comparing(AbstractLimitViolationEntity::getLimit, Comparator.nullsLast(Comparator.naturalOrder()));
            case AbstractLimitViolationEntity.Fields.limitName ->
                Comparator.comparing(AbstractLimitViolationEntity::getLimitName, Comparator.nullsLast(Comparator.naturalOrder()));
            case AbstractLimitViolationEntity.Fields.limitType ->
                Comparator.comparing(AbstractLimitViolationEntity::getLimitType, Comparator.nullsLast(Comparator.naturalOrder()));
            case AbstractLimitViolationEntity.Fields.acceptableDuration ->
                Comparator.comparing(AbstractLimitViolationEntity::getAcceptableDuration, Comparator.nullsLast(Comparator.naturalOrder()));
            case AbstractLimitViolationEntity.Fields.value ->
                Comparator.comparing(AbstractLimitViolationEntity::getValue, Comparator.nullsLast(Comparator.naturalOrder()));
            case AbstractLimitViolationEntity.Fields.side ->
                Comparator.comparing(AbstractLimitViolationEntity::getSide, Comparator.nullsLast(Comparator.naturalOrder()));
            case AbstractLimitViolationEntity.Fields.loading ->
                Comparator.comparing(AbstractLimitViolationEntity::getLoading, Comparator.nullsLast(Comparator.naturalOrder()));
            case AbstractLimitViolationEntity.Fields.locationId ->
                Comparator.comparing(AbstractLimitViolationEntity::getLocationId, Comparator.nullsLast(Comparator.naturalOrder()));
            default -> throw new IllegalArgumentException("Sorting on the column '" + field + "' is not supported"); // not supposed to happen
        };
    }

    private Pageable addDefaultSortAndRemoveChildrenSorting(Pageable pageable, String defaultSortColumn) {
        if (pageable.isPaged()) {
            // Can't use both distinct and sort on nested field here, so we have to remove "children" sorting. Maybe there is a way to do it ?
            // https://github.com/querydsl/querydsl/issues/2443
            Sort finalSort = Sort.by(pageable.getSort().filter(sortOrder -> !sortOrder.getProperty().startsWith("contingencyLimitViolations")).toList());
            //if it's already sorted by our defaultColumn we don't add another sort by the same column
            if (finalSort.getOrderFor(defaultSortColumn) == null) {
                finalSort = finalSort.and(Sort.by(DEFAULT_SORT_DIRECTION, defaultSortColumn));
            }
            return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), finalSort);
        }
        //nothing to do if the request is not paged
        return pageable;
    }
}
