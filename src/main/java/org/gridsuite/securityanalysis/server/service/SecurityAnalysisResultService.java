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
import org.gridsuite.computation.error.ComputationException;
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
import java.util.function.Function;

import static org.gridsuite.computation.error.ComputationBusinessErrorCode.INVALID_SORT_FORMAT;
import static org.gridsuite.computation.error.ComputationBusinessErrorCode.RESULT_NOT_FOUND;
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
    public List<PreContingencyLimitViolationResultDTO> findNResult(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Sort sort) {
        assertResultExists(resultUuid);
        assertPreContingenciesSortAllowed(sort);

        Specification<PreContingencyLimitViolationEntity> specification = preContingencyLimitViolationSpecificationBuilder.buildSpecification(resultUuid, resourceFilters);
        List<PreContingencyLimitViolationEntity> preContingencyLimitViolation = preContingencyLimitViolationRepository.findAll(specification, sort);
        return preContingencyLimitViolation.stream()
                .map(PreContingencyLimitViolationResultDTO::toDto)
                .toList();
    }

    public List<PreContingencyLimitViolationResultDTO> findNResult(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Sort sort) {
        assertResultExists(resultUuid);
        assertPreContingenciesSortAllowed(sort);

        List<ResourceFilterDTO> allResourceFilters = getAllResourceFilters(stringFilters, stringGlobalFilters, globalFilter -> filterService.getResourceFilterN(networkUuid, variantId, globalFilter));
        Specification<PreContingencyLimitViolationEntity> specification = preContingencyLimitViolationSpecificationBuilder.buildSpecification(resultUuid, allResourceFilters);

        List<PreContingencyLimitViolationEntity> preContingencyLimitViolation = preContingencyLimitViolationRepository.findAll(specification, sort);
        return preContingencyLimitViolation.stream()
                .map(PreContingencyLimitViolationResultDTO::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public byte[] findNResultZippedCsv(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Sort sort, CsvTranslationDTO csvTranslations) {
        List<PreContingencyLimitViolationResultDTO> result = self.findNResult(resultUuid, networkUuid, variantId, stringFilters, stringGlobalFilters, sort);
        return CsvExportUtils.csvRowsToZippedCsv(csvTranslations.headers(), csvTranslations.language(), result.stream().map(r -> r.toCsvRow(csvTranslations.enumValueTranslations(), csvTranslations.language())).toList());
    }

    @Transactional(readOnly = true)
    public Page<ContingencyResultDTO> findNmKContingenciesPaged(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        List<ResourceFilterDTO> allResourceFilters = getAllResourceFilters(stringFilters, stringGlobalFilters, globalFilter -> filterService.getResourceFilterContingencies(networkUuid, variantId, globalFilter));
        Page<ContingencyEntity> contingencyPageBis = self.findContingenciesPage(resultUuid, allResourceFilters, pageable);
        return contingencyPageBis.map(ContingencyResultDTO::toDto);
    }

    @Transactional(readOnly = true)
    public List<ContingencyResultDTO> findNmKContingenciesResult(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Sort sort) {
        assertResultExists(resultUuid);

        List<ResourceFilterDTO> allResourceFilters = getAllResourceFilters(stringFilters, stringGlobalFilters, globalFilter -> filterService.getResourceFilterContingencies(networkUuid, variantId, globalFilter));
        List<ContingencyEntity> contingencyEntities = self.findContingencies(resultUuid, allResourceFilters, sort);
        return contingencyEntities.stream().map(ContingencyResultDTO::toDto).toList();
    }

    @Transactional(readOnly = true)
    public byte[] findNmKContingenciesResultZippedCsv(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Sort sort, CsvTranslationDTO csvTranslations) {
        List<ContingencyResultDTO> result = self.findNmKContingenciesResult(resultUuid, networkUuid, variantId, stringFilters, stringGlobalFilters, sort);
        return CsvExportUtils.csvRowsToZippedCsv(csvTranslations.headers(), csvTranslations.language(), result.stream().map(r -> r.toCsvRows(csvTranslations.enumValueTranslations(), csvTranslations.language())).flatMap(List::stream).toList());
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationResultDTO> findNmKConstraintsResultPaged(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Pageable pageable) {
        assertResultExists(resultUuid);

        List<ResourceFilterDTO> allResourceFilters = getAllResourceFilters(stringFilters, stringGlobalFilters, globalFilter -> filterService.getResourceFilterSubjectLimitViolations(networkUuid, variantId, globalFilter));
        Page<SubjectLimitViolationEntity> subjectLimitViolationsPage = self.findSubjectLimitViolationsPage(resultUuid, allResourceFilters, pageable);
        return subjectLimitViolationsPage.map(SubjectLimitViolationResultDTO::toDto);
    }

    @Transactional(readOnly = true)
    public List<SubjectLimitViolationResultDTO> findNmKConstraintsResult(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Sort sort) {
        assertResultExists(resultUuid);
        assertNmKSubjectLimitViolationsSortAllowed(sort);

        List<ResourceFilterDTO> allResourceFilters = getAllResourceFilters(stringFilters, stringGlobalFilters, globalFilter -> filterService.getResourceFilterSubjectLimitViolations(networkUuid, variantId, globalFilter));
        List<SubjectLimitViolationEntity> subjectLimitViolationEntities = self.findSubjectLimitViolations(resultUuid, allResourceFilters, sort);
        return subjectLimitViolationEntities.stream().map(SubjectLimitViolationResultDTO::toDto).toList();
    }

    @Transactional(readOnly = true)
    public byte[] findNmKConstraintsResultZippedCsv(UUID resultUuid, UUID networkUuid, String variantId, String stringFilters, String stringGlobalFilters, Sort sort, CsvTranslationDTO csvTranslations) {
        List<SubjectLimitViolationResultDTO> result = self.findNmKConstraintsResult(resultUuid, networkUuid, variantId, stringFilters, stringGlobalFilters, sort);
        return CsvExportUtils.csvRowsToZippedCsv(csvTranslations.headers(), csvTranslations.language(), result.stream().map(r -> r.toCsvRows(csvTranslations.enumValueTranslations(), csvTranslations.language())).flatMap(List::stream).toList());
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
            throw new ComputationException(INVALID_SORT_FORMAT, "Invalid sort format");
        }
    }

    public void assertResultExists(UUID resultUuid) {
        if (securityAnalysisResultRepository.findById(resultUuid).isEmpty()) {
            throw new ComputationException(RESULT_NOT_FOUND, "Result not found");
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
    public Page<ContingencyEntity> findContingenciesPage(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        assertNmKContingenciesSortAllowed(pageable.getSort());

        Pageable modifiedPageable = addDefaultSortAndRemoveChildrenSortingPage(pageable, ContingencyEntity.Fields.uuid);
        Specification<ContingencyEntity> specification = contingencySpecificationBuilder.buildSpecification(resultUuid, resourceFilters);
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
            appendLimitViolationsAndElementsToContingenciesResultPage(contingenciesPage, resourceFilters);

            return contingenciesPage;
        }
    }

    @Transactional(readOnly = true)
    public List<ContingencyEntity> findContingencies(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Sort sort) {
        Objects.requireNonNull(resultUuid);
        assertNmKContingenciesSortAllowed(sort);

        Sort finalSort = addDefaultSortAndRemoveChildrenSorting(sort, ContingencyEntity.Fields.uuid);
        Specification<ContingencyEntity> specification = contingencySpecificationBuilder.buildSpecification(resultUuid, resourceFilters);

        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch

        // ---- First query: UUIDs only (sorted)
        List<ContingencyRepository.EntityUuid> uuidList = contingencyRepository.findBy(specification, q ->
                q.project("uuid")
                        .as(ContingencyRepository.EntityUuid.class)
                        .sortBy(finalSort)
                        .all()
        );
        List<UUID> uuids = uuidList.stream().map(ContingencyRepository.EntityUuid::getUuid).toList();
        // Then we fetch the main entities data for each UUID
        List<ContingencyEntity> contingencies = contingencyRepository.findAllByUuidIn(uuids);
        contingencies.sort(Comparator.comparing(c -> uuids.indexOf(c.getUuid())));

        appendLimitViolationsAndElementsToContingenciesResult(contingencies, resourceFilters, sort);

        return contingencies;
    }

    @Transactional(readOnly = true)
    public Page<SubjectLimitViolationEntity> findSubjectLimitViolationsPage(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Pageable pageable) {
        Objects.requireNonNull(resultUuid);
        assertNmKSubjectLimitViolationsSortAllowed(pageable.getSort());

        Pageable modifiedPageable = addDefaultSortAndRemoveChildrenSortingPage(pageable, SubjectLimitViolationEntity.Fields.id);
        Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationSpecificationBuilder.buildSpecification(resultUuid, resourceFilters);
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
            appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResultPage(subjectLimitViolationPage, resourceFilters);

            return subjectLimitViolationPage;
        }
    }

    @Transactional(readOnly = true)
    public List<SubjectLimitViolationEntity> findSubjectLimitViolations(UUID resultUuid, List<ResourceFilterDTO> resourceFilters, Sort sort) {
        Objects.requireNonNull(resultUuid); //
        assertNmKSubjectLimitViolationsSortAllowed(sort);

        Sort finalSort = addDefaultSortAndRemoveChildrenSorting(sort, SubjectLimitViolationEntity.Fields.id);
        Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationSpecificationBuilder.buildSpecification(resultUuid, resourceFilters);
        // WARN org.hibernate.hql.internal.ast.QueryTranslatorImpl -
        // HHH000104: firstResult/maxResults specified with collection fetch; applying in memory!
        // cf. https://vladmihalcea.com/fix-hibernate-hhh000104-entity-fetch-pagination-warning-message/
        // We must separate in two requests, one with pagination the other one with Join Fetch
        List<SubjectLimitViolationRepository.EntityId> uuidList = subjectLimitViolationRepository.findBy(specification, q ->
                q.project("id")
                        .as(SubjectLimitViolationRepository.EntityId.class)
                        .sortBy(finalSort)
                        .all()
        );

        List<UUID> uuids = uuidList.stream().map(u -> u.getId()).toList();
        // Then we fetch the main entities data for each UUID
        List<SubjectLimitViolationEntity> subjectLimitViolations = subjectLimitViolationRepository.findAllByIdIn(uuids);
        subjectLimitViolations.sort(Comparator.comparing(lm -> uuids.indexOf(lm.getId())));

        // then we append the missing data, and filter some of the Lazy Loaded collections
        appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResult(subjectLimitViolations, resourceFilters, finalSort);

        return subjectLimitViolations;
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

    private List<ResourceFilterDTO> getAllResourceFilters(String stringFilters, String stringGlobalFilter, Function<GlobalFilter, Optional<ResourceFilterDTO>> getResourceGlobalFilter) {
        List<ResourceFilterDTO> resourceFilters = fromStringFiltersToDTO(stringFilters, objectMapper);
        GlobalFilter globalFilter = fromStringGlobalFiltersToDTO(stringGlobalFilter, objectMapper);
        List<ResourceFilterDTO> allResourceFilters = new ArrayList<>();
        if (resourceFilters != null) {
            allResourceFilters.addAll(resourceFilters);
        }
        if (globalFilter != null) {
            Optional<ResourceFilterDTO> resourceGlobalFilters = getResourceGlobalFilter.apply(globalFilter);
            resourceGlobalFilters.ifPresent(allResourceFilters::add);
        }
        return allResourceFilters;
    }

    private void appendLimitViolationsAndElementsToContingenciesResultPage(Page<ContingencyEntity> contingencies, List<ResourceFilterDTO> resourceFilters) {

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

            sortLimitViolationsInContingenciesPage(contingencies);
        }
    }

    private void appendLimitViolationsAndElementsToContingenciesResult(List<ContingencyEntity> contingencies, List<ResourceFilterDTO> resourceFilters, Sort sort) {

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

            sortLimitViolationsInContingencies(contingencies, sort);
        }
    }

    private void appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResultPage(Page<SubjectLimitViolationEntity> subjectLimitViolations, List<ResourceFilterDTO> resourceFilters) {

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

            sortLimitViolationsInSubjectLimitViolationsPage(subjectLimitViolations);
        }
    }

    private void appendLimitViolationsAndContingencyElementsToSubjectLimitViolationsResult(List<SubjectLimitViolationEntity> subjectLimitViolations, List<ResourceFilterDTO> resourceFilters, Sort sort) {

        // using the the Hibernate First-Level Cache or Persistence Context
        // cf.https://vladmihalcea.com/spring-data-jpa-multiplebagfetchexception/
        if (!subjectLimitViolations.isEmpty()) {
            List<UUID> subjectLimitViolationsUuids = subjectLimitViolations.stream()
                    .map(c -> c.getId())
                    .toList();
            Specification<SubjectLimitViolationEntity> specification = subjectLimitViolationSpecificationBuilder.buildLimitViolationsSpecification(subjectLimitViolationsUuids, resourceFilters);
            subjectLimitViolationRepository.findAll(specification);

            List<UUID> contingencyUuids = subjectLimitViolations.stream().map(SubjectLimitViolationEntity::getContingencyLimitViolations).flatMap(List::stream)
                    .map(lm -> lm.getContingency().getUuid())
                    .toList();
            // we fetch contingencyElements for each contingency here to prevent N+1 query
            contingencyRepository.findAllWithContingencyElementsByUuidIn(contingencyUuids);

            sortLimitViolationsInSubjectLimitViolations(subjectLimitViolations, sort);
        }
    }

    private void sortLimitViolationsInContingenciesPage(Page<ContingencyEntity> contingencies) {
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

    private void sortLimitViolationsInContingencies(List<ContingencyEntity> contingencies, Sort sort) {
        Optional<Sort.Order> lvSortOrder = sort.get()
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

    private void sortLimitViolationsInSubjectLimitViolationsPage(Page<SubjectLimitViolationEntity> subjectLimitViolations) {
        Optional<Sort.Order> lvSortOrder = getLimitViolationLvSortOrderForSubjectLimitViolations(subjectLimitViolations.getSort());
        Comparator<ContingencyLimitViolationEntity> comparator = getLimitViolationComparatorForSubjectLimitViolations(lvSortOrder);

        boolean isSortOrderAscending = lvSortOrder.map(Sort.Order::isAscending).orElse(true);

        subjectLimitViolations.forEach(subjectLimitViolation -> subjectLimitViolation
            .getContingencyLimitViolations()
            .sort(isSortOrderAscending ?
                comparator :
                comparator.reversed()));
    }

    private void sortLimitViolationsInSubjectLimitViolations(List<SubjectLimitViolationEntity> subjectLimitViolations, Sort sort) {
        Optional<Sort.Order> lvSortOrder = getLimitViolationLvSortOrderForSubjectLimitViolations(sort);
        Comparator<ContingencyLimitViolationEntity> comparator = getLimitViolationComparatorForSubjectLimitViolations(lvSortOrder);

        boolean isSortOrderAscending = lvSortOrder.map(Sort.Order::isAscending).orElse(true);

        subjectLimitViolations.forEach(subjectLimitViolation -> subjectLimitViolation
                .getContingencyLimitViolations()
                .sort(isSortOrderAscending ?
                        comparator :
                        comparator.reversed()));
    }

    private Optional<Sort.Order> getLimitViolationLvSortOrderForSubjectLimitViolations(Sort sort) {
        return sort.get()
                // we filter sort on nested limit violations
                .filter(sortOrder ->
                        sortOrder.getProperty().startsWith(SubjectLimitViolationEntity.Fields.contingencyLimitViolations))
                // for now, only one children sort possible
                .findFirst();
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

    private Pageable addDefaultSortAndRemoveChildrenSortingPage(Pageable pageable, String defaultSortColumn) {
        if (pageable.isPaged()) {
            Sort finalSort = addDefaultSortAndRemoveChildrenSorting(pageable.getSort(), defaultSortColumn);
            return PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), finalSort);
        }
        //nothing to do if the request is not paged
        return pageable;
    }

    private Sort addDefaultSortAndRemoveChildrenSorting(Sort sort, String defaultSortColumn) {
        // Can't use both distinct and sort on nested field here, so we have to remove "children" sorting. Maybe there is a way to do it ?
        // https://github.com/querydsl/querydsl/issues/2443
        Sort finalSort = Sort.by(sort.filter(sortOrder -> !sortOrder.getProperty().startsWith("contingencyLimitViolations")).toList());
        //if it's already sorted by our defaultColumn we don't add another sort by the same column
        if (finalSort.getOrderFor(defaultSortColumn) == null) {
            finalSort = finalSort.and(Sort.by(DEFAULT_SORT_DIRECTION, defaultSortColumn));
        }
        return finalSort;
    }
}
