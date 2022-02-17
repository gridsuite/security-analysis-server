/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.gridsuite.securityanalysis.server.entities.ComputationStatusEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyElementEmbeddable;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.GlobalStatusEntity;
import org.gridsuite.securityanalysis.server.entities.LimitViolationEntity;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.BusbarSectionContingency;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.contingency.DanglingLineContingency;
import com.powsybl.contingency.GeneratorContingency;
import com.powsybl.contingency.HvdcLineContingency;
import com.powsybl.contingency.LineContingency;
import com.powsybl.contingency.LoadContingency;
import com.powsybl.contingency.ShuntCompensatorContingency;
import com.powsybl.contingency.StaticVarCompensatorContingency;
import com.powsybl.contingency.ThreeWindingsTransformerContingency;
import com.powsybl.contingency.TwoWindingsTransformerContingency;
import com.powsybl.security.LimitViolation;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.LimitViolationsResult;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.results.PostContingencyResult;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Repository
public class SecurityAnalysisResultRepository {

    private ComputationStatusRepository computationStatusRepository;

    private ContingencyRepository contingencyRepository;

    private LimitViolationRepository limitViolationRepository;

    private GlobalStatusRepository globalStatusRepository;

    public SecurityAnalysisResultRepository(ComputationStatusRepository computationStatusRepository,
                                            ContingencyRepository contingencyRepository,
                                            LimitViolationRepository limitViolationRepository,
                                            GlobalStatusRepository globalStatusRepository) {
        this.computationStatusRepository = computationStatusRepository;
        this.contingencyRepository = contingencyRepository;
        this.limitViolationRepository = limitViolationRepository;
        this.globalStatusRepository = globalStatusRepository;
    }

    private static LimitViolation fromEntity(LimitViolationEntity entity) {
        return new LimitViolation(entity.getSubjectId(), entity.getLimitType(), entity.getLimitName(), entity.getAcceptableDuration(),
                entity.getLimit(), entity.getLimitReduction(), entity.getValue(), entity.getSide());
    }

    private static boolean fromEntity(ComputationStatusEntity entity) {
        return entity.isOk();
    }

    private static Contingency fromEntity(ContingencyEntity entity) {
        List<ContingencyElement> elements = entity.getContingencyElements().stream()
            .map(e -> {
                switch (e.getElementType()) {
                    case LINE: return new LineContingency(e.getElementId());
                    case BRANCH: return new BranchContingency(e.getElementId());
                    case LOAD: return new LoadContingency(e.getElementId());
                    case GENERATOR: return new GeneratorContingency(e.getElementId());
                    case BUSBAR_SECTION: return new BusbarSectionContingency(e.getElementId());
                    case HVDC_LINE: return new HvdcLineContingency(e.getElementId());
                    case DANGLING_LINE: return new DanglingLineContingency(e.getElementId());
                    case SHUNT_COMPENSATOR: return new ShuntCompensatorContingency(e.getElementId());
                    case TWO_WINDINGS_TRANSFORMER: return new TwoWindingsTransformerContingency(e.getElementId());
                    case THREE_WINDINGS_TRANSFORMER: return new ThreeWindingsTransformerContingency(e.getElementId());
                    case STATIC_VAR_COMPENSATOR: return new StaticVarCompensatorContingency(e.getElementId());
                    default:
                        throw new IllegalStateException("Element type yet support: " + e.getElementType());
                }
            }).collect(Collectors.toList());
        return new Contingency(entity.getContingencyId(), elements);
    }

    private static LimitViolationEntity toEntity(UUID resultUuid, String contingencyId, LimitViolation limitViolation) {
        return new LimitViolationEntity(resultUuid, limitViolation.getLimitType(), contingencyId, limitViolation.getSubjectId(),
                limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
                limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
                limitViolation.getSide());
    }

    private static ComputationStatusEntity toEntity(UUID resultUuid, Contingency contingency, boolean ok) {
        return new ComputationStatusEntity(resultUuid, contingency != null ? contingency.getId() : "", ok);
    }

    private static List<LimitViolationEntity> toEntity(UUID resultUuid, Contingency contingency, List<LimitViolation> limitViolations) {
        return limitViolations
                .stream()
                .map(limitViolation -> toEntity(resultUuid, contingency != null ? contingency.getId() : "", limitViolation))
                .collect(Collectors.toList());
    }

    private static ContingencyEntity toEntity(UUID resultUuid, Contingency contingency) {
        List<ContingencyElementEmbeddable> elements = contingency.getElements().stream()
            .map(e -> new ContingencyElementEmbeddable(e.getType(), e.getId())).collect(Collectors.toList());
        return new ContingencyEntity(resultUuid, contingency.getId(), elements);
    }

    private static GlobalStatusEntity toEntity(UUID resultUuid, String status) {
        return new GlobalStatusEntity(resultUuid, status);
    }

    @Transactional(readOnly = true)
    public SecurityAnalysisResult find(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(limitTypes);

        // load all rows related to this result UUID
        List<ComputationStatusEntity> statusEntities = computationStatusRepository.findByResultUuid(resultUuid);

        Map<String, Boolean> computationsStatuses = statusEntities.stream()
            .collect(Collectors.toMap(ComputationStatusEntity::getContingencyId, SecurityAnalysisResultRepository::fromEntity));

        List<LimitViolationEntity> limitViolationEntities = limitTypes.isEmpty()
            ? limitViolationRepository.findByResultUuid(resultUuid)
            : limitViolationRepository.findByResultUuidAndLimitTypeIn(resultUuid, limitTypes);

        Map<String, Collection<LimitViolation>> limitViolations = limitViolationEntities.stream()
            .map(lve -> ImmutablePair.of(lve.getContingencyId(), fromEntity(lve)))
            .collect(
                Collectors.groupingBy(Pair::getKey, Collectors.mapping(Pair::getValue, Collectors.toCollection(ArrayList::new))));

        List<ContingencyEntity> contingencyEntities = contingencyRepository.findByResultUuid(resultUuid);
        List<Contingency> contingencies = contingencyEntities.stream()
                .map(SecurityAnalysisResultRepository::fromEntity)
                .collect(Collectors.toList());

        // and then rebuild security analysis data structure

        Boolean preContingencyComputationOk = computationsStatuses.get("");
        if (preContingencyComputationOk == null) {
            return null;
        }

        List<LimitViolation> preContingencyViolations = (List<LimitViolation>) limitViolations.getOrDefault("", Collections.emptyList());
        LimitViolationsResult preContingencyResult = new LimitViolationsResult(Objects.equals(Boolean.TRUE, preContingencyComputationOk),
            preContingencyViolations);

        List<PostContingencyResult> postContingencyResults = contingencies.stream()
                .map(contingency -> {
                    Boolean computationOk = computationsStatuses.get(contingency.getId());
                    ArrayList<LimitViolation> limitViolations1 = new ArrayList<>(
                        limitViolations.getOrDefault(contingency.getId(), Collections.emptyList()));
                    return new PostContingencyResult(contingency, computationOk != null && computationOk,
                        limitViolations1);
                })
                .collect(Collectors.toList());

        return new SecurityAnalysisResult(preContingencyResult, postContingencyResults);
    }

    @Transactional
    public void insert(UUID resultUuid, SecurityAnalysisResult result) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(result);

        // !!! save pre-contingency result last, so we can rely on it to known if full result is available
        result.getPostContingencyResults().forEach(
            postContingencyResult -> {
                contingencyRepository.save(toEntity(resultUuid, postContingencyResult.getContingency()));
                computationStatusRepository.save(toEntity(resultUuid, postContingencyResult.getContingency(),
                    postContingencyResult.getLimitViolationsResult().isComputationOk()));
                limitViolationRepository.saveAll(toEntity(resultUuid, postContingencyResult.getContingency(),
                    postContingencyResult.getLimitViolationsResult().getLimitViolations()));
            }
        );
        LimitViolationsResult limitViolationsResult = result.getPreContingencyResult().getLimitViolationsResult();
        computationStatusRepository.save(toEntity(resultUuid, null, limitViolationsResult.isComputationOk()));
        limitViolationRepository.saveAll(toEntity(resultUuid, null, limitViolationsResult.getLimitViolations()));
    }

    public void insertStatus(List<UUID> resultUuids, String status) {
        Objects.requireNonNull(resultUuids);
        globalStatusRepository.saveAll(resultUuids.stream()
            .map(uuid -> toEntity(uuid, status)).collect(Collectors.toList()));
    }

    @Transactional
    public void delete(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        computationStatusRepository.deleteByResultUuid(resultUuid);
        limitViolationRepository.deleteByResultUuid(resultUuid);
        contingencyRepository.deleteByResultUuid(resultUuid);
        globalStatusRepository.deleteByResultUuid(resultUuid);
    }

    @Transactional
    public void deleteAll() {
        computationStatusRepository.deleteAll();
        limitViolationRepository.deleteAll();
        contingencyRepository.deleteAll();
        globalStatusRepository.deleteAll();
    }

    public String findStatus(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        GlobalStatusEntity byResultUuid = globalStatusRepository.findByResultUuid(resultUuid);
        return byResultUuid == null ? null : byResultUuid.getStatus();
    }

}
