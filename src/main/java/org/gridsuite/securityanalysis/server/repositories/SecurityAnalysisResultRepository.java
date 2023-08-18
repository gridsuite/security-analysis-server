/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.contingency.*;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.*;
import com.powsybl.security.results.NetworkResult;
import com.powsybl.security.results.PostContingencyResult;
import com.powsybl.security.results.PreContingencyResult;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.entities.*;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

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

    private static String fromEntity(ComputationStatusEntity entity) {
        return entity.getStatus();
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
                        throw new IllegalStateException("Element type not yet support: " + e.getElementType());
                }
            }).collect(Collectors.toList());
        return new Contingency(entity.getResultId().getContingencyId(), elements);
    }

    private static LimitViolationEntity toEntity(UUID resultUuid, String contingencyId, LimitViolation limitViolation) {
        return new LimitViolationEntity(resultUuid, limitViolation.getLimitType(), contingencyId, limitViolation.getSubjectId(),
                limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
                limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
                limitViolation.getSide());
    }

    private static ComputationStatusEntity toEntity(UUID resultUuid, Contingency contingency, String status) {
        return new ComputationStatusEntity(resultUuid, contingency != null ? contingency.getId() : "", status);
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
        return new ContingencyEntity(new ContingencyEntityId(resultUuid, contingency.getId()), elements);
    }

    private static GlobalStatusEntity toEntity(UUID resultUuid, SecurityAnalysisStatus status) {
        return new GlobalStatusEntity(resultUuid, status);
    }

    @Transactional(readOnly = true)
    public SecurityAnalysisResult find(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(limitTypes);

        // load all rows related to this result UUID
        List<ComputationStatusEntity> statusEntities = computationStatusRepository.findByResultUuid(resultUuid);

        Map<String, String> computationsStatusesByContingencyId = statusEntities.stream()
            .collect(Collectors.toMap(ComputationStatusEntity::getContingencyId, SecurityAnalysisResultRepository::fromEntity));

        List<LimitViolationEntity> limitViolationEntities = limitTypes.isEmpty()
            ? limitViolationRepository.findByResultUuid(resultUuid)
            : limitViolationRepository.findByResultUuidAndLimitTypeIn(resultUuid, limitTypes);

        Map<String, List<LimitViolation>> limitViolationsByContingencyId = limitViolationEntities.stream()
            .map(lve -> ImmutablePair.of(lve.getContingencyId(), fromEntity(lve)))
            .collect(
                Collectors.groupingBy(Pair::getKey, Collectors.mapping(Pair::getValue, Collectors.toCollection(ArrayList::new))));

        List<ContingencyEntity> contingencyEntities = contingencyRepository.findByResultIdResultUuid(resultUuid);
        List<Contingency> contingencies = contingencyEntities.stream()
                .map(SecurityAnalysisResultRepository::fromEntity)
                .collect(Collectors.toList());

        // and then rebuild security analysis data structure

        String preContingencyComputationStatus = computationsStatusesByContingencyId.get("");
        if (preContingencyComputationStatus == null) {
            return null;
        }

        List<LimitViolation> preContingencyViolations = limitViolationsByContingencyId.getOrDefault("", Collections.emptyList());
        PreContingencyResult preContingencyResult = new PreContingencyResult(LoadFlowResult.ComponentResult.Status.valueOf(preContingencyComputationStatus),
                                                                             new LimitViolationsResult(preContingencyViolations),
                                                                             new NetworkResult(Collections.emptyList(), Collections.emptyList(), Collections.emptyList()));

        List<PostContingencyResult> postContingencyResults = contingencies.stream()
                .map(contingency -> {
                    PostContingencyComputationStatus status = PostContingencyComputationStatus.valueOf(computationsStatusesByContingencyId.get(contingency.getId()));
                    List<LimitViolation> limitViolations = limitViolationsByContingencyId.getOrDefault(contingency.getId(), Collections.emptyList());
                    return new PostContingencyResult(contingency, status, limitViolations);
                })
                .collect(Collectors.toList());

        return new SecurityAnalysisResult(preContingencyResult, postContingencyResults, Collections.emptyList());
    }

    @Transactional
    public void insert(UUID resultUuid, SecurityAnalysisResult result) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(result);

        // !!! save pre-contingency result last, so we can rely on it to known if full result is available
        result.getPostContingencyResults().forEach(
            postContingencyResult -> {
                contingencyRepository.save(toEntity(resultUuid, postContingencyResult.getContingency()));
                computationStatusRepository.save(toEntity(resultUuid, postContingencyResult.getContingency(), postContingencyResult.getStatus().name()));
                limitViolationRepository.saveAll(toEntity(resultUuid, postContingencyResult.getContingency(),
                    postContingencyResult.getLimitViolationsResult().getLimitViolations()));
            }
        );
        computationStatusRepository.save(toEntity(resultUuid, null, result.getPreContingencyResult().getStatus().name()));
        limitViolationRepository.saveAll(toEntity(resultUuid, null, result.getPreContingencyResult().getLimitViolationsResult().getLimitViolations()));
    }

    public void insertStatus(List<UUID> resultUuids, SecurityAnalysisStatus status) {
        Objects.requireNonNull(resultUuids);
        globalStatusRepository.saveAll(resultUuids.stream()
            .map(uuid -> toEntity(uuid, status)).collect(Collectors.toList()));
    }

    @Transactional
    public void delete(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        computationStatusRepository.deleteByResultUuid(resultUuid);
        limitViolationRepository.deleteByResultUuid(resultUuid);
        contingencyRepository.deleteByResultIdResultUuid(resultUuid);
        globalStatusRepository.deleteByResultUuid(resultUuid);
    }

    @Transactional
    public void deleteAll() {
        computationStatusRepository.deleteAll();
        limitViolationRepository.deleteAll();
        contingencyRepository.deleteAll();
        globalStatusRepository.deleteAll();
    }

    public SecurityAnalysisStatus findStatus(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        GlobalStatusEntity byResultUuid = globalStatusRepository.findByResultUuid(resultUuid);
        return byResultUuid == null ? null : byResultUuid.getStatus();
    }

}
