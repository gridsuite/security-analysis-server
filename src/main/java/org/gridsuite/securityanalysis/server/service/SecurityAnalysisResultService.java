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
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.entities.*;
import org.gridsuite.securityanalysis.server.repositories.ContingencyRepository;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisResultService {
    private SecurityAnalysisResultRepository securityAnalysisResultRepository;
    private ContingencyRepository contingencyRepository;

    public SecurityAnalysisResultService(SecurityAnalysisResultRepository securityAnalysisResultRepository,
                                         ContingencyRepository contingencyRepository) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
        this.contingencyRepository = contingencyRepository;
    }

    @Transactional(readOnly = true)
    public SecurityAnalysisResult find(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(limitTypes);

        Optional<SecurityAnalysisResultEntity> securityAnalysisResultEntityOpt = /*limitTypes.isEmpty()*/
            /*?*/ securityAnalysisResultRepository.findById(resultUuid);
/*
            : securityAnalysisResultRepository.findByIdAndFilterLimitViolationsByLimitType(resultUuid, limitTypes);
*/

        if (securityAnalysisResultEntityOpt.isEmpty()) {
            return null;
        }
        SecurityAnalysisResultEntity securityAnalysisResultEntity = securityAnalysisResultEntityOpt.get();
        PreContingencyResultEntity preContingencyResultEntity = securityAnalysisResultEntity.getPreContingencyResult();

        List<LimitViolation> preContingencyLimitViolations = preContingencyResultEntity.getPreContingencyLimitViolation().stream()
            .map(preContingencyLimitViolation -> fromEntity(preContingencyLimitViolation))
            .filter(limitViolation -> limitTypes.isEmpty() || limitTypes.contains(limitViolation.getLimitType()))
            .collect(Collectors.toList());

        PreContingencyResult preContingencyResult = new PreContingencyResult(LoadFlowResult.ComponentResult.Status.valueOf(preContingencyResultEntity.getPreContingencyStatus()),
            new LimitViolationsResult(preContingencyLimitViolations),
            new NetworkResult(Collections.emptyList(), Collections.emptyList(), Collections.emptyList()));

        List<PostContingencyResult> postContingencyResults = securityAnalysisResultEntity.getContingencies().stream()
            .map(contingencyEntity -> {
                PostContingencyComputationStatus status = PostContingencyComputationStatus.valueOf(contingencyEntity.getStatus());
                List<LimitViolation> limitViolations = contingencyEntity.getContingencyLimitViolations().stream()
                    .map(limitViolation -> fromEntity(limitViolation))
                    .filter(limitViolation -> limitTypes.isEmpty() || limitTypes.contains(limitViolation.getLimitType()))
                    .collect(Collectors.toList());
                Contingency contingency = fromEntity(contingencyEntity);
                return new PostContingencyResult(contingency, status, limitViolations);
            })
            .collect(Collectors.toList());

        return new SecurityAnalysisResult(preContingencyResult, postContingencyResults, Collections.emptyList());
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
            Optional<SecurityAnalysisResultEntity> securityAnalysisResult = securityAnalysisResultRepository.findById(resultUuid);
            if (securityAnalysisResult.isPresent()) {
                securityAnalysisResult.get().setStatus(status);
            }
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

    private static LimitViolation fromEntity(AbstractLimitViolationEntity entity) {
        return new LimitViolation(entity.getSubjectId(), entity.getLimitType(), entity.getLimitName(), entity.getAcceptableDuration(),
            entity.getLimit(), entity.getLimitReduction(), entity.getValue(), entity.getSide());
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
        return new Contingency(entity.getContingencyId(), elements);
    }

    private static SecurityAnalysisResultEntity toEntity(UUID resultUuid, SecurityAnalysisResult securityAnalysisResult, SecurityAnalysisStatus securityAnalysisStatus) {
        List<ContingencyEntity> contingencies = securityAnalysisResult.getPostContingencyResults().stream()
            .map(postContingencyResult -> toEntity(postContingencyResult)).collect(Collectors.toList());

        PreContingencyResultEntity preContingencyResult = toEntity(securityAnalysisResult.getPreContingencyResult());

        return new SecurityAnalysisResultEntity(resultUuid, securityAnalysisStatus, contingencies, preContingencyResult);
    }

    private static PreContingencyResultEntity toEntity(PreContingencyResult preContingencyResult) {
        List<PreContingencyLimitViolationEntity> preContingencyLimitViolation = preContingencyResult.getLimitViolationsResult().getLimitViolations().stream().map(limitViolation -> toPreContingencyLimitViolationEntity(limitViolation)).collect(Collectors.toList());
        return new PreContingencyResultEntity(preContingencyResult.getStatus().name(), preContingencyLimitViolation);
    }

    private static ContingencyEntity toEntity(PostContingencyResult postContingencyResult) {
        List<ContingencyElementEmbeddable> contingencyElements = postContingencyResult.getContingency().getElements().stream().map(contingencyElement -> toEntity(contingencyElement)).collect(Collectors.toList());
        List<ContingencyLimitViolationEntity> contingencyLimitViolations = postContingencyResult.getLimitViolationsResult().getLimitViolations().stream().map(limitViolation -> toContingencyLimitViolationEntity(limitViolation)).collect(Collectors.toList());
        return new ContingencyEntity(postContingencyResult.getContingency().getId(), postContingencyResult.getStatus().name(), contingencyElements, contingencyLimitViolations);
    }

    private static ContingencyLimitViolationEntity toContingencyLimitViolationEntity(LimitViolation limitViolation) {
        return new ContingencyLimitViolationEntity(limitViolation.getSubjectId(),
            limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
            limitViolation.getLimitType(), limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
            limitViolation.getSide());
    }

    private static PreContingencyLimitViolationEntity toPreContingencyLimitViolationEntity(LimitViolation limitViolation) {
        return new PreContingencyLimitViolationEntity(limitViolation.getSubjectId(),
            limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
            limitViolation.getLimitType(), limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
            limitViolation.getSide());
    }

    private static ContingencyElementEmbeddable toEntity(ContingencyElement contingencyElement) {
        return new ContingencyElementEmbeddable(contingencyElement.getType(), contingencyElement.getId());
    }
}
