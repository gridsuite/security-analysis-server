package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisResult;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;


import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface SecurityAnalysisResultRepository extends JpaRepository<SecurityAnalysisResultEntity, UUID> {
    /*@Query("SELECT sar from SecurityAnalysisResultEntity sar " +
        "LEFT JOIN FETCH sar.contingencyLimitViolation clv " +
        "LEFT JOIN sar.preContingencyResult pcr " +
        "LEFT JOIN pcr.preContingencyLimitViolation pclv " +
        "where clv.limitType in (:limitType) " +
        "and pclv.limitType in (:limitType) " +
        "and sar.id = :uuid")*/

    @Query("SELECT sar from SecurityAnalysisResultEntity sar " +
        "LEFT JOIN FETCH sar.contingencies c " +
        "INNER JOIN FETCH c.contingencyLimitViolations clv " +
        "where clv.limitType in (:limitType) " +
        "and sar.id = :uuid")
    Optional<SecurityAnalysisResultEntity> findByIdAndFilterLimitViolationsByLimitType(UUID uuid, Set<LimitViolationType> limitType);

    @EntityGraph(attributePaths = {"contingencies", "contingencies.contingencyLimitViolations"}, type = EntityGraph.EntityGraphType.FETCH)
    List<SecurityAnalysisResultEntity> findWithContingencyLimitViolationsById(UUID id);

    @Query("SELECT sar from SecurityAnalysisResultEntity sar LEFT JOIN sar.contingencyLimitViolation clv where clv IS NULL OR clv.limitType in (:limitType)")
    List<SecurityAnalysisResultEntity> findAllByIdAndFilterLimitViolationsByLimitType(Set<LimitViolationType> limitType);

    @Query("SELECT sar from SecurityAnalysisResultEntity sar where sar.id = :uuid")
    List<SecurityAnalysisResultEntity> findAllById(UUID uuid);
}
