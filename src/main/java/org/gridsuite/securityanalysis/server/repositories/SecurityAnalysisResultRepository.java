package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.security.LimitViolationType;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface SecurityAnalysisResultRepository extends JpaRepository<SecurityAnalysisResultEntity, UUID> {
    @Query("SELECT sar from SecurityAnalysisResultEntity sar INNER JOIN sar.contingencyLimitViolation clv on clv.limitType in (:limitType) WHERE sar.id = :uuid")
    Optional<SecurityAnalysisResultEntity> findByIdAndFilterLimitViolationsByLimitType(UUID uuid, Set<LimitViolationType> limitType);
}
