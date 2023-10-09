package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.security.LimitViolationType;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface SecurityAnalysisResultRepository extends JpaRepository<SecurityAnalysisResultEntity, UUID> {
}
