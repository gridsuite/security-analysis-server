package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.ConstraintEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ConstraintRepository extends JpaRepository<ConstraintEntity, UUID> {
    List<ConstraintEntity> findByResultIdOrderBySubjectId(UUID resultUuid);
}
