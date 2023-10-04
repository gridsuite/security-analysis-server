package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;

import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "result")
public class ResultEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    private String status;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ContingencyEntity> contingencies;

    @OneToMany
    private List<ContingencyLimitViolationEntity> contingencyLimitViolation;

    @ElementCollection
    private List<PreContingencyLimitViolationEntity> preContingencyLimitViolation;
}
