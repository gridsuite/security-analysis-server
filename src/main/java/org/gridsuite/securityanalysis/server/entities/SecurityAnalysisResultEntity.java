package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@NoArgsConstructor
@Getter
@Entity
@Table(name = "result")
public class SecurityAnalysisResultEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    private String status;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ContingencyEntity> contingencies;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ContingencyLimitViolationEntity> contingencyLimitViolation;

    @Embedded
    private PreContingencyResultEntity preContingencyResult;

    public SecurityAnalysisResultEntity(String status, List<ContingencyEntity> contingencies, PreContingencyResultEntity preContingencyResult) {
        this.status = status;
        this.contingencies = contingencies;
        this.preContingencyResult = preContingencyResult;
    }
}
