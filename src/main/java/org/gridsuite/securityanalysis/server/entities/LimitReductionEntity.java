package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Getter
@Entity
@NoArgsConstructor
@Table(name = "limitReductionEntity", indexes = {@Index(name = "idx_security_analysis_parameters_id", columnList = "security_analysis_parameters_id")})
public class LimitReductionEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "limit_reduction_entity_reductions",
            joinColumns = @JoinColumn(name = "limit_reduction_entity_id"),
            foreignKey = @ForeignKey(name = "limitReductionEntity_limitReductionEntityReductions_fk")
    )
    @OrderColumn(name = "index")
    @Column(name = "reductions")
    private List<Double> reductions;

    public LimitReductionEntity(List<Double> reductions) {
        this.reductions = reductions;
    }
}
