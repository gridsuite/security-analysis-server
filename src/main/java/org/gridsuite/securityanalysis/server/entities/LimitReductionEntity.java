package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Getter
@Entity
@NoArgsConstructor
@Table(name = "limit_reduction_entity")
public class LimitReductionEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "limit_reduction_entity_values",
            joinColumns = @JoinColumn(name = "limit_reduction_entity_id"),
            foreignKey = @ForeignKey(name = "limitReductionEntity_limitReductionEntityValues_fk")
    )
    @OrderColumn(name = "index")
    @Column(name = "values_") // "values" is not supported in UT with H2
    private List<Double> values;

    public LimitReductionEntity(List<Double> values) {
        this.values = values;
    }
}
