package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "parameters_contingency_list", indexes = {@Index(name = "idx_security_analysis_parameters_id", columnList = "security_analysis_parameters_id")})
public class ParametersContingencyListEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "contingency_list_id")
    private UUID id;

    @ElementCollection
    @CollectionTable(
            name = "parameters_contingency_list_contingencies",
            joinColumns = @JoinColumn(name = "contingency_list_id")
    )
    @Column(name = "contingencies_id")
    private List<UUID> contingenciesIds;

    @Column(name = "description")
    private String description;

    @Column(name = "activated")
    private boolean activated;

    @ManyToOne
    @JoinColumn(name = "security_analysis_parameters_id")
    private SecurityAnalysisParametersEntity securityAnalysisParameters;

    public ParametersContingencyListEntity(List<UUID> contingenciesIds, String description, boolean activated) {
        this.contingenciesIds = contingenciesIds;
        this.description = description;
        this.activated = activated;
    }
}
