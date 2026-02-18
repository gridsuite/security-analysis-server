/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
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
@Table(name = "parameters_contingency_lists", indexes = {@Index(name = "idx_parameters_contingency_lists_security_analysis_parameters_id", columnList = "security_analysis_parameters_id")})
public class ParametersContingencyListEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @ElementCollection
    @CollectionTable(
            name = "parameters_contingency_lists_contingency_list",
            joinColumns = @JoinColumn(name = "parameters_contingency_lists_id"),
            foreignKey = @ForeignKey(name = "parameters_contingency_lists_id_fk")
    )
    @Column(name = "contingency_list_id")
    private List<UUID> contingencyListIds;

    @Column(name = "description")
    private String description;

    @Column(name = "activated")
    private boolean activated;

    @ManyToOne
    @JoinColumn(name = "security_analysis_parameters_id", foreignKey = @ForeignKey(name = "security_analysis_parameters_id_fk"))
    private SecurityAnalysisParametersEntity securityAnalysisParameters;

    public ParametersContingencyListEntity(List<UUID> contingencyListIds, String description, boolean activated) {
        this.contingencyListIds = contingencyListIds;
        this.description = description;
        this.activated = activated;
    }
}
