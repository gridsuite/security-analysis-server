package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;

import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "contingency")
public class ContingencyEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private ResultEntity result;

    @ElementCollection
    private List<ContingencyElementEmbeddable> contingencyElements;
}
