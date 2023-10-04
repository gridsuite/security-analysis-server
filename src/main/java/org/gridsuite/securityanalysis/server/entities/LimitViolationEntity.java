package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import jakarta.persistence.*;

import java.util.UUID;

@MappedSuperclass
public abstract class LimitViolationEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne
    private ResultEntity result;

    private String subjectId;

    private String subjectName;

    @Column(name = "limitValue")
    private double limit;

    private String limitName;

    private int acceptableDuration;

    private float limitReduction;

    @Column(name = "offendingValue")
    private double value;

    @Enumerated(EnumType.STRING)
    private Branch.Side side;
}
