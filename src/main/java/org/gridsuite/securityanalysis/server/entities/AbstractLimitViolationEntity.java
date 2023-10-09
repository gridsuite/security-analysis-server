package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@NoArgsConstructor
@Getter
@MappedSuperclass
public abstract class AbstractLimitViolationEntity {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne
    private ConstraintEntity constraint;

    private String subjectName;

    @Column(name = "limitValue")
    private double limit;

    private String limitName;

    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    private int acceptableDuration;

    private float limitReduction;

    @Column(name = "offendingValue")
    private double value;

    @Enumerated(EnumType.STRING)
    private Branch.Side side;

    public AbstractLimitViolationEntity(ConstraintEntity constraint, String subjectName, double limit, String limitName, LimitViolationType limitType, int acceptableDuration, float limitReduction, double value, Branch.Side side) {
        this.constraint = constraint;
        this.subjectName = subjectName;
        this.limit = limit;
        this.limitName = limitName;
        this.limitType = limitType;
        this.acceptableDuration = acceptableDuration;
        this.limitReduction = limitReduction;
        this.value = value;
        this.side = side;
    }
}
