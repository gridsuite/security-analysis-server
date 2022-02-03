package org.gridsuite.securityanalysis.server.repository;

import java.util.UUID;

import java.io.Serializable;

import javax.persistence.Embeddable;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;

import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author Laurent Garnier <laurent.garnier at rte-france.com>
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@EqualsAndHashCode
@Embeddable
public class LimitationViolationId  implements Serializable {

    private UUID resultUuid;

    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    private String contingencyId;

    private String subjectId;
}
