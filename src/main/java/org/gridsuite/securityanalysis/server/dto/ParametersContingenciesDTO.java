package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class ParametersContingenciesDTO {
    UUID id;
    String name;
}
