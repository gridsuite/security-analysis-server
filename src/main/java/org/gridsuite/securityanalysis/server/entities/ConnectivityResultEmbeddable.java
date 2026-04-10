package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.security.results.ConnectivityResult;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author Ghazwa Rehili <ghazwa.rehili at rte-france.com>
 */

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Embeddable
public class ConnectivityResultEmbeddable {
    @Column
    private double disconnectedLoadActivePower;

    @Column
    private double disconnectedGenerationActivePower;

    public static ConnectivityResultEmbeddable toEntity(ConnectivityResult connectivityResult) {
        return ConnectivityResultEmbeddable.builder()
                .disconnectedGenerationActivePower(connectivityResult.getDisconnectedGenerationActivePower())
                .disconnectedLoadActivePower(connectivityResult.getDisconnectedLoadActivePower())
                .build();
    }
}
