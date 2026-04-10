package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ConnectivityResultEmbeddable;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ConnectivityResultDTO {
    private double disconnectedLoadActivePower;
    private double disconnectedGenerationActivePower;

    public static ConnectivityResultDTO toDto(ConnectivityResultEmbeddable connectivityResult) {
        return ConnectivityResultDTO.builder()
            .disconnectedLoadActivePower(connectivityResult.getDisconnectedLoadActivePower())
            .disconnectedGenerationActivePower(connectivityResult.getDisconnectedGenerationActivePower())
            .build();
    }
}
