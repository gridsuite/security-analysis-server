package org.gridsuite.securityanalysis.server.service;

import com.vladmihalcea.sql.SQLStatementCountValidator;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

import static com.vladmihalcea.sql.SQLStatementCountValidator.*;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.RESULT;

/**
 * @author Florent MILLOT <florent.millot@rte-france.com>
 */
@SpringBootTest
class SecurityAnalysisResultServiceTest {

    @Autowired
    SecurityAnalysisResultService securityAnalysisResultService;

    @Test
    void deleteResultPerfTest() {
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(resultUuid, RESULT, SecurityAnalysisStatus.CONVERGED);
        SQLStatementCountValidator.reset();

        securityAnalysisResultService.delete(resultUuid);

        // 5 manual deletes + the list of ContingencyElementEmbeddable inside ContingencyEntity
        assertDeleteCount(6);
    }
}