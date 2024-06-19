package org.gridsuite.securityanalysis.server.util;

import com.powsybl.commons.report.ReportNode;
import org.apache.commons.text.StringSubstitutor;
import org.gridsuite.securityanalysis.server.computation.service.ReportService;
import org.mockito.ArgumentCaptor;

import java.util.Iterator;
import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.verify;

public final class TestUtils {

    private TestUtils() {
    }

    public static void assertLogNthMessage(String expectedMessage, String reportKey, ReportService reportService, int rank) {
        ArgumentCaptor<ReportNode> reporterCaptor = ArgumentCaptor.forClass(ReportNode.class);
        verify(reportService, atLeast(1)).sendReport(any(UUID.class), reporterCaptor.capture());
        assertNotNull(reporterCaptor.getValue());
        Optional<String> message = getMessageFromReporter(reportKey, reporterCaptor.getValue(), rank);
        assertTrue(message.isPresent());
        assertEquals(expectedMessage, message.get().trim());
    }

    public static void assertLogMessage(String expectedMessage, String reportKey, ReportService reportService) {
        assertLogNthMessage(expectedMessage, reportKey, reportService, 1);
    }

    private static Optional<String> getMessageFromReporter(String reportKey, ReportNode reporterModel, int rank) {
        Optional<String> message = Optional.empty();

        Iterator<ReportNode> reportsIterator = reporterModel.getChildren().iterator();
        int nbTimes = 0;
        while (message.isEmpty() && reportsIterator.hasNext()) {
            ReportNode report = reportsIterator.next();
            if (report.getMessageKey().equals(reportKey)) {
                nbTimes++;
                if (nbTimes == rank) {
                    message = Optional.of(formatReportMessage(report, reporterModel));
                }
            }
        }

        Iterator<ReportNode> reportersIterator = reporterModel.getChildren().iterator();
        while (message.isEmpty() && reportersIterator.hasNext()) {
            message = getMessageFromReporter(reportKey, reportersIterator.next(), rank);
        }

        return message;
    }

    private static String formatReportMessage(ReportNode report, ReportNode reporterModel) {
        return new StringSubstitutor(reporterModel.getValues()).replace(new StringSubstitutor(report.getValues()).replace(report.getMessageTemplate()));
    }
}
