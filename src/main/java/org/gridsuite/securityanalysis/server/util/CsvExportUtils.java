package org.gridsuite.securityanalysis.server.util;

import com.univocity.parsers.csv.CsvFormat;
import com.univocity.parsers.csv.CsvWriter;
import com.univocity.parsers.csv.CsvWriterSettings;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class CsvExportUtils {
    public static final char CSV_DELIMITER = ';';
    public static final char CSV_QUOTE_ESCAPE = '"';

    private CsvExportUtils() {
        throw new java.lang.UnsupportedOperationException("CsvExportUtils Utility class and cannot be instantiated");
    }

    public static StreamingResponseBody csvRowsToCsvStream(List<List<String>> csvRows) {
        return outputStream -> {
            try (Writer writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8)) {
                CsvWriterSettings settings = new CsvWriterSettings();
                setFormat(settings.getFormat());
                CsvWriter csvWriter = new CsvWriter(writer, settings);
                csvWriter.writeRows(csvRows);
            }
        };
    }

    private static void setFormat(CsvFormat format) {
        format.setLineSeparator(System.lineSeparator());
        format.setDelimiter(CSV_DELIMITER);
        format.setQuoteEscape(CSV_QUOTE_ESCAPE);
    }
}
