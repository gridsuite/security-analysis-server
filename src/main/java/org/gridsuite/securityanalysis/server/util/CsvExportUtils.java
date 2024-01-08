package org.gridsuite.securityanalysis.server.util;

import com.univocity.parsers.csv.CsvFormat;
import com.univocity.parsers.csv.CsvWriter;
import com.univocity.parsers.csv.CsvWriterSettings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class CsvExportUtils {
    public static final char CSV_DELIMITER = ';';
    public static final char CSV_QUOTE_ESCAPE = '"';

    private CsvExportUtils() {
        throw new java.lang.UnsupportedOperationException("CsvExportUtils Utility class and cannot be instantiated");
    }

    public static byte[] csvRowsToCsvStream(List<String> headers, List<List<String>> csvRows) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            zipOutputStream.putNextEntry(new ZipEntry("result.csv"));

            CsvWriterSettings settings = new CsvWriterSettings();
            setFormat(settings.getFormat());
            CsvWriter csvWriter = new CsvWriter(zipOutputStream, settings);
            csvWriter.writeRow(headers);
            csvWriter.writeRows(csvRows);

            csvWriter.close();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void setFormat(CsvFormat format) {
        format.setLineSeparator(System.lineSeparator());
        format.setDelimiter(CSV_DELIMITER);
        format.setQuoteEscape(CSV_QUOTE_ESCAPE);
    }
}
