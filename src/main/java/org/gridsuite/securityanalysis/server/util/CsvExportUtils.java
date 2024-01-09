package org.gridsuite.securityanalysis.server.util;

import com.univocity.parsers.csv.CsvFormat;
import com.univocity.parsers.csv.CsvWriter;
import com.univocity.parsers.csv.CsvWriterSettings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class CsvExportUtils {
    public static final char CSV_DELIMITER = ';';
    public static final char CSV_QUOTE_ESCAPE = '"';

    public static final String CSV_RESULT_FILE_NAME = "result.csv";

    private CsvExportUtils() {
        throw new java.lang.UnsupportedOperationException("CsvExportUtils Utility class and cannot be instantiated");
    }

    public static byte[] csvRowsToCsvStream(List<String> headers, List<List<String>> csvRows) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            zipOutputStream.putNextEntry(new ZipEntry(CSV_RESULT_FILE_NAME));

            CsvWriterSettings settings = new CsvWriterSettings();
            setFormat(settings.getFormat());
            CsvWriter csvWriter = new CsvWriter(zipOutputStream, settings);
            csvWriter.writeRow(headers);
            csvWriter.writeRows(csvRows);

            csvWriter.close();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new SecurityAnalysisException(SecurityAnalysisException.Type.FILE_EXPORT_ERROR);
        }
    }

    private static void setFormat(CsvFormat format) {
        format.setLineSeparator(System.lineSeparator());
        format.setDelimiter(CSV_DELIMITER);
        format.setQuoteEscape(CSV_QUOTE_ESCAPE);
    }

    public static String replaceNullWithEmptyString(Object input) {
        return input == null ? "" : input.toString();
    }

    public static String translate(String valueToTranslate, Map<String, String> translations) {
        if (translations == null) {
            return valueToTranslate;
        }
        String translatedValue = translations.get(valueToTranslate);
        // if value to translate or translate value is null, we keep original value (null or untranslated value)
        if (valueToTranslate == null || translatedValue == null) {
            return valueToTranslate;
        }
        return translatedValue;
    }
}
