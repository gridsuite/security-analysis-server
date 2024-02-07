package org.gridsuite.securityanalysis.server.util;

import com.univocity.parsers.csv.CsvFormat;
import com.univocity.parsers.csv.CsvWriter;
import com.univocity.parsers.csv.CsvWriterSettings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class CsvExportUtils {
    public static final char CSV_DELIMITER = ',';
    public static final char CSV_QUOTE_ESCAPE = '"';

    public static final String CSV_RESULT_FILE_NAME = "result.csv";

    private CsvExportUtils() {
        throw new UnsupportedOperationException("CsvExportUtils Utility class and cannot be instantiated");
    }

    public static byte[] csvRowsToZippedCsv(List<String> headers, List<List<String>> csvRows) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            zipOutputStream.putNextEntry(new ZipEntry(CSV_RESULT_FILE_NAME));

            writeUTF8Bom(zipOutputStream);

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

    private static void writeUTF8Bom (OutputStream outputStream) throws IOException {
        outputStream.write(0xef); // emits 0xef
        outputStream.write(0xbb); // emits 0xbb
        outputStream.write(0xbf); // emits 0xbf
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
        // if value to translate or translations is null, we keep original value (null or no translation values)
        if (valueToTranslate == null || translations == null) {
            return valueToTranslate;
        }
        // if translated value is null, we keep original value (untranslated value)
        return translations.getOrDefault(valueToTranslate, valueToTranslate);
    }
}
