package org.gridsuite.securityanalysis.server.util;

import org.gridsuite.computation.ComputationException;
import com.univocity.parsers.csv.CsvFormat;
import com.univocity.parsers.csv.CsvWriter;
import com.univocity.parsers.csv.CsvWriterSettings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.gridsuite.computation.ComputationBusinessErrorCode.FILE_EXPORT_ERROR;

public final class CsvExportUtils {
    public static final char CSV_DELIMITER_FR = ';';
    public static final char CSV_DELIMITER_EN = ',';
    public static final char CSV_QUOTE_ESCAPE = '"';

    public static final String CSV_RESULT_FILE_NAME = "result.csv";

    private CsvExportUtils() {
        throw new UnsupportedOperationException("CsvExportUtils Utility class and cannot be instantiated");
    }

    public static byte[] csvRowsToZippedCsv(List<String> headers, String language, List<List<String>> csvRows) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            zipOutputStream.putNextEntry(new ZipEntry(CSV_RESULT_FILE_NAME));

            // adding BOM to the beginning of file to help excel in some versions to detect this is UTF-8 encoding bytes
            writeUTF8Bom(zipOutputStream);

            CsvWriterSettings settings = new CsvWriterSettings();
            setFormat(settings.getFormat(), language);
            CsvWriter csvWriter = new CsvWriter(zipOutputStream, StandardCharsets.UTF_8, settings);
            csvWriter.writeRow(headers);
            csvWriter.writeRows(csvRows);

            csvWriter.close();
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new ComputationException(FILE_EXPORT_ERROR, "Error occured during data csv export");
        }
    }

    private static void writeUTF8Bom(OutputStream outputStream) throws IOException {
        outputStream.write(0xef);
        outputStream.write(0xbb);
        outputStream.write(0xbf);
    }

    private static void setFormat(CsvFormat format, String language) {
        format.setLineSeparator(System.lineSeparator());
        format.setDelimiter(language != null && language.equals("fr") ? CSV_DELIMITER_FR : CSV_DELIMITER_EN);
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
