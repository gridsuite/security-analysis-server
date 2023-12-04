package org.gridsuite.securityanalysis.server.util;

import static com.vladmihalcea.sql.SQLStatementCountValidator.*;
import static com.vladmihalcea.sql.SQLStatementCountValidator.assertDeleteCount;

public final class DatabaseQueryUtils {

    private DatabaseQueryUtils() {
        throw new IllegalStateException("Not implemented exception");
    }

    public static void assertRequestsCount(long select, long insert, long update, long delete) {
        assertSelectCount(select);
        assertInsertCount(insert);
        assertUpdateCount(update);
        assertDeleteCount(delete);
    }
}
