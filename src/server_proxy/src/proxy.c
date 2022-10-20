#include "proxy.h"

#define DEBUG 0

// === proxy interface ===

int CreateTables(sqlite3 *db)
{
    // TODO: already exists対策

    int n_tables = N_TABLES;

    const char sql[N_TABLES][MAX_SIZE_SQL] = {
        "CREATE TABLE user_table (\
            UserID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\
            DataPublicKey TEXT NOT NULL,\
            KeywordPublicKey TEXT NOT NULL\
        );",  // (1) create user table
        "CREATE TABLE group_table (\
            GroupID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\
            GroupName TEXT NOT NULL,\
            ParentGroupID INTEGER NULL,\
            CONSTRAINT pgid_is_gid FOREIGN KEY (ParentGroupID) REFERENCES group_table(GroupID)\
        );",  // (2) create group table
        "CREATE TABLE ciphertext_table(\
            DataID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,\
            GroupID INTEGER NOT NULL,\
            DataCT TEXT NOT NULL,\
            KeywordCT TEXT NOT NULL,\
            CONSTRAINT gid_in_gtable FOREIGN KEY (GroupID) REFERENCES group_table(GroupID)\
        );"   // (3) create ciphertext table
    };

    int rc;
    char *zErrMsg = 0;

    for (int i = 0; i < n_tables; i++) {
        if (DEBUG) {
            printf("    sql - %s\n", sql[i]);
        }

        rc = sqlite3_exec(db, sql[i], 0, 0, &zErrMsg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", zErrMsg);
            sqlite3_free(zErrMsg);
        }
    }

    return 0;
}

UserTableRow *AddUser(sqlite3 *db, char *pkd, char *pkw)
{
    char sql[MAX_SIZE_USER_INSERT_SQL] = "";
    sprintf(sql,
            "INSERT INTO user_table (DataPublicKey, KeywordPublicKey) values "
            "('%s', '%s');",
            pkd, pkw);

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    int rowid = (int)sqlite3_last_insert_rowid(db);
    if (DEBUG) {
        printf("    last-row-id - %d\n", rowid);
    }

    UserTableRow *row = initializeUserTableRow();
    setUserTableRow(row, rowid, pkd, pkw);

    return row;
}

GroupTableRow *AddGroup(sqlite3 *db, char *name, int pid)
{
    char sql[MAX_SIZE_GROUP_INSERT_SQL] = "";
    char pid_s[256] = "NULL";
    if (pid >= 1) {
        sprintf(pid_s, "%d", pid);
    }
    sprintf(sql,
            "INSERT INTO group_table (GroupName, ParentGroupId) values ('%s', "
            "%s);",
            name, pid_s);

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    int rowid = (int)sqlite3_last_insert_rowid(db);
    if (DEBUG) {
        printf("    last-row-id - %d\n", rowid);
    }

    GroupTableRow *row = initializeGroupTableRow();
    setGroupTableRow(row, rowid, name, pid);

    return row;
}

CipherTextTableRow *AddCipherText(sqlite3 *db, int group_id, char *data_ct,
                                  char *keyword_ct)
{
    char sql[MAX_SIZE_CIPHER_TEXT_INSERT_SQL] = "";
    sprintf(sql,
            "INSERT INTO ciphertext_table (GroupID, DataCT, KeywordCT) values "
            "(%d, '%s', '%s');",
            group_id, data_ct, keyword_ct);

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    int rowid = (int)sqlite3_last_insert_rowid(db);
    if (DEBUG) {
        printf("    last-row-id - %d\n", rowid);
    }

    CipherTextTableRow *row = initializeCipherTextTableRow();
    setCipherTextTableRow(row, rowid, group_id, data_ct, keyword_ct);

    return row;
}

static int callback_get_user(void *row, int argc, char **argv, char **azColName)
{
    if (DEBUG) {
        printf("    select - id: %s, pkd: %s, pkw: %s\n", argv[0], argv[1],
               argv[2]);
    }

    setUserTableRow((UserTableRow *)row, atoi(argv[0]), argv[1], argv[2]);

    return 0;
}

UserTableRow *GetUser(sqlite3 *db, int user_id)
{
    char sql[MAX_SIZE_SQL] = "";
    sprintf(sql,
            "SELECT UserID, DataPublicKey, KeywordPublicKey FROM user_table "
            "WHERE UserID=%d;",
            user_id);

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    UserTableRow *row = initializeUserTableRow();

    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, callback_get_user, (void *)row, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    return row;
}

static int callback_get_group(void *row, int argc, char **argv,
                              char **azColName)
{
    if (DEBUG) {
        printf("    select - id: %s, name: %s, parent_id: %s\n", argv[0],
               argv[1], argv[2]);
    }

    // ParentGroupID is nullable.
    // Return row that is ParentGroupID = -1, if it is null.
    setGroupTableRow((GroupTableRow *)row, atoi(argv[0]), argv[1],
                     argv[2] ? atoi(argv[2]) : PARENT_GROUP_IS_NULL);

    return 0;
}

GroupTableRow *GetGroup(sqlite3 *db, int group_id)
{
    char sql[MAX_SIZE_SQL] = "";
    sprintf(sql,
            "SELECT GroupID, GroupName, ParentGroupID FROM group_table "
            "WHERE GroupID=%d;",
            group_id);

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    GroupTableRow *row = initializeGroupTableRow();

    char *zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, callback_get_group, (void *)row, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    return row;
}

int SearchChildGroups(sqlite3 *db, int parent_group_id, GroupTableRow *rows)
{
    char sql[MAX_SIZE_SQL] = "";
    sprintf(sql,
            "SELECT GroupID, GroupName, ParentGroupID FROM group_table WHERE "
            "ParentGroupID=%d;",
            parent_group_id);

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    sqlite3_stmt *stmt = NULL;
    int return_value = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (return_value) {
        printf("Selecting data from DB Failed (err_code=%d)\n", return_value);
        return -1;
    }

    int i = 0;

    while (1) {
        return_value = sqlite3_step(stmt);

        if (return_value == SQLITE_ROW) {
            int id = (int)sqlite3_column_int(stmt, 0);
            char *name = (char *)sqlite3_column_text(stmt, 1);
            int pid = (int)sqlite3_column_int(stmt, 2);

            setGroupTableRow(&rows[i], id, name, pid);
        }
        else if (return_value == SQLITE_DONE) {
            break;
        }
        else {
            sqlite3_finalize(stmt);
            printf("Some error encountered\n");
            return -1;
        }

        i++;
    }

    sqlite3_finalize(stmt);

    return i;
}

static int callback_get_cipher_text(void *row, int argc, char **argv,
                                    char **azColName)
{
    if (DEBUG) {
        printf("    select - id: %s, group_id: %s data: %s, keyword: %s\n",
               argv[0], argv[1], argv[2], argv[3]);
    }

    // ParentGroupID is nullable.
    // Return row that is ParentGroupID = -1, if it is null.
    setCipherTextTableRow((CipherTextTableRow *)row, atoi(argv[0]),
                          atoi(argv[1]), argv[2], argv[3]);

    return 0;
}

CipherTextTableRow *GetCipherText(sqlite3 *db, int ct_id)
{
    char sql[MAX_SIZE_SQL] = "";
    sprintf(sql,
            "SELECT DataID, GroupID, DataCT, KeywordCT FROM ciphertext_table "
            "WHERE DataID=%d;",
            ct_id);

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    CipherTextTableRow *row = initializeCipherTextTableRow();

    char *zErrMsg = 0;
    int rc =
        sqlite3_exec(db, sql, callback_get_cipher_text, (void *)row, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }

    return row;
}

int SearchCipherTexts(sqlite3 *db, int group_id, char *td,
                      CipherTextTableRow *rows)
{
    char sql[MAX_SIZE_CIPHER_TEXT_SEARCH_SQL] = "";
    sprintf(sql,
            "SELECT DataID, GroupID, DataCT, KeywordCT FROM ciphertext_table "
            "WHERE GroupID=%d and test(DataCT, '%s')=1;",
            group_id, td);  // TODO; check SQL execution in SommlierDB

    if (DEBUG) {
        printf("    sql - %s\n", sql);
    }

    sqlite3_stmt *stmt = NULL;
    int return_value = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (return_value) {
        printf("Selecting data from DB Failed (err_code=%d)\n", return_value);
        return -1;
    }

    int i = 0;

    while (1) {
        return_value = sqlite3_step(stmt);

        if (return_value == SQLITE_ROW) {
            int id = (int)sqlite3_column_int(stmt, 0);
            int gid = (int)sqlite3_column_int(stmt, 1);
            char *data_ct = (char *)sqlite3_column_text(stmt, 2);
            char *keyword_ct = (char *)sqlite3_column_text(stmt, 3);

            setCipherTextTableRow(&rows[i], id, gid, data_ct, keyword_ct);
        }
        else if (return_value == SQLITE_DONE) {
            break;
        }
        else {
            sqlite3_finalize(stmt);
            printf("Some error encountered\n");
            return -1;
        }

        i++;
    }

    sqlite3_finalize(stmt);

    return i;
}

// === utility function for row data ===

UserTableRow *initializeUserTableRow()
{
    UserTableRow *row = INITIALIZE(UserTableRow);
    row->data_public_key =
        (char *)malloc(sizeof(char) * MAX_SIZE_DATA_PUBLIC_KEY);
    row->keyword_public_key =
        (char *)malloc(sizeof(char) * MAX_SIZE_KEYWORD_PUBLIC_KEY);

    return row;
}

void finalizeUserTableRow(UserTableRow *row)
{
    free(row->data_public_key);
    free(row->keyword_public_key);
    free(row);
}

void debugUserTableRow(UserTableRow *row)
{
    printf("<user id: %d, pkd: %s, pkw: %s>\n", row->user_id,
           row->data_public_key, row->keyword_public_key);
    fflush(stdout);
}

void setUserTableRow(UserTableRow *row, int id, char *pkd, char *pkw)
{
    row->user_id = id;
    strcpy(row->data_public_key, pkd);
    strcpy(row->keyword_public_key, pkw);
}

GroupTableRow *initializeGroupTableRow()
{
    GroupTableRow *row = INITIALIZE(GroupTableRow);
    row->group_name = (char *)malloc(sizeof(char) * MAX_SIZE_NAME);
    return row;
}

GroupTableRow *initializeGroupTableRows(int n_rows)
{
    GroupTableRow *rows = INITIALIZE_N(GroupTableRow, n_rows);
    for (int i = 0; i < n_rows; i++) {
        (&rows[i])->group_name = (char *)malloc(sizeof(char) * MAX_SIZE_NAME);
    }
    return rows;
}

void finalizeGroupTableRow(GroupTableRow *row)
{
    free(row->group_name);
    free(row);
}

void debugGroupTableRow(GroupTableRow *row)
{
    printf("<group id: %d, name: %s, parent_id: %d>\n", row->group_id,
           row->group_name, row->parent_group_id);
    fflush(stdout);
}

void setGroupTableRow(GroupTableRow *row, int id, char *name, int pid)
{
    row->group_id = id;
    strcpy(row->group_name, name);
    row->parent_group_id = pid;
}

CipherTextTableRow *initializeCipherTextTableRow()
{
    CipherTextTableRow *row = INITIALIZE(CipherTextTableRow);
    row->data_ct = (char *)malloc(sizeof(char) * MAX_SIZE_DATA_CIPHER_TEXT);
    row->keyword_ct =
        (char *)malloc(sizeof(char) * MAX_SIZE_KEYWORD_CIPHER_TEXT);
    return row;
}

void finalizeCipherTextTableRow(CipherTextTableRow *row)
{
    free(row->data_ct);
    free(row->keyword_ct);
    free(row);
}

void debugCipherTextTableRow(CipherTextTableRow *row)
{
    printf("<ciphertext id: %d, group_id: %d, data: %s, keyword: %s>\n",
           row->data_id, row->group_id, row->data_ct, row->keyword_ct);
    fflush(stdout);
}

void setCipherTextTableRow(CipherTextTableRow *row, int id, int gid, char *data,
                           char *keyword)
{
    row->data_id = id;
    row->group_id = gid;
    strcpy(row->data_ct, data);
    strcpy(row->keyword_ct, keyword);
}
