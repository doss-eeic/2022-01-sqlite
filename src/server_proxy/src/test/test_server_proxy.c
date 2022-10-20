#include "../proxy.h"

#define DBFILE "./sommelier.db"

int test_create_tables(sqlite3 *);
int test_get_user(sqlite3 *);
int test_get_group(sqlite3 *);
int test_search_child_groups(sqlite3 *);
int test_get_cipher_text(sqlite3 *);
int test_search_cipher_text(sqlite3 *);

int main(void)
{
    sqlite3 *db = NULL;
    int err = sqlite3_open(DBFILE, &db);
    if (err) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return (1);
    }
    printf("create db - %s\n", DBFILE);

    test_create_tables(db);
    test_get_user(db);
    test_get_group(db);
    test_search_child_groups(db);
    test_get_cipher_text(db);

    sqlite3_close(db);

    return 0;
}

// === test proxy implements ===

int test_create_tables(sqlite3 *db) { CreateTables(db); }

int test_get_user(sqlite3 *db)
{
    printf("test_get_user: row1 and row2 must have same field.\n");

    UserTableRow *row1 = AddUser(db, "test_pkd", "test_pwd");

    UserTableRow *row2 = GetUser(db, row1->user_id);

    printf("row1: ");
    debugUserTableRow(row1);

    printf("row2: ");
    debugUserTableRow(row2);

    finalizeUserTableRow(row1);
    finalizeUserTableRow(row2);

    return 0;
}

int test_get_group(sqlite3 *db)
{
    printf("test_get_group: row1 and row2 must have same field.\n");

    GroupTableRow *parent_group = AddGroup(db, "parent", -1);

    GroupTableRow *row1 = AddGroup(db, "test_group", parent_group->group_id);

    GroupTableRow *row2 = GetGroup(db, row1->group_id);

    printf("row1: ");
    debugGroupTableRow(row1);

    printf("row2: ");
    debugGroupTableRow(row2);

    finalizeGroupTableRow(parent_group);
    finalizeGroupTableRow(row1);
    finalizeGroupTableRow(row2);

    return 0;
}

int test_search_child_groups(sqlite3 *db)
{
    printf(
        "test_search_child_groups: hit 4 groups and they have same "
        "parent_id.\n");

    GroupTableRow *parent_group = AddGroup(db, "parent", -1);

    GroupTableRow *child1 = AddGroup(db, "child1", parent_group->group_id);
    GroupTableRow *child2 = AddGroup(db, "child2", parent_group->group_id);
    GroupTableRow *child3 = AddGroup(db, "child3", parent_group->group_id);
    GroupTableRow *child4 = AddGroup(db, "child4", parent_group->group_id);

    GroupTableRow *children = initializeGroupTableRows(MAX_SIZE_CHILDREN);
    int n_children = SearchChildGroups(db, parent_group->group_id, children);

    printf("n_children: %d\n", n_children);

    for (int i = 0; i < n_children; i++) {
        debugGroupTableRow(&children[i]);
    }

    finalizeGroupTableRow(parent_group);
    finalizeGroupTableRow(child1);
    finalizeGroupTableRow(child2);
    finalizeGroupTableRow(child3);
    finalizeGroupTableRow(child4);

    return 0;
}

int test_get_cipher_text(sqlite3 *db)
{
    printf("test_get_group: row1 and row2 must have same field.\n");

    GroupTableRow *group = AddGroup(db, "test_group", -1);

    CipherTextTableRow *row1 =
        AddCipherText(db, group->group_id, "test_data", "test_keyword");

    CipherTextTableRow *row2 = GetCipherText(db, row1->data_id);

    printf("row1: ");
    debugCipherTextTableRow(row1);

    printf("row2: ");
    debugCipherTextTableRow(row2);

    finalizeGroupTableRow(group);
    finalizeCipherTextTableRow(row1);
    finalizeCipherTextTableRow(row2);

    return 0;
}

int test_search_cipher_text(sqlite3 *db)
{
    // TODO: Implement Test.
}
