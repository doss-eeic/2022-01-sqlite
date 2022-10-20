#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_TABLES 3
#define N_KEYWORD 64

#define MAX_SIZE_SQL 512
#define MAX_SIZE_NAME 256

// User Table Column
#define MAX_SIZE_DATA_PUBLIC_KEY 47112
#define MAX_SIZE_KEYWORD_PUBLIC_KEY 47112
#define MAX_SIZE_USER_INSERT_SQL \
    MAX_SIZE_SQL + MAX_SIZE_DATA_PUBLIC_KEY + MAX_SIZE_KEYWORD_PUBLIC_KEY

// Group Table Column
#define MAX_SIZE_GROUP_INSERT_SQL MAX_SIZE_SQL

// CipherText Table Column
#define MAX_SIZE_DATA_CIPHER_TEXT 2900000
#define MAX_SIZE_KEYWORD_CIPHER_TEXT 2900000
#define MAX_SIZE_TRAPDOOR 22800
#define MAX_SIZE_CIPHER_TEXT_INSERT_SQL \
    MAX_SIZE_SQL + MAX_SIZE_DATA_CIPHER_TEXT + MAX_SIZE_KEYWORD_CIPHER_TEXT
#define MAX_SIZE_CIPHER_TEXT_SEARCH_SQL MAX_SIZE_SQL + MAX_SIZE_TRAPDOOR

#define MAX_SIZE_CHILDREN 100

#define PARENT_GROUP_IS_NULL -1

#define INITIALIZE(TYPE) ((TYPE *)malloc(sizeof(TYPE *)))
#define INITIALIZE_N(TYPE, N) ((TYPE *)malloc(sizeof(TYPE *) * N))

typedef struct {
    int user_id;
    char *data_public_key;
    char *keyword_public_key;
} UserTableRow;

UserTableRow *initializeUserTableRow();
void finalizeUserTableRow(UserTableRow *);
void debugUserTableRow(UserTableRow *);
void setUserTableRow(UserTableRow *, int, char *, char *);

typedef struct {
    int group_id;
    char *group_name;
    int parent_group_id;
} GroupTableRow;

GroupTableRow *initializeGroupTableRow();
GroupTableRow *initializeGroupTableRows(int);
void finalizeGroupTableRow(GroupTableRow *);
void debugGroupTableRow(GroupTableRow *);
void setGroupTableRow(GroupTableRow *, int, char *, int);

typedef struct {
    int data_id;
    int group_id;
    char *data_ct;
    char *keyword_ct;
} CipherTextTableRow;

CipherTextTableRow *initializeCipherTextTableRow();
void finalizeCipherTextTableRow(CipherTextTableRow *);
void debugCipherTextTableRow(CipherTextTableRow *);
void setCipherTextTableRow(CipherTextTableRow *, int, int, char *, char *);

int CreateTables(sqlite3 *);
UserTableRow *GetUser(sqlite3 *, int);  // use instead of GetPublicKeys
UserTableRow *AddUser(sqlite3 *, char *, char *);
GroupTableRow *GetGroup(sqlite3 *, int);  // use instead of GetParentGroupID
int SearchChildGroups(sqlite3 *, int, GroupTableRow *);
GroupTableRow *AddGroup(sqlite3 *, char *, int);
CipherTextTableRow *AddCipherText(sqlite3 *, int, char *, char *);
CipherTextTableRow *GetCipherText(sqlite3 *, int);
int SearchCipherTexts(sqlite3 *, int, char *, CipherTextTableRow *);
