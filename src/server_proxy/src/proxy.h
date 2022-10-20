#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SQL_SIZE 1024
#define MAX_KEY_SIZE 1024
#define MAX_NAME_SIZE 256
#define MAX_CIPHERTEXT_SIZE 1024
#define MAX_CHILDREN_SIZE 100
#define N_TABLES 4
#define N_KEYWORD 128
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
