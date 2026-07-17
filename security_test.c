#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define DB_FILE "security_app.db"

typedef struct {
    int id;
    char username[64];
    char role[32];
}
User;

/* Forward declarations from main app (you can also move them to a shared header) */
int init_db(sqlite3** db);
int authenticate_user(sqlite3* db, const char* username, const char* password, User* out_user);
void html_escape(const char* input, char* output, size_t out_size);

/* Minimal reimplementation to keep this file self-contained */
int init_db(sqlite3** db)
{
    int rc = sqlite3_open(DB_FILE, db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(*db));
        return 0;
    }

    const char* create_table_sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "password TEXT NOT NULL,"
        "role TEXT NOT NULL"
        ");";

    rc = sqlite3_exec(*db, create_table_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to create table: %s\n", sqlite3_errmsg(*db));
        return 0;
    }

    const char* insert_sql =
        "INSERT OR IGNORE INTO users (username, password, role) VALUES "
        "('admin', 'admin123', 'admin'),"
        "('alice', 'alice123', 'user');";

    rc = sqlite3_exec(*db, insert_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to insert sample users: %s\n", sqlite3_errmsg(*db));
        return 0;
    }

    return 1;
}

int authenticate_user(sqlite3* db, const char* username, const char* password, User* out_user)
{
    const char* sql =
        "SELECT id, username, role FROM users WHERE username = ? AND password = ?;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
    {
        out_user->id = sqlite3_column_int(stmt, 0);
        snprintf(out_user->username, sizeof(out_user->username), "%s",
                 sqlite3_column_text(stmt, 1));
        snprintf(out_user->role, sizeof(out_user->role), "%s",
                 sqlite3_column_text(stmt, 2));
        sqlite3_finalize(stmt);
        return 1;
    }
    else
    {
        sqlite3_finalize(stmt);
        return 0;
    }
}

void html_escape(const char* input, char* output, size_t out_size)
{
    size_t j = 0;
    for (size_t i = 0; input[i] != '\0' && j + 6 < out_size; i++)
    {
        char c = input[i];
        if (c == '<')
        {
            j += snprintf(output + j, out_size - j, "&lt;");
        }
        else if (c == '>')
        {
            j += snprintf(output + j, out_size - j, "&gt;");
        }
        else if (c == '&')
        {
            j += snprintf(output + j, out_size - j, "&amp;");
        }
        else if (c == '"')
        {
            j += snprintf(output + j, out_size - j, "&quot;");
        }
        else if (c == '\'')
        {
            j += snprintf(output + j, out_size - j, "&#39;");
        }
        else
        {
            output[j++] = c;
        }
    }
    output[j] = '\0';
}

/* Test: SQL injection attempt should fail */
void test_sql_injection(sqlite3* db)
{
    User user;
    const char* malicious_username = "admin' OR '1'='1";
    const char* malicious_password = "anything";

    int result = authenticate_user(db, malicious_username, malicious_password, &user);
    if (result == 0)
    {
        printf("[PASS] SQL injection attempt did NOT bypass authentication.\n");
    }
    else
    {
        printf("[FAIL] SQL injection attempt succeeded (vulnerable).\n");
    }
}

/* Test: XSS payload should be escaped */
void test_xss_escape(void)
{
    const char* payload = "<script>alert('XSS');</script>";
    char escaped[256];
    html_escape(payload, escaped, sizeof(escaped));

    if (strstr(escaped, "<script>") == NULL &&
        strstr(escaped, "</script>") == NULL &&
        strstr(escaped, "alert('XSS')") == NULL)
    {
        printf("[PASS] XSS payload was escaped: %s\n", escaped);
    }
    else
    {
        printf("[FAIL] XSS payload was not properly escaped: %s\n", escaped);
    }
}

int main(void)
{
    sqlite3* db = NULL;
    if (!init_db(&db))
    {
        fprintf(stderr, "Database initialization failed.\n");
        return EXIT_FAILURE;
    }

    printf("Running security tests...\n");
    test_sql_injection(db);
    test_xss_escape();

    sqlite3_close(db);
    return EXIT_SUCCESS;
}
