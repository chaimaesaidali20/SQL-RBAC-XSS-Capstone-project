#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define DB_FILE "security_app.db"
#define MAX_INPUT 256

typedef struct {
    int id;
    char username[64];
    char role[32];
}
User;

/* Simple HTML escape to mitigate XSS when displaying user-controlled content */
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

/* Basic input validation: ensure non-empty and reasonable length */
int validate_input(const char* input)
{
    if (input == NULL) return 0;
    size_t len = strlen(input);
    if (len == 0 || len >= MAX_INPUT) return 0;
    return 1;
}

/* Initialize database: users table and sample data */
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

    /* Insert sample users if not exists */
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

/* Secure authentication using prepared statements (prevents SQL injection) */
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

/* Role-based access control: only admin can perform admin actions */
int has_admin_access(const User* user)
{
    return strcmp(user->role, "admin") == 0;
}

/* Simulate storing a user comment and safely displaying it */
int store_comment(sqlite3* db, const char* username, const char* comment)
{
    const char* create_comments_sql =
        "CREATE TABLE IF NOT EXISTS comments ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL,"
        "comment TEXT NOT NULL"
        ");";

    int rc = sqlite3_exec(db, create_comments_sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to create comments table: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    const char* insert_sql =
        "INSERT INTO comments (username, comment) VALUES (?, ?);";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare insert comment: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, comment, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to insert comment: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    return 1;
}

int display_comments(sqlite3* db)
{
    const char* select_sql =
        "SELECT username, comment FROM comments;";

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare select comments: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    printf("\n--- Comments (HTML-escaped to prevent XSS) ---\n");
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        const unsigned char* username = sqlite3_column_text(stmt, 0);
        const unsigned char* comment = sqlite3_column_text(stmt, 1);

        char escaped[512];
        html_escape((const char*)comment, escaped, sizeof(escaped));

        printf("User: %s\n", username);
        printf("Comment: %s\n\n", escaped);
    }

    sqlite3_finalize(stmt);
    return 1;
}

int main(void)
{
    sqlite3* db = NULL;
    if (!init_db(&db))
    {
        fprintf(stderr, "Database initialization failed.\n");
        return EXIT_FAILURE;
    }

    char username[MAX_INPUT];
    char password[MAX_INPUT];

    printf("Secure Login System\n");
    printf("Username: ");
    if (!fgets(username, sizeof(username), stdin))
    {
        fprintf(stderr, "Failed to read username.\n");
        sqlite3_close(db);
        return EXIT_FAILURE;
    }
    username[strcspn(username, "\n")] = '\0';

    printf("Password: ");
    if (!fgets(password, sizeof(password), stdin))
    {
        fprintf(stderr, "Failed to read password.\n");
        sqlite3_close(db);
        return EXIT_FAILURE;
    }
    password[strcspn(password, "\n")] = '\0';

    if (!validate_input(username) || !validate_input(password))
    {
        fprintf(stderr, "Invalid input.\n");
        sqlite3_close(db);
        return EXIT_FAILURE;
    }

    User user;
    if (!authenticate_user(db, username, password, &user))
    {
        fprintf(stderr, "Authentication failed.\n");
        sqlite3_close(db);
        return EXIT_FAILURE;
    }

    printf("Welcome, %s! Your role is: %s\n", user.username, user.role);

    if (has_admin_access(&user))
    {
        printf("You have admin access. You can manage users or view all comments.\n");
    }
    else
    {
        printf("You are a regular user. You can post comments.\n");
    }

    /* Let user post a comment */
    char comment[MAX_INPUT];
    printf("Enter a comment (potentially containing HTML/JS): ");
    if (!fgets(comment, sizeof(comment), stdin))
    {
        fprintf(stderr, "Failed to read comment.\n");
        sqlite3_close(db);
        return EXIT_FAILURE;
    }
    comment[strcspn(comment, "\n")] = '\0';

    if (!validate_input(comment))
    {
        fprintf(stderr, "Invalid comment.\n");
        sqlite3_close(db);
        return EXIT_FAILURE;
    }

    if (!store_comment(db, user.username, comment))
    {
        fprintf(stderr, "Failed to store comment.\n");
        sqlite3_close(db);
        return EXIT_FAILURE;
    }

    /* Display comments with HTML escaping to mitigate XSS */
    display_comments(db);

    sqlite3_close(db);
    return EXIT_SUCCESS;
}
