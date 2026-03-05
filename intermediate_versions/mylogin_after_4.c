/*
 * mylogin_after_4.c — Preparatory Assignment 4
 *
 * Builds on mylogin_after_3.c (basic login) by adding:
 *   1. pw_failed counter: tracks consecutive failed login attempts.
 *      - Incremented on each wrong password.
 *      - Reset to 0 on successful login.
 *   2. Account lockout: if pw_failed > 3, the account is locked.
 *      - The admin can unlock it by editing the pwfile (set failed back to 0).
 *   3. pw_age counter: tracks number of successful logins.
 *      - Incremented on each successful login.
 *      - If pw_age > 5, warn the user to change their password.
 *   Uses pwdb_update_user() to persist changes to the pwfile.
 *
 * Compile: gcc -o mylogin mylogin_after_4.c pwdblib.c -lcrypt
 */

#define _XOPEN_SOURCE /* Required for crypt() to be declared in <unistd.h>/<crypt.h> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* getpass() — reads password without echoing to terminal */
#include <crypt.h>   /* crypt()   — one-way hash function for password verification */
#include "pwdblib.h" /* pwdb_getpwnam(), pwdb_update_user(), struct pwdb_passwd, etc. */

/* Maximum length of a username (including the null terminator '\0'). */
#define USERNAME_SIZE (32)

/* After this many consecutive failed attempts, the account is locked. */
#define MAX_FAILED_ATTEMPTS (3)

/* After this many successful logins, the user is warned to change their password. */
#define PASSWORD_AGE_LIMIT (5)

/*
 * read_username — Prompts "login: " and reads the username from stdin.
 *
 * Parameters:
 *   username — a pointer to a char array (buffer) of at least USERNAME_SIZE bytes.
 *              The function writes the entered username into this buffer.
 *              In C, arrays decay to pointers when passed to functions,
 *              so the caller's buffer is modified directly.
 */
void read_username(char *username)
{
    printf("login: ");

    /* fgets reads at most USERNAME_SIZE-1 chars and always null-terminates.
     * It also includes the newline '\n' if there's room, so we strip it below. */
    fgets(username, USERNAME_SIZE, stdin);

    /* strlen() returns the number of characters before the '\0' terminator.
     * The last character is the '\n' from pressing Enter — overwrite it with '\0'. */
    username[strlen(username) - 1] = '\0';
}

/*
 * verify_password — Checks if the given plaintext password matches the stored hash.
 *
 * Parameters:
 *   password    — pointer to the plaintext password string (from getpass).
 *   stored_hash — pointer to the stored hash string from the pwfile
 *                 (format: 2-char salt + hashed password, e.g. "0BWGsAnLYCtBU").
 *
 * Returns:
 *   1 if the password matches, 0 otherwise.
 *
 * How it works:
 *   1. The first 2 characters of stored_hash are the "salt" — a value that was
 *      used when the password was originally hashed, to prevent identical passwords
 *      from producing identical hashes.
 *   2. crypt(password, salt) hashes the plaintext password with that same salt,
 *      producing a string in the same format as stored_hash.
 *   3. strcmp compares the two strings: returns 0 if they are identical.
 */
int verify_password(const char *password, const char *stored_hash)
{
    /* Salt buffer: 2 characters + 1 null terminator = 3 bytes.
     * In C, strings must always end with '\0', so a 2-char salt needs a 3-byte array. */
    char salt[3];

    /* strncpy copies at most 2 bytes from stored_hash into salt.
     * Unlike strcpy, strncpy limits how many characters are copied,
     * preventing buffer overflow if stored_hash were unexpectedly short. */
    strncpy(salt, stored_hash, 2);
    salt[2] = '\0'; /* Ensure null termination — strncpy does NOT guarantee this. */

    /* crypt() returns a pointer to a static internal buffer containing the hash.
     * WARNING: this buffer is overwritten on every call to crypt(), so we must
     * use the result immediately (or copy it) before calling crypt() again. */
    char *hashed_input = crypt(password, salt);

    /* strcmp returns 0 when the two strings are identical.
     * We convert this to a boolean: (0 == 0) is 1 (true), anything else is 0 (false). */
    return (strcmp(hashed_input, stored_hash) == 0);
}

/*
 * is_account_locked — Checks whether the account has been locked due to too many
 *                     consecutive failed login attempts.
 *
 * Parameters:
 *   p — pointer to the user's pwdb_passwd struct (read from the pwfile).
 *       'const' means this function promises not to modify the struct.
 *
 * Returns:
 *   1 if the account is locked, 0 otherwise.
 */
int is_account_locked(const struct pwdb_passwd *p)
{
    return (p->pw_failed > MAX_FAILED_ATTEMPTS);
}

/*
 * handle_failed_login — Called when a password check fails.
 *   Increments the pw_failed counter and writes it back to the pwfile.
 *
 * Parameters:
 *   p — pointer to the user's struct. Can be NULL if user was not found.
 *       If NULL, we skip the update (nothing to track for non-existent users).
 */
void handle_failed_login(struct pwdb_passwd *p)
{
    if (p != NULL)
    {
        p->pw_failed++;

        /* pwdb_update_user writes the modified struct back to the pwfile.
         * It finds the matching user entry by pw_name and overwrites the entire line. */
        if (pwdb_update_user(p) != 0)
        {
            printf("Error updating user database.\n");
        }
    }
    printf("Unknown user or incorrect password.\n");
}

/*
 * handle_successful_login — Called when a password check succeeds.
 *   Resets pw_failed to 0, increments pw_age, writes back to pwfile,
 *   and warns the user if their password is old.
 *
 * Parameters:
 *   p — pointer to the user's struct (guaranteed non-NULL here).
 */
void handle_successful_login(struct pwdb_passwd *p)
{
    p->pw_failed = 0;
    p->pw_age++;

    /* Persist the changes to the pwfile. */
    if (pwdb_update_user(p) != 0)
    {
        printf("Error updating user database.\n");
    }

    /* Warn user if their password is old (many successful logins without changing it). */
    if (p->pw_age > PASSWORD_AGE_LIMIT)
    {
        printf("Warning: Your password is old (%d logins). Please change it!\n", p->pw_age);
    }

    printf("User authenticated successfully.\n");
}

int main(int argc, char **argv)
{
    /* Stack-allocated buffer for the username.
     * In C, local arrays like this live on the stack and are automatically
     * freed when the function returns — no need for malloc/free. */
    char username[USERNAME_SIZE];

    /* Main login loop: keeps prompting until a successful login. */
    while (1)
    {
        read_username(username);

        /* pwdb_getpwnam searches the local pwfile for a user with this name.
         * Returns a pointer to a dynamically allocated (malloc'd) struct, or
         * NULL if the user was not found (or on error).
         * The '*' in 'struct pwdb_passwd *p' means p is a POINTER — it holds
         * the memory address of the struct, not the struct itself. */
        struct pwdb_passwd *p = pwdb_getpwnam(username);

        /* getpass() prints "Password: " to the terminal and reads input WITHOUT
         * echoing characters — essential for password security. It returns a
         * pointer to a static buffer containing the entered password.
         * We always ask for the password even if the user doesn't exist,
         * to avoid revealing whether a username is valid (timing attack prevention). */
        char *password = getpass("Password: ");

        if (p == NULL)
        {
            /* User not found — pass NULL so handle_failed_login skips the file update. */
            handle_failed_login(NULL);
            continue; /* Jump back to the top of the while loop. */
        }

        /* Check if the account is locked before even trying the password. */
        if (is_account_locked(p))
        {
            printf("Account is locked due to too many failed attempts.\n");
            continue;
        }

        /* p->pw_passwd accesses the pw_passwd field through the pointer p.
         * The '->' operator dereferences a pointer and accesses a struct member.
         * Equivalent to (*p).pw_passwd, but much more readable. */
        if (verify_password(password, p->pw_passwd))
        {
            handle_successful_login(p);
            return 0; /* Exit the program with success status. */
        }
        else
        {
            handle_failed_login(p);
            /* Loop continues — re-prompt for login. */
        }
    }

    return 0;
}
