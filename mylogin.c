#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* Behövs för getpass */
#include <crypt.h>   /* Behövs för crypt */
#include "pwdblib.h" /* Inkludera header för pwdblib.c */
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#define USERNAME_SIZE (32)

/* * Funktion för att starta användarens skal.
 * Hanterar fork, setgid, setuid och execl.
 * Motsvarar Prep 6 och Problem 10-11.
 */
void start_shell_session(struct pwdb_passwd *p)
{
    printf("User authenticated successfully. Starting shell...\n");

    pid_t pid = fork();

    if (pid < 0)
    {
        perror("Fork failed");
    }
    else if (pid == 0)
    {
        /* Barnprocessen */

        /* Byt till användarens Group ID och User ID */
        /* VIKTIGT: setgid måste göras innan setuid annars förloras rättigheter för tidigt */
        if (setgid(p->pw_gid) != 0)
        {
            perror("setgid failed");
        }
        if (setuid(p->pw_uid) != 0)
        {
            perror("setuid failed");
        }

        /* Starta skalet enligt instruktionerna*/
        execl(p->pw_shell, p->pw_shell, NULL);

        /* Om execl misslyckas: */
        perror("Exec failed");
        exit(1);
    }
    else
    {
        /* Förälderprocessen */
        /* Väntar bara tills barnet avslutas (Alltså användare t.ex donald loggar ut)  */
        wait(NULL);
        printf("Child exited. Returning to login prompt...\n");
    }
}

/*
 * Hanterar logik vid lyckad inloggning:
 * - Nollställer pw_failed
 * - Ökar pw_age
 * - Sparar till filen pwfile
 * - Startar skalet
 */
void handle_successful_login(struct pwdb_passwd *p)
{
    p->pw_failed = 0;
    p->pw_age++;

    if (pwdb_update_user(p) != 0)
    {
        printf("Error updating user database.\n");
    }

    /* Varna om lösenordet är gammalt (Alltså någon loggat in fler än 3 gånger)*/
    if (p->pw_age > 5)
    {
        printf("Warning => Your password is old (%d logins). Please change it!!!!!\n", p->pw_age);
    }

    /* Starta skalet */
    start_shell_session(p);
}

/*
 * Hanterar logik vid misslyckad inloggning:
 * - Ökar pw_failed
 * - Sparar till pwfile
 */
void handle_failed_login(struct pwdb_passwd *p)
{
    if (p != NULL)
    {
        p->pw_failed++;
        pwdb_update_user(p);
    }
    printf("Unknown user or incorrect password.\n");
}

void read_username(char *username)
{
    printf("login: ");
    if (fgets(username, USERNAME_SIZE, stdin) == NULL)
    {
        clearerr(stdin); /*Gör så att ctrl-c inte kraschar programmet*/
        username[0] = '\0';
        printf("\n");
        return;
    }

    /*Här tvättar vi bort enter tryckingen alltså '\n'*/
    size_t len = strlen(username);
    if (len > 0 && username[len - 1] == '\n')
    {
        username[len - 1] = '\0';
    }
}

int main(int argc, char **argv)
{
    /* Ignorera ctrl-c*/
    signal(SIGINT, SIG_IGN);

    char username[USERNAME_SIZE];
    char *password_input;
    struct pwdb_passwd *p;
    char salt[3];
    char *encrypted_input;

    /*Vår main while loop som körs om och om igen*/
    while (1)
    {
        read_username(username);

        if (strlen(username) == 0)
        {
            continue;
        }

        /* Hämta användare först för att kunna kolla om den finns/är låst */
        p = pwdb_getpwnam(username);

        /* Om användaren inte finns, fråga ändå efter lösenord för att inte avslöja det,
           men vi kan hantera det enkelt här */
        password_input = getpass("Password: ");

        if (p == NULL)
        {
            /* Ingen användare hittades */
            handle_failed_login(NULL);
            continue;
        }

        /* Kolla om kontot är låst pga fler än tre felaktiga logins */
        if (p->pw_failed > 3)
        {
            printf("Account is locked.\n");
            continue;
        }

        /* Autentisering */
        strncpy(salt, p->pw_passwd, 2);
        salt[2] = '\0';
        /*Vi anropar crypt med lösenordet användaren skrev in och saltet vi får från pwfile*/
        /*Exempel: crypt("quack01", "0B") -> Resultat: 0BWGsAnLYCtBU*/
        /*Om vi anropar quack01 med inställning 0B blir det alltid 0BWGsAnLYCtBU*/
        encrypted_input = crypt(password_input, salt);

        /*Här nedan kollar vi om hashen blir korrekt eller inte*/
        if (strcmp(encrypted_input, p->pw_passwd) == 0)
        {
            /* Lyckad inloggning */
            handle_successful_login(p);

            /* OBS: Tog bort 'break' här. Enligt manualen ska programmet
               visa "login:" igen när skalet avslutas.  */
        }
        else
        {
            /* Misslyckad inloggning */
            handle_failed_login(p);
        }
    }

    return 0;
}