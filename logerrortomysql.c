/*
 *    Simple program to log Apache errors to a MySQL database using the piped log mechanism.
 *    Copyright (C) 2003  David I Fletcher (david@megapico.co.uk)
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 *    Version 0.9, 1-Nov-2003
 *
 */

#include <mysql/my_global.h>
#include <mysql/mysql.h>
#include <mysql/my_getopt.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#define BUFSIZE  4096                  /* Max buffer size for log record   */

#define MYSQL_ERROR(mysql) ((mysql)?(mysql_error(mysql)):"MySQL server has gone away")

MYSQL *conn = NULL;
FILE * out;

static char *opt_db_name = NULL;
static char *opt_db_host = NULL;
static char *opt_db_user = NULL;
static char *opt_db_pwd = NULL;
static char *opt_socket_file = NULL;
static char *opt_log_file = NULL;
static char *opt_db_sysuser = NULL;
static char *opt_db_sysgroup = NULL;
static int opt_logging;
static int opt_port;

static const char *client_groups[] = {"logerrortomysql", NULL};

static struct my_option my_opts[] = 
{
  {"help", '?', "Display this help text and exit", NULL, NULL, NULL, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"host", 'h', "MySQL host to connect to", (gptr *) &opt_db_host, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"port", 'P', "Port number to use for connection", (gptr *) &opt_port, NULL, NULL, GET_INT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"password", 'p', "Password", (gptr *) &opt_db_pwd, NULL, NULL, GET_STR_ALLOC, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"database", 'd', "Logging database", (gptr *) &opt_db_name, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"user", 'u', "Username", (gptr *) &opt_db_user, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"socket", 's', "Socket file", (gptr *) &opt_socket_file, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"logging", 'l', "Logging level 0(off) 1(important) 2(everyting)", (gptr *) &opt_logging, NULL, NULL, GET_INT, REQUIRED_ARG, 1, 0, 0, 0, 0, 0},
  {"logfile", 'f', "Log file", (gptr *) &opt_log_file, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"sysuser", 'U', "System user name", (gptr *) &opt_db_sysuser, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"sysgroup", 'G', "System group name", (gptr *) &opt_db_sysgroup, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0}
};

static int ask_password = 0;

/* internal function prototypes */
int safe_mysql_query(const char *);
int open_logdb_link(void);
void logError(char *);
my_bool get_one_option(int, const struct my_option *, char *);

int main (int argc, char **argv)
{
    char buf[BUFSIZE];
    char safe_buf[BUFSIZE*2 + 1];
    int nRead;
    int retval = 0;
    int num_errors = 0;
    int opt_error;
    //Data to log
    char *query;
    char *end;
    struct passwd *entp;
    struct group *entg;
    time_t timer;

    query = (char *) malloc((BUFSIZE*2) + 401);

    //Read in options from either the command line, or the mysqllog section of my.cnf
    my_init();
    load_defaults ("my", client_groups, &argc, &argv);
    if(opt_error = handle_options(&argc, &argv, my_opts, get_one_option))
      exit(opt_error);
    if(ask_password)
      opt_db_pwd = get_tty_password(NULL);

    //Open the error log file prior to changing uid/pid
    out = fopen(opt_log_file, "a");

    //Change gid and uid to non-root values - Apache will otherwise run this program as root.
    //Get the uid and gid corresponding to the names given in the config file/command line

    if (!(entp = getpwnam(opt_db_sysuser))) {
      logError("Bad system user name. LogErrorToMysql halted.");
      exit(1);
    }

    if (!(entg = getgrnam(opt_db_sysgroup))) {
      logError("Bad system group name. LogErrorToMysql halted.");
      exit(1);
    }

    //Change group before changing user, since a non-root user can't cahnge group
    if (entg->gr_gid < 1 || setgid(entg->gr_gid) == -1) {
      logError("Failed to set system group name. LogErrorToMysql halted.");
      exit(1);
    }

    if (entp->pw_uid < 1 || setuid(entp->pw_uid) == -1) {
      logError("Failed to set system user name. LogErrorToMysql halted.");
      exit(1);
    }

    if (opt_logging > 0) logError("LogErrorToMysql piped connection starting");
    //Set up MySQL connection
    open_logdb_link();

    for (;;) {
      //nRead = read(0, buf, sizeof buf); //This doesn't work - under very high server loads queries get lost
      fgets(buf, sizeof buf, stdin);
      nRead = strlen(buf);
      if (nRead == 0)
	exit(3);
      
      //Since error logs are much more free-form than the access logs, 
      //including output of cgi scripts etc
      //just log the whole line and the date
      
      //Remove trailing white space
      end = buf + (strlen(buf) - 1); /* Point to the last non-null character in the string */
      while(isspace(*end)){
	end--;
      }
      *(end+1) = '\0';
      
      if(conn)
	mysql_real_escape_string(conn, safe_buf, buf, strlen(buf));
      else
	mysql_escape_string(safe_buf, buf, strlen(buf));
      
      sprintf(query, "INSERT INTO errorlog (datetime, message) VALUES (NULL, '%s')", safe_buf);
      
      retval = safe_mysql_query(query);
      
      if (opt_logging > 1) logError(query);

      //A query may fail for a temporary reason, so don't break immediately, but do prevent an infinite loop.
      //This is especially important if Apache is in a chroot jail
      //becase it is often unable to re-start a failed piped logging process
      if(retval != 0){
	num_errors++;
      }

      if(num_errors > 2000){
 	break;
      }
    }
    /* We never get here, but suppress the compile warning */
    if (opt_logging > 0) logError("LogErrorToMysql piped connection stopped");
    return (0);
}

my_bool get_one_option(int optid, const struct my_option *opt, char *argument){
  switch(optid){
  case '?':
    my_print_help(my_opts);
    exit(0);
  case 'p':
    if(!argument)
      ask_password = 1;
    else{
      opt_db_pwd = strdup (argument);
      if(opt_db_pwd == NULL){
	printf("%s \n", "Could not allocate password buffer");
	exit(1);
      }
      while (*argument)
	*argument++ = 'x';
    }
    break;
  }
  return(0);
}

int open_logdb_link()
{
  /* Returns 2 if already connected, 0 if successful, 1 if unsuccessful */
  
  if (conn != NULL) {
    return 2;
  }
  conn = mysql_init(NULL);
  if (conn == NULL)
    return 1;
  if(mysql_real_connect(conn, opt_db_host, opt_db_user, opt_db_pwd, opt_db_name, opt_port, opt_socket_file, 0) == NULL){
    if (opt_logging > 0) logError("No connection could be made to the server");
    //Do not call mysql_close(conn) for a failed connection
    //Prevent the initialised connector appearing as a real connection in this case.
    conn = NULL;
    return 1;
  }
  if (opt_logging > 1) logError("Connection made to server");
  return 0;
}

int safe_mysql_query(const char *query)
{
  int retval;
  struct timespec delay, remainder;
  char *str;
  void (*handler) (int);

  /* A failed mysql_query() may send a SIGPIPE, so we ignore that signal momentarily. */
  handler = signal(SIGPIPE, SIG_IGN);

  if (conn == NULL)
    open_logdb_link();

  //If connection is still NULL just forget this query, wait for the next and try again 
  //Don't get into a loop of trying to connect - just wait for the next incoming query.
  //Important when both Apache and MySql are starting up togther, but MySql is slower.
  if (conn == NULL){
    /* Restore SIGPIPE to its original handler function */
    signal(SIGPIPE, handler);
    if (opt_logging > 1) logError("unable to reach database");
    return 1;
  }

  /* First attempt for the query */
  retval = mysql_query(conn, query);

  if ( retval != 0 ){
    /* Something went wrong, so start by trying to restart the db link. */
    mysql_close(conn);
    conn = NULL;
    open_logdb_link();
    
    if (conn == NULL) {	 /* still unable to link */
      /* Restore SIGPIPE to its original handler function */
      signal(SIGPIPE, handler);
      if (opt_logging > 1) logError("unable to reach database");
      return retval;
    } else {
      if (opt_logging > 1) logError("reconnect successful");
    }
    
    /* Attempt a single re-try... First sleep for a tiny amount of time. */
    delay.tv_sec = 0;
    delay.tv_nsec = 250000000;  /* max is 999999999 (nine nines) */
    nanosleep(&delay, &remainder);
    
    /* Now make our second attempt */
    retval = mysql_query(conn,query);
    
    /* If this one also failed, log that and append to our local offline file */
    if ( retval != 0 ){
      if (opt_logging > 0) logError("delayed insert attempt failed, API said: ");
      if (opt_logging > 0) logError((char *) MYSQL_ERROR(conn));
    }else{
      if (opt_logging > 1) logError("insert successful after a delayed retry.");
    }
  }
  
  /* Restore SIGPIPE to its original handler function */
  signal(SIGPIPE, handler);
  
  return retval;
}

void logError(char *buffer){
  int nWrite;
  time_t timer;

  timer=time(NULL);
  if (out) {
    fprintf(out, "PID: %i: %s: Time: %s", (int) getpid(), buffer, asctime(localtime(&timer)));
    fflush(out);
  } else {
    fprintf(stderr, "PID: %i: %s: Time: %s", (int) getpid(), buffer, asctime(localtime(&timer)));
    fflush(stderr);
  }
  fflush(out);
}
