/*
 *    Simple program to log from Apache to a MySQL database using the piped log mechanism.
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

#define BUFSIZE  12288                 /* Max buffer size for log record   */
#define MAXHOST  512                   /* Max hostname buffer size         */
#define MAXURL   4096                  /* Max HTTP request/URL field size  */
#define	MAXHTTP	 12    	       	       /* Max http version field size  	   */
#define MAXREF   4096                  /* Max referrer field size          */
#define MAXAGENT 256                   /* Max user agent field size        */
#define MAXSRCH  1024                  /* Max size of search string buffer */
#define MAXIDENT 256                   /* Max size of ident string (user)  */
#define MAXSSLPROTO 16                 /* Max size of SSL protocol         */
#define MAXSSLCIPHER 512               /* Max size of SSL cipher           */

struct  log_struct  {
  char   hostname[MAXHOST];                      /* hostname                     */
  char   safe_hostname[(MAXHOST*2) + 1];         /* escaped hostname             */
  char   datetime[29];                           /* raw timestamp                */
  char   safe_datetime[59];                      /* escaped raw timestamp        */
  char   url[MAXURL];                            /* raw request field            */
  char   safe_url[(MAXURL*2) + 1];               /* escaped raw request field    */
  char   http[MAXHTTP];                          /* HTTP type (1.0/1.1/2.0)      */
  char   safe_http[(MAXHTTP*2) + 1];             /* escaped HTTP type            */
  u_long req_size;                               /* request size in bytes        */
  int    resp_code;                              /* response code                */
  u_long xfer_size;                              /* xfer size in bytes           */
  char   refer[MAXREF];                          /* referrer                     */
  char   safe_refer[(MAXREF*2) + 1];             /* escaped referrer             */
  char   agent[MAXAGENT];                        /* user agent (browser)         */
  char   safe_agent[(MAXAGENT*2) + 1];           /* escaped user agent (browser) */
  char   ident[MAXIDENT];                        /* ident string (user)          */
  char   safe_ident[(MAXIDENT*2) + 1];           /* escaped ident string (user)  */
  char   ssl_protocol[MAXSSLPROTO];              /* ssl protocol string          */
  char   safe_ssl_protocol[(MAXSSLPROTO*2) + 1]; /* escaped ssl protocol string  */
  char   ssl_cipher[MAXSSLCIPHER];               /* ssl cipher string            */
  char   safe_ssl_cipher[(MAXSSLCIPHER*2) + 1];  /* escaped ssl cipher string    */
}; 

struct log_struct log_rec;

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

static const char *client_groups[] = {"logtomysql", NULL};

static struct my_option my_opts[] = 
{
  {"help", '?', "Display this help text and exit", NULL, NULL, NULL, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"host", 'h', "MySQL host to connect to", &opt_db_host, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"port", 'P', "Port number to use for connection", &opt_port, NULL, NULL, GET_INT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"password", 'p', "Password", &opt_db_pwd, NULL, NULL, GET_STR_ALLOC, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"database", 'd', "Logging database", &opt_db_name, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"user", 'u', "Username", &opt_db_user, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"socket", 's', "Socket file", &opt_socket_file, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"logging", 'l', "Logging level 0(off) 1(important) 2(everyting)", &opt_logging, NULL, NULL, GET_INT, REQUIRED_ARG, 1, 0, 0, 0, 0, 0},
  {"logfile", 'f', "Log file", &opt_log_file, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"sysuser", 'U', "System user name", &opt_db_sysuser, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"sysgroup", 'G', "System group name", &opt_db_sysgroup, NULL, NULL, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0}
};

static int ask_password = 0;

/* internal function prototypes */
void fmt_logrec(char *);
int  parse_record_web(char *);
int safe_mysql_query(const char *);
int open_logdb_link(void);
void logError(char *);
my_bool get_one_option(int, const struct my_option *, char *);

int main (int argc, char **argv)
{
    char buf[BUFSIZE];
    int nRead;
    int retval = 0;
    int num_errors = 0;
    int opt_error;
    //Data to log
    char *query;
    struct passwd *entp;
    struct group *entg;

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
      logError("Bad system user name. LogToMysql halted.");
      exit(1);
    }

    if (!(entg = getgrnam(opt_db_sysgroup))) {
      logError("Bad system group name. LogToMysql halted.");
      exit(1);
    }

    //Change group before changing user, since a non-root user can't cahnge group
    if (entg->gr_gid < 1 || setgid(entg->gr_gid) == -1) {
      logError("Failed to set system group name. LogToMysql halted.");
      exit(1);
    }

    if (entp->pw_uid < 1 || setuid(entp->pw_uid) == -1) {
      logError("Failed to set system user name. LogToMysql halted.");
      exit(1);
    }

    if (opt_logging > 0) logError("LogToMysql piped connection starting");
    //Set up MySQL connection
    open_logdb_link();

    for (;;) {
      //nRead = read(0, buf, sizeof buf); //This doesn't work - under very high server loads queries get lost
      fgets(buf, sizeof buf, stdin);
      nRead = strlen(buf);
      if (nRead == 0)
	exit(3);
      parse_record_web(buf);
      //Escape any characters in the string which might mess up MySQL queries. 
      if(conn){
	mysql_real_escape_string(conn, log_rec.safe_hostname, log_rec.hostname, strlen(log_rec.hostname));
	mysql_real_escape_string(conn, log_rec.safe_datetime, log_rec.datetime, strlen(log_rec.datetime));
	mysql_real_escape_string(conn, log_rec.safe_url, log_rec.url, strlen(log_rec.url));
        mysql_real_escape_string(conn, log_rec.safe_http, log_rec.http, strlen(log_rec.http));
	mysql_real_escape_string(conn, log_rec.safe_refer, log_rec.refer, strlen(log_rec.refer));
	mysql_real_escape_string(conn, log_rec.safe_agent, log_rec.agent, strlen(log_rec.agent));
	mysql_real_escape_string(conn, log_rec.safe_ident, log_rec.ident, strlen(log_rec.ident));
	mysql_real_escape_string(conn, log_rec.safe_ssl_protocol, log_rec.ssl_protocol, strlen(log_rec.ssl_protocol));
	mysql_real_escape_string(conn, log_rec.safe_ssl_cipher, log_rec.ssl_cipher, strlen(log_rec.ssl_cipher));
      }else{
	mysql_escape_string(log_rec.safe_hostname, log_rec.hostname, strlen(log_rec.hostname));
	mysql_escape_string(log_rec.safe_datetime, log_rec.datetime, strlen(log_rec.datetime));
	mysql_escape_string(log_rec.safe_url, log_rec.url, strlen(log_rec.url));
        mysql_escape_string(log_rec.safe_http, log_rec.http, strlen(log_rec.http));
	mysql_escape_string(log_rec.safe_refer, log_rec.refer, strlen(log_rec.refer));
	mysql_escape_string(log_rec.safe_agent, log_rec.agent, strlen(log_rec.agent));
	mysql_escape_string(log_rec.safe_ident, log_rec.ident, strlen(log_rec.ident));
        mysql_escape_string(log_rec.safe_ssl_protocol, log_rec.ssl_protocol, strlen(log_rec.ssl_protocol));
        mysql_escape_string(log_rec.safe_ssl_cipher, log_rec.ssl_cipher, strlen(log_rec.ssl_cipher));
      }
      
      sprintf(query, "INSERT INTO log (hostname, datetime, datetime_ts, url, http_type, req_size, refer, agent, ident, resp_code, xfer_size, ssl_protocol, ssl_cipher)\
                        VALUES ('%s', '%s', unix_timestamp(STR_TO_DATE('%s','%s')), '%s', '%s', %lu, '%s', '%s', '%s', %i, %lu, '%s', '%s')", \
	      log_rec.safe_hostname, log_rec.safe_datetime, log_rec.safe_datetime, "[%d/%b/%Y:%H:%i:%S", log_rec.safe_url, log_rec.safe_http,\
              log_rec.req_size, log_rec.safe_refer, log_rec.safe_agent, log_rec.safe_ident, log_rec.resp_code, log_rec.xfer_size,\
	      log_rec.safe_ssl_protocol, log_rec.safe_ssl_cipher);
      
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
    if (opt_logging > 0) logError("LogToMysql piped connection stopped");
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

void fmt_logrec(char *buffer)
{
   char *cp=buffer;
   int  q=0,b=0,p=0;

   while (*cp != '\0')
   {
      /* break record up, terminate fields with '\0' */
      switch (*cp)
      {
       case ' ': if (b || q || p) break; *cp='\0'; break;
       case '"': q^=1;  break;
       case '[': if (q) break; b++; break;
       case ']': if (q) break; if (b>0) b--; break;
       case '(': if (q) break; p++; break;
       case ')': if (q) break; if (p>0) p--; break;
      }
      cp++;
   }
}

int parse_record_web(char *buffer)
{
   int size;
   char *cp1, *cp2, *cpx, *eob, *eos;
   char *msg_big_host= "Warning: Truncating oversized hostname";
   char *msg_big_user= "Warning: Truncating oversized username";
   char *msg_big_date= "Warning: Truncating oversized date field";
   char *msg_big_req = "Warning: Truncating oversized request field";
   char *msg_big_ref = "Warning: Truncating oversized referrer field";
   int     verbose = 0     ;                 /* 2=verbose,1=err, 0=none  */ 
   int     debug_mode = 0  ;                 /* debug mode flag          */

   char *temp1, *temp2;
   char cp[MAXHOST];

   memset(&log_rec,0,sizeof(struct log_struct));

   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer+size;                     /* calculate end of buffer     */
   fmt_logrec(buffer);                    /* seperate fields with \0's   */

   /* HOSTNAME */
   cp1 = cpx = buffer; cp2=log_rec.hostname;
   eos = (cp1+MAXHOST)-1;
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_host);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* skip next field (ident) */
   while ( (*cp1 != '\0') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;

   /* IDENT (authuser) field */
   cpx = cp1;
   cp2 = log_rec.ident;
   eos = (cp1+MAXIDENT-1);
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '[') && (cp1 < eos) ) /* remove embeded spaces */
   {
      if (*cp1=='\0') *cp1=' ';
      *cp2++=*cp1++;
   }
   *cp2--='\0';

   if (cp1 >= eob) return 0;

   /* check if oversized username */
   if (*cp1 != '[')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_user);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while ( (*cp1 != '[') && (cp1 < eob) ) cp1++;
   }

   /* strip trailing space(s) */
   while (*cp2==' ') *cp2--='\0';

   /* date/time string */
   cpx = cp1;
   cp2 = log_rec.datetime;
   eos = (cp1+28);
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_date);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* minimal sanity check on timestamp */
   if ( (log_rec.datetime[0] != '[') ||
        (log_rec.datetime[3] != '/') ||
        (cp1 >= eob))  return 0;

   /* HTTP request */
   cpx = cp1;
   cp2 = log_rec.url;
   eos = (cp1+MAXURL-1);
   if (eos >= eob) eos = eob-1;

   if ( (*cp1 == '"') ) {
     *cp2++ = *cp1++;
     while ( (*cp1 != '"') && (cp1 != eos) ) *cp2++ = *cp1++;
     if (*cp1 == '"') *cp2++ = *cp1++;
     while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   }
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_req);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   if ( (log_rec.url[0] != '"') ||
        (cp1 >= eob) ) return 0;

   /* response code */
   log_rec.resp_code = atoi(cp1);

   /* xfer size */
   while ( (*cp1 != '\0') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   if (*cp1<'0') log_rec.xfer_size=0;
   else log_rec.xfer_size = strtoul(cp1,NULL,10);

   /* done with CLF record */
   if (cp1>=eob) return 1;

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   /* get referrer if present */
   cpx = cp1;
   cp2 = log_rec.refer;
   eos = (cp1+MAXREF-1);
   if (eos >= eob) eos = eob-1;

   if ( (*cp1 == '"') ) {
     *cp2++ = *cp1++;
     while ( (*cp1 != '"') && (cp1 != eos) ) *cp2++ = *cp1++;
     if (*cp1 == '"') *cp2++ = *cp1++;
     while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   }
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_ref);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   cpx = cp1;
   cp2 = log_rec.agent;
   eos = cp1+(MAXAGENT-1);
   if (eos >= eob) eos = eob-1;

   if ( (*cp1 == '"') ) {
     *cp2++ = *cp1++;
     while ( (*cp1 != '"') && (cp1 != eos) ) *cp2++ = *cp1++;
     if (*cp1 == '"') *cp2++ = *cp1++;
     while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   }
   *cp2 = '\0';

   /* done with CMN record */
   if (cp1>=eob) return 1;

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   /* get http type if present */
   cpx = cp1;
   cp2 = log_rec.http;
   eos = (cp1+MAXHTTP-1);
   if (eos >= eob) eos = eob-1;
   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';

   /* request size */
   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   if (*cp1<'0') log_rec.req_size=0;
   else log_rec.req_size = strtoul(cp1,NULL,10);

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   /* get SSL_PROTOCOL if present */
   cpx = cp1;
   cp2 = log_rec.ssl_protocol;
   eos = (cp1+MAXSSLPROTO-1);
   if (eos >= eob) eos = eob-1;
   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   /* get SSL_CIPHER if present */
   cpx = cp1;
   cp2 = log_rec.ssl_cipher;
   eos = (cp1+MAXSSLCIPHER-1);
   if (eos >= eob) eos = eob-1;
   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';

   return 1;     /* maybe a valid record, return with TRUE */
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
