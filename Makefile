#################################################################
#Change these lines to point to the directories containing your 
#MySQL includes and libraries. Note - no trailing slash!!
#
#Places to try are:
#
#   Includes:
#        /usr/local/mysql/include/mysql
#        /usr/local/include/mysql
#        /usr/include/mysql
#   Libraries:
#        /usr/local/mysql/lib/mysql
#        /usr/local/lib/mysql
#        /usr/lib/mysql
#################################################################

INCLUDES = -I/usr/include/mysql
LIBS = -L/usr/lib64/mysql -lmysqlclient_r -lz

#No changes needed below here####################################

CC = gcc
#all: logtomysql logerrortomysql
all: logtomysql
logtomysql.o: logtomysql.c
	$(CC) -O3 -c $(INCLUDES) logtomysql.c
logtomysql: logtomysql.o
	$(CC) -O3 -o logtomysql logtomysql.o $(LIBS)
#logerrortomysql.o: logerrortomysql.c
#	$(CC) -O3 -c $(INCLUDES) logerrortomysql.c
#logerrortomysql: logerrortomysql.o
#	$(CC) -O3 -o logerrortomysql logerrortomysql.o $(LIBS)
clean:
	rm -f logtomysql logtomysql.o logerrortomysql logerrortomysql.o

