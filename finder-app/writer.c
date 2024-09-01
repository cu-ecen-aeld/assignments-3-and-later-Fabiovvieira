#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

int main(int argc, char** argv)
{
	openlog(NULL,0,LOG_USER);
	char *writefile;
	char *writestr;
	FILE *fd;

	if (argc != 3)
	{
		syslog(LOG_ERR, "Wrong number of arguments\n");
		fprintf(stderr, "Wrong number of arguments\n");
		return 1;
	}
	
	writefile = argv[1];
	writestr = argv[2];

	fd = fopen(writefile, "w+");
	if (!fd)
	{
		syslog(LOG_ERR, "Error opening the file %s: %s\n", writefile, strerror(errno));
		fprintf(stderr, "Error opening the file %s: %s\n", writefile, strerror(errno));
		return 1;
	}
	fprintf(fd, "%s", writestr);
	fprintf(stdout, "Writing <%s> to %s\n", writestr, writefile);
	syslog(LOG_DEBUG,"Writing <%s> to %s\n", writestr, writefile);
	fclose(fd);
	closelog();
	return 0;
}
