#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define BUF_SIZE 100
#define FILE_PATH "/var/tmp/aesdsocketdata"

int     sockfd;
int     server_running = 1;
struct addrinfo     *servinfo;  // will point to the results


void	handle_sig(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
    {
        syslog(LOG_INFO, "Caught signal, exiting\n");
        close(sockfd);
        server_running = 0;
        freeaddrinfo(servinfo);
        if (remove(FILE_PATH) == 0)
            syslog(LOG_INFO, "File deleted.\n");
        else
            syslog(LOG_INFO, "Failed to delete file.\n");
    }
    exit(0);
}


void daemon_mode(void)
{
    pid_t pid;

    if ((pid = fork()) == -1)
    {
        perror("Error on fork:");
        exit(-1);
    }
    else if (pid == 0) //child process
    {
        setsid();
        chdir("/");
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0) {
            syslog(LOG_ERR, "opening file error: %s\n", strerror(errno));
            close(fd);
            exit(-1);
        }
        if(dup2(fd, STDIN_FILENO) == -1)
            syslog(LOG_ERR, "error while redirection STDIN to /dev/null: %s\n", strerror(errno));
        if(dup2(fd, STDOUT_FILENO) == -1)
            syslog(LOG_ERR, "error while redirection STDOUT to /dev/null: %s\n", strerror(errno));
        if(dup2(fd, STDERR_FILENO) == -1)
            syslog(LOG_ERR, "error while redirection STDERR to /dev/null: %s\n", strerror(errno));
    }
    else //parent process
    {
        exit(0);
    }

}


int main(int argc, char **argv)
{
    openlog(NULL,0,LOG_USER);
    (void)argc;
    (void)argv;
    int                 sockfd_accept;
    char                ipstr[INET_ADDRSTRLEN];
    void                *addr;
    int                 status;
    struct addrinfo     hints;
    //struct addrinfo     *servinfo;  // will point to the results
    struct sockaddr_in  *ipv4;
    //struct sockaddr     client_addr;
    //socklen_t           client_addr_size;
    int                 numbytes;
    char                buf[BUF_SIZE];
    int                 yes=1;
    struct sigaction	sa;

    //Handling SIGINT and SIGTERM
    sa.sa_handler = &handle_sig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);


    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_INET;     // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    if ((status = getaddrinfo(NULL, "9000", &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", strerror(errno));
        syslog(LOG_ERR,"getaddrinfo error: %s\n", strerror(errno));
        exit(-1);
    }

    ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
    addr = &(ipv4->sin_addr);
    inet_ntop(servinfo->ai_family, addr, ipstr, sizeof ipstr);
    printf("IP is: %s\n",ipstr);

    //create socket file descriptor
    fprintf(stdout, "Create socket step\n");
    if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        syslog(LOG_ERR,"socket error: %s\n", strerror(errno));
        exit(-1);
    }

    //fix issue with "Address already in use" error message
    fprintf(stdout, "Fix \"address already in use\" step\n");
    if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
        fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
        syslog(LOG_ERR, "setsockopt error: %s\n", strerror(errno));
        exit(-1);
    }

    //bind to assign an address to the socket file descriptor
    fprintf(stdout, "Bind step\n");
    if ((status = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen)) == -1) {
        fprintf(stderr, "bind error: %s\n", strerror(errno));
        syslog(LOG_ERR,"bind error: %s\n", strerror(errno));
        exit(-1);
    }


    //daemon mode
    if (argc > 1 && strcmp(argv[1], "-d") == 0)
    {
        daemon_mode();
    }

    //listen step
    fprintf(stdout, "Listen step\n");
    if ((status = listen(sockfd, 5)) == -1) {
        fprintf(stderr, "listen error: %s\n", strerror(errno));
        syslog(LOG_ERR,"listen error: %s\n", strerror(errno));
        exit(-1);
    }

    while (server_running)
    {

        //accept and incoming connection
        fprintf(stdout, "Accepted step\n");
        if ((sockfd_accept = accept(sockfd, servinfo->ai_addr, &servinfo->ai_addrlen)) == -1) {
            fprintf(stderr, "accept error: %s\n", strerror(errno));
            syslog(LOG_ERR,"accept error: %s\n", strerror(errno));
            exit(-1);
        }
        else
        {
            ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(servinfo->ai_family, addr, ipstr, sizeof ipstr);
            fprintf(stderr, "Accepted connection from %s\n", ipstr);
            syslog(LOG_ERR,"Accepted connection from %s\n", ipstr);
        }

        //create file
        int file_fd = open(FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (file_fd < 0) {
            syslog(LOG_ERR, "opening file error: %s\n", strerror(errno));
            close(file_fd);
            exit(-1);
        }

        //write to the file data received over connection
        while ((numbytes = recv(sockfd_accept, buf, BUF_SIZE-1, 0)) > 0)
        {
            write(file_fd, buf, numbytes);
            if (buf[numbytes - 1] == '\n')
                break;
        }
        close(file_fd);


        // read from file and send back to client
        file_fd = open(FILE_PATH, O_RDONLY);
        if (file_fd < 0) {
            syslog(LOG_ERR, "opening file error: %s\n", strerror(errno));
            close(file_fd);
            close(sockfd_accept);
            exit(-1);
        }

        while ((numbytes = read(file_fd, buf, BUF_SIZE-1)) > 0)
        {
            if ((send(sockfd_accept, buf, numbytes, 0)) < 0) {
                fprintf(stderr, "send error: %s\n", strerror(errno));
                syslog(LOG_ERR, "send error: %s\n", strerror(errno));
                exit(1);
            }
        }

        fprintf(stderr, "Closed connection from %s\n", ipstr);
        syslog(LOG_INFO, "Closed connection from %s\n", ipstr);
        close(file_fd);
        close(sockfd_accept);
    }
    close(sockfd);
    freeaddrinfo(servinfo);
    closelog();
}
