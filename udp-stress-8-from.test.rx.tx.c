
/* udp-stress.c */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <arpa/inet.h>

#define LEN 1400
#define HOSTS 8

int main(int argc, char *argv[])
{
    int sd, len, i;
    struct sockaddr_in addr, addr_from;
    struct iovec iov;
    struct msghdr msg;
    static unsigned char sbuf[LEN], rbuf[LEN];

    /* eth0:0 address of each node in cluster: */
    static char *host[HOSTS] = {
        "10.0.0.7", "10.0.0.10", "10.0.0.8", "10.0.0.4",
        "10.0.0.11", "10.0.0.9", "10.0.0.5", "10.0.0.6",
    };

    fflush(stdout);
    fflush(stderr);
    if (fork())
        return 0;
    close(1);
    open("/tmp/udp-stress.log",O_CREAT|O_WRONLY|O_APPEND,0777);
    close(2);
    dup(1);
    close(0);
    setsid();
    chdir("/");

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0)
    {
        perror("socket()");
        return 1;
    }

    len = 16 * 1024 * 1024;
    if (setsockopt(sd, SOL_SOCKET, SO_SNDBUFFORCE, &len, sizeof(len)) < 0)
    {
        perror("setsockopt(SO_SNDBUFFORCE)");
        return 2;
    }

    len = 16 * 1024 * 1024;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUFFORCE, &len, sizeof(len)) < 0)
    {
        perror("setsockopt(SO_RCVBUFFORCE)");
        return 3;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[1]));
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind()");
        return 4;
    }

    for (i = 0; i < LEN; i++)
        sbuf[i] = (unsigned char)i;

    for (;;)
    {
        if (rand() & 8)
        {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(atoi(argv[1]));
            addr.sin_addr.s_addr = inet_addr(host[rand() % HOSTS]);

            memset(&iov, 0, sizeof(iov));
            iov.iov_base = sbuf;
            iov.iov_len = rand() % LEN + 0x300;
            //if (iov.iov_len > LEN)
            //   iov.iov_len = LEN;
            iov.iov_len = 0x476; //send 0x476 bytes

            memset(&msg, 0, sizeof(msg));
            msg.msg_name = &addr;
            msg.msg_namelen = sizeof(addr);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            len = sendmsg(sd, &msg, MSG_DONTWAIT);
            if (len != iov.iov_len)
            {
                if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    continue;
                perror("sendmsg()");
                return 5;
            }
        }
        else
        {
            memset(rbuf, 0xCC, LEN);
            memset(&iov, 0, sizeof(iov));
            iov.iov_base = rbuf;
            iov.iov_len = LEN;

            memset(&msg, 0, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            memset(&addr_from, 0, sizeof(addr_from)); //cdx
            msg.msg_name = &addr_from;
            msg.msg_namelen = sizeof(addr_from);

            len = recvmsg(sd, &msg, MSG_DONTWAIT);
            if (len <= 0)
            {
                if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    continue;
                perror("recvmsg()");
                return 6;
            }

            if (memcmp(sbuf, rbuf, len))
            {
                fprintf(stderr, "710:1127:receive data mismatch detected "
                                "[@port = %hd, len = 0x%x, from %s:%hd]\n",
                                atoi(argv[1]), len,
                                inet_ntoa(addr_from.sin_addr),
                                ntohs(addr_from.sin_port));

                for (i = 0; i < len; i++)
                    if (rbuf[i] != sbuf[i])
                    {
                        fprintf(stderr, " rbuf[0x%x] = 0x%02hhx"
                                        " [expected 0x%02hhx]\n",
                                        i, rbuf[i], sbuf[i]);
                    }

                //return 7;
            }
        }
    }

    return 0;
}
