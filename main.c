#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <sys/select.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define TARGETSFILE	"targets"
#define INTERVAL	60
#define LINEBUF		512
#define HOSTLEN		64
#define MAXPACKET	4096		/* max packet size */
#define IDSEQUENCE	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

typedef struct target {
  char id;
  char hostname[HOSTLEN+1];
  char address[16];
  struct sockaddr_in *addr;
  unsigned long rttsum;
  unsigned int rttmin;
  unsigned int rttmax;
  char *comment;
  struct target *next;
  int waitping;
} target;

target *targets;

int pid;
int sock;
int ntargets = 0;
int pinground = 0;

struct timeval nexttv;

int open_socket(void);
struct timeval check_timers(void);
int tvcmp(struct timeval, struct timeval);
struct timeval tvsub(struct timeval, struct timeval);
void read_socket(int);
void print_packet(char *, int, struct sockaddr_in *);
char *print_type(int);
int read_targets(void);
void send_ping(target *);
u_short calc_checksum(struct icmp *, int);

int main(void) {
  memset(&nexttv, 0, sizeof(struct timeval));

  pid = getpid();

  printf("My pid = %d\n", pid);

  if (open_socket() == -1) exit(-1);

  if (read_targets() == -1) exit(-2);

  while (1) {
    int r, fdmask = 1 << sock;
    struct timeval timeout;

    timeout = check_timers();

    r = select(sock+1, (fd_set *)&fdmask, 0, 0, &timeout);
    if (r == -1) {
      if (errno == EINTR) continue;
      perror("select()");
      exit(-3);
    }
    if (r) read_socket(sock);
  }
}

int open_socket(void) {
  struct protoent *proto = NULL;

  if (!(proto = getprotobyname("icmp"))) {
    perror("getprotobyname()");
    return -1;
  }
  if ((sock = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
    perror("socket()");
    return -1;
  }
  return 0;
}

struct timeval check_timers(void) {
  static target *tp = NULL;
  struct timeval currtv;

  gettimeofday(&currtv, NULL);

  if (tvcmp(currtv, nexttv) < 0) return tvsub(nexttv, currtv);

  if (tp) {
    if (tp->waitping) printf("%c  %-25.25s %-15s Probe %d delayed   (%d second%s)\n", tp->id, tp->hostname,
      tp->address, tp->waitping, INTERVAL / ntargets, INTERVAL/ntargets==1?"":"s");
    tp = tp->next;
  }
  if (!tp) {
    tp = targets;
    pinground++;
    printf("Starting ping round %d\n", pinground);
  }

  if (tp->waitping) printf("%c  %-25.25s %-15s Probe %d abandoned (60 seconds)\n", tp->id, tp->hostname,
    tp->address, tp->waitping);
  send_ping(tp);
  tp->waitping = pinground;

  memcpy(&nexttv, &currtv, sizeof(struct timeval));
  nexttv.tv_sec += INTERVAL / ntargets;
  currtv.tv_sec = INTERVAL / ntargets;
  currtv.tv_usec = 0;
  return currtv;
}

int tvcmp(struct timeval left, struct timeval right) {
  if (left.tv_sec > right.tv_sec) return 1;
  if (left.tv_sec < right.tv_sec) return -1;
  if (left.tv_usec > right.tv_usec) return 1;
  if (left.tv_usec < right.tv_usec) return -1;
  return 0;
}

struct timeval tvsub(struct timeval left, struct timeval right) {
  struct timeval r;

  r.tv_sec = left.tv_sec - right.tv_sec;
  r.tv_usec = left.tv_usec - right.tv_usec;

  if (r.tv_usec < 0) {
    r.tv_sec--;
    r.tv_usec += 1000000;
  }
  if (r.tv_sec < 0) {
    fprintf(stderr, "Fatal error: negative result in timeval subtraction (%d)\n", r.tv_sec);
    exit(-28);
  }
  return r;
}

void read_socket(int sock) {
  char packet[MAXPACKET];
  struct sockaddr_in from;
  int r = 0, len = sizeof(packet), fromlen = sizeof(from);

  r = recvfrom(sock, packet, len, 0, (struct sockaddr *)&from, &fromlen);

  if (r > 0) print_packet(packet, r, &from);

  if ((r == -1) && (errno != EINTR)) perror("recvfrom()");
}

void print_packet(char *packet, int len, struct sockaddr_in *from) {
  int r, hlen;
  long *lp = (long *) packet;
  target *tp;
  struct ip *ip;
  struct icmp *icp;
  struct timeval *packtv, currtv;

  ip = (struct ip *) packet;
  hlen = ip->ip_hl << 2;
  if (len < hlen + ICMP_MINLEN) return;

  len -= hlen;
  icp = (struct icmp *)(packet + hlen);

  if (icp->icmp_id != pid) return;

  if ((icp->icmp_type != 0) || (icp->icmp_code != 0)) {
    if (icp->icmp_type != 8) printf("%d bytes from %s: icmp_type=%d (%s) icmp_code=%d icmp_id=%d\n", len,
      inet_ntoa(from->sin_addr), icp->icmp_type, print_type(icp->icmp_type), icp->icmp_code, icp->icmp_id);
    return;
  }

  for (tp = targets; tp; tp = tp->next) {
    if (!strcmp(tp->address, inet_ntoa(from->sin_addr))) break;
  }

  gettimeofday(&currtv, NULL);
  packtv = (struct timeval *)icp->icmp_data;
  currtv = tvsub(currtv, *packtv);
  r = currtv.tv_sec * 1000;
  r += currtv.tv_usec / 1000;

  tp->rttsum += r;
  if (r < tp->rttmin) tp->rttmin = r;
  if (r > tp->rttmax) tp->rttmax = r;
  if (icp->icmp_seq == tp->waitping) tp->waitping = 0;

  printf("%c  %-25.25s %-15s %4d ms  (%4d/%4d/%4d)\n", tp->id, tp->hostname, tp->address, r, tp->rttmin,
    tp->rttsum/pinground, tp->rttmax);
}

char *print_type(int t) {
  static char *ttab[] = {
                "Echo Reply",
                "ICMP 1",
                "ICMP 2",
                "Dest Unreachable",
                "Source Quench",
                "Redirect",
                "ICMP 6",
                "ICMP 7",
                "Echo",
                "ICMP 9",
                "ICMP 10",
                "Time Exceeded",
                "Parameter Problem",
                "Timestamp",
                "Timestamp Reply",
                "Info Request",
                "Info Reply"
  };

  if ((t < 0) || (t > 16)) return("OUT-OF-RANGE");

  return ttab[t];
}

int read_targets(void) {
  char buf[LINEBUF+1], *tmp2;
  target *t, *tmp;
  struct addrinfo hints, *res = NULL;
  FILE *fp = NULL;

  if (!(fp = fopen(TARGETSFILE, "r"))) {
    perror("fopen()");
    return -1;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_INET;

  while (fgets(buf, LINEBUF, fp)) {
    strtok(buf, " \n");
    if (!buf) {
      fprintf(stderr, "Syntax error in targets file\n");
      return -1;
    }
    if (getaddrinfo(buf, NULL, &hints, &res)) {
      fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(errno));
      return -1;
    }
    if (!(t = (target *)malloc(sizeof(target)))) {
      perror("malloc()");
      return -1;
    }
    memset(t, 0, sizeof(target));
    if (!(t->addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in)+1))) {
      perror("malloc()");
      return -1;
    }
    t->id = IDSEQUENCE[ntargets];
    if (!t->id) t->id = '?';
    memset(t->addr, 0, sizeof(struct sockaddr_in));
    strncpy(t->hostname, res->ai_canonname, HOSTLEN);
    memcpy(t->addr, res->ai_addr, sizeof(struct sockaddr_in));
    strncpy(t->address, inet_ntoa(t->addr->sin_addr), 15);
    t->rttmin = -1;
    tmp2 = strtok(NULL, "\n");
    if (tmp2) {
      if (!(t->comment = (char *)malloc(strlen(tmp2)+1))) {
        perror("malloc()");
        return -1;
      }
      strcpy(t->comment, tmp2);
    }
    freeaddrinfo(res);

    if (!targets) targets = t;
    else {
      for (tmp = targets; tmp->next; tmp = tmp->next);
      tmp->next = t;
    }
    ntargets++;
  }

  for (tmp = targets; tmp; tmp = tmp->next) {
    if (tmp->comment) printf("%c %s (%s) \"%s\"\n", tmp->id, tmp->hostname, tmp->address, tmp->comment);
    else printf("%c %s (%s)\n", tmp->id, tmp->hostname, tmp->address);
  }

  return 0;
}

void send_ping(target *t) {
  int len = sizeof(struct icmp) + sizeof(struct timeval);
  u_char packet[len+1];
  struct icmp *icp = (struct icmp *) packet;
  struct timeval *tp = (struct timeval *) &packet[8];

  icp->icmp_type = ICMP_ECHO;
  icp->icmp_code = 0;
  icp->icmp_id = pid;
  icp->icmp_cksum = 0;
  icp->icmp_seq = pinground;

  gettimeofday(tp, NULL);

  icp->icmp_cksum = calc_checksum(icp, len);

  if ((sendto(sock, packet, len, 0, (struct sockaddr *)t->addr, sizeof(struct sockaddr))) <= 0) perror("sendto()");
}

u_short calc_checksum(struct icmp *addr, int len) {
  int nleft = len;
  u_short *w = (u_short *)addr;
  u_short answer;
  int sum = 0;

  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    u_short u = 0;

    *(u_char *)(&u) = *(u_char *)w;
    sum += u;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}
