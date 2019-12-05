#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <ncurses.h>
#include <netdb.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/prctl.h>		// debug

#define INITWAIT	5		/* Seconds to show initialisation messages before going visual */
#define GRIDMARK	'+'
#define TARGETSFILE	"targets"
#define INTERVAL	60
#define HISTLOG		100		/* Number of intervals to keep full data from in memory */
#define SCROLLSIZE	6
#define LINEBUF		512
#define HOSTLEN		64
#define MAXPACKET	4096		/* max packet size */
#define IDSEQUENCE	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define LEARNROUNDS	5		/* number of INTERVALS to wait before marking any result as lagged */
#define JITMULT		3		/* Sensitive: 2 */
#define LAGMULT		10		/* Sensitive: 10 */
#define LAGMIN		8		/* Currently unused */

#define STATE_OK	3
#define STATE_JIT	4
#define STATE_LAG	5
#define STATE_LOSS	6

#define HTMLHEAD1	"<HTML>\n<HEAD>\n<TITLE>Ping stats</TITLE>\n<STYLE type=\"text/css\">\n"
#define HTMLHEAD2	"BODY { background-color: black; color: rgb(200,200,200) }\n"
#define HTMLHEAD3	"TABLE { text-align: center }\n"
#define HTMLHEAD8	"TABLE#results TH { color: black; background-color: rgb(200,200,200); width: 1em }\n"
#define HTMLHEAD4	"TABLE#results TD { color: black; background-color: green; width: 1em }\n"
#define HTMLHEAD5	"TABLE#results TD.j { background-color: yellow }\n"
#define HTMLHEAD6	"TABLE#results TD.d { background-color: blue }\n"
#define HTMLHEAD7	"TABLE#results TD.l { background-color: red }\n"
#define HTMLHEAD9	"</STYLE></HEAD>\n\n<BODY>\n"

typedef struct pingdata {
  unsigned int rtt;
  int color;
} pingdata;

typedef struct passdata {
  time_t time;
  pingdata *data;
} passdata;

passdata *histlog;
int currlog = 0;

typedef struct logdata {
  unsigned int count;
  unsigned int rttmin;
  unsigned int rttavg;
  unsigned int rttmax;
  unsigned int delaycount;
  unsigned int losscount;
  unsigned int okavg;
  float stddev;
} logdata;

typedef struct target {
  int num;
  char id;
  char hostname[HOSTLEN+1];
  char address[16];
  struct sockaddr_in *addr;
  int rank;
  int detached;
  int lastcolor;
  int treecolor;
  int beepmode;		// 0 = normal, 1 = reverse, 2 = off
  unsigned long rttsum;
  unsigned long oksum;
  unsigned long sqsum;
  unsigned int rttavg;
  unsigned int okavg;
  unsigned int rttmin;
  unsigned int rttmax;
  unsigned int rttlast;
  unsigned int okcount;
  unsigned int delaycount;
  unsigned int losscount;
  time_t downsince;
  char *comment;
  struct target *next;
  int waitping;
} target;

target *targets;

int pid;
int sock;
int ntargets = 0, ndown = 0;
int pinground = 0;
int rows, cols, gotwinch = 0;
int msinterval, maxwidth = 0, ndetach = 0;
int showdown = 1, showtree = 1;
char showinfo = '\0';

target *currtarget = NULL;

struct timeval nexttv, tvinterval;

WINDOW *header, *footer, *status, *grid, *scroller, *hostinfo, *tree, *downlist;

FILE *htmlout = NULL;

int open_socket(void);
struct timeval check_timers(void);
int tvcmp(struct timeval, struct timeval);
struct timeval tvsub(struct timeval, struct timeval);
struct timeval tvadd(struct timeval, struct timeval);
void read_socket(int);
void print_packet(char *, int, struct sockaddr_in *);
char *print_type(int);
int read_targets(void);
void send_ping(target *);
u_short calc_checksum(struct icmp *, int);
void start_curses(void);
void draw_border(WINDOW *, char *);
void print_scroll(char *, ...);
void print_status(char *, ...);
void print_tree(void);
void print_info(void);
void print_down(void);
void update_screen(int);
logdata *get_logdata(int);
char *itoa(int);
char *itodur(int);
void sig_winch(int);
void got_winch(void);
WINDOW *resize_win(WINDOW *, int, int, int, int, int);
void do_exit(int sig);

int main(int argc, char *argv[]) {
  int c, r;
  char *cp, *idp = IDSEQUENCE;
  target *tp;
  fd_set fdmask;
  struct timeval timeout;

  if (open_socket() == -1) exit(-1);

  setuid(getuid()); // Drop root privileges, we don't need them anymore.

  prctl(PR_SET_DUMPABLE, 1); // debug

  pid = getpid();

  signal(SIGHUP, do_exit);
  signal(SIGINT, do_exit);
  signal(SIGTERM, do_exit);
//  signal(SIGWINCH, sig_winch); // while debugging

  if (argc == 2) {
    printf("HTML output file: %s\n", argv[1]);
    if (!(htmlout = fopen(argv[1], "w"))) {
      perror("fopen()");
      exit(-2);
    }
    fputs(HTMLHEAD1, htmlout);
    fputs(HTMLHEAD2, htmlout);
    fputs(HTMLHEAD3, htmlout);
    fputs(HTMLHEAD4, htmlout);
    fputs(HTMLHEAD5, htmlout);
    fputs(HTMLHEAD6, htmlout);
    fputs(HTMLHEAD7, htmlout);
    fputs(HTMLHEAD8, htmlout);
    fputs(HTMLHEAD9, htmlout);
  }

  if (read_targets() == -1) exit(-3);

  histlog = (passdata *)malloc(sizeof(passdata)*HISTLOG);
  if (!histlog) {
    printf("Error allocating memory for history log; system out of memory?\n");
    exit(-4);
  }
  memset(histlog, 0, sizeof(passdata)*HISTLOG);
  for (c = 0; c < HISTLOG; c++) {
    histlog[c].data = (pingdata *)malloc(sizeof(pingdata)*ntargets);
    if (!histlog[c].data) {
      printf("Error allocating memory for histlog; system out of memory?\n");
      exit(-5);
    }
    memset(histlog[c].data, 0, sizeof(pingdata)*ntargets);
  }

  printf("Data storage for history log initialised (%d bytes)\n", sizeof(passdata)*HISTLOG*sizeof(pingdata)*ntargets);

  memset(&nexttv, 0, sizeof(struct timeval));

  msinterval = INTERVAL*1000/ntargets;
  tvinterval.tv_sec = INTERVAL/ntargets;
  tvinterval.tv_usec = INTERVAL*1000000/ntargets%1000000;

  printf("Ping timeout is %d milliseconds\n", msinterval);
  printf("Ping throughput is %d pings per minute\n", INTERVAL/60*ntargets);

  printf("Initialisation complete, starting in %d", INITWAIT?INITWAIT:1);
  fflush(stdout);
  sleep(1);
  for (c = INITWAIT-1; c; c--) {
    printf("\b%d", c);
    fflush(stdout);
    sleep(1);
  }
  printf("\b0\n");

  if (htmlout) {
    fputs("<HR>\n<TABLE id=\"results\">\n<THEAD>\n<TR><TH>Time\n", htmlout);
    for (tp = targets; tp; tp = tp->next) fprintf(htmlout, "<TH title=\"%s\">%c\n", tp->hostname, tp->id);
    fputs("<TBODY>\n", htmlout);
  }

  start_curses();

  while (1) {
    if (gotwinch) got_winch();

    FD_ZERO(&fdmask);
    FD_SET(0, &fdmask);
    FD_SET(sock, &fdmask);

    timeout = check_timers();

    r = select(sock+1, &fdmask, 0, 0, &timeout);
    if (r == -1) {
      if (errno == EINTR) continue;
      perror("select()");
      abort();	// debug
    }
    if (FD_ISSET(sock, &fdmask)) read_socket(sock);
    if (FD_ISSET(0, &fdmask)) {
      if ((r = getc(stdin)) == EOF) {
        perror("getc(stdin)");
        exit(-7);
      }
      r = toupper(r);
      if (r == '\r') {
        if (showdown && ndown) showdown = 0;
        else if (showdown == 2) showdown = 1;
        else if (ndown) {
          showdown = 1;
          print_down();
        }
        else showdown = 2;
      }
      else if (r == ' ') {
        if (showtree) {
          showtree = 0;
          mvwin(downlist, 1, cols-40);
        }
        else {
          showtree = 1;
          mvwin(downlist, 1, cols-40-(maxwidth+5));
        }
      }
      else if (r == showinfo) showinfo = '\0';
      else if (((cp = strchr(idp, r))) && (cp-idp < ntargets)) {
        showinfo = r;
        print_info();
      }
      else if ((r == '!') && showinfo) {
        for (tp = targets; tp; tp = tp->next) {
          if (tp->id == showinfo) break;
        }
        if (tp->beepmode++ == 2) tp->beepmode = 0;
        print_info();
      }
      update_screen('f');
    }
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
  int ellsum = 0;
  static int ell = 0;
  char timebuf[10];
  target *tp;
  time_t now;
  struct tm *currtm;
  struct timeval currtv, temptv;

  gettimeofday(&currtv, NULL);

  if (tvcmp(currtv, nexttv) < 0) return tvsub(nexttv, currtv);

  now = time(NULL);
  currtm = localtime(&now);

  if (currtarget) {
    if (currtarget->waitping) {
      waddch(grid, '\b');
      waddch(grid, GRIDMARK|COLOR_PAIR(STATE_LOSS));
      wattron(scroller, COLOR_PAIR(STATE_LOSS));
      print_scroll("%c  %-30.30s %-15s >%4d ms  (timeout)", currtarget->id, currtarget->hostname, currtarget->address,
        msinterval);
      currtarget->losscount++;
      if (!currtarget->beepmode) beep();
      if (!currtarget->downsince) currtarget->downsince = now;
      if ((currtarget->lastcolor == STATE_LOSS) && (currtarget->treecolor != STATE_LOSS)) {
        currtarget->treecolor = STATE_LOSS;
        print_tree();
        ndown++;
        if (showdown) print_down();
      }
      histlog[currlog].data[currtarget->num].rtt = -1;
      histlog[currlog].data[currtarget->num].color = STATE_LOSS;
      currtarget->lastcolor = STATE_LOSS;
      if (currtarget->id == showinfo) print_info();
      if (htmlout) fputs("<TD class=\"l\">lost\n", htmlout);
    }
    currtarget = currtarget->next;
  }
  if (!currtarget) {
    currtarget = targets;
    pinground++;
    snprintf(timebuf, 9, "\n[%02d:%02d] ", currtm->tm_hour, currtm->tm_min);
    waddstr(grid, timebuf);
    if (showdown && ndown) print_down();
    if (htmlout) {
      if (!(pinground%30)) {
        fputs("<TR>\n<TH>Time\n", htmlout);
        for (tp = targets; tp; tp = tp->next) fprintf(htmlout, "<TH title=\"%s\">%c\n", tp->hostname, tp->id);
      }
      fflush(htmlout);
      fprintf(htmlout, "<TR><TD>%02d:%02d\n", currtm->tm_hour, currtm->tm_min);
    }
    if (pinground > 1) {
      for (tp = targets; tp; tp = tp->next) ellsum += tp->rttlast - tp->rttmin;
      ell = ellsum / ntargets;
    }
    if (++currlog == HISTLOG) currlog = 0;
    histlog[currlog].time = now;
  }

  waddch(grid, ' ');
  waddch(grid, GRIDMARK);
  currtarget->waitping = pinground;

  print_status("Ping round %d / Monitoring %d hosts / Estimated local latency: %d ms", pinground, ntargets, ell);

  update_screen('a');

  send_ping(currtarget);

  memcpy(&temptv, &currtv, sizeof(struct timeval));
  gettimeofday(&currtv, NULL);
  temptv = tvsub(currtv, temptv);       // time lost in function
  temptv = tvsub(tvinterval, temptv);   // interval minus drift correction
  nexttv = tvadd(currtv, temptv);       // next time function needs to run
  return temptv;                        // timeout for select()
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
    r.tv_sec = 0;
    r.tv_usec = 0;
  }
  return r;
}

struct timeval tvadd(struct timeval left, struct timeval right) {
  struct timeval r;

  r.tv_sec = left.tv_sec + right.tv_sec;
  r.tv_usec = left.tv_usec + right.tv_usec;
  if (r.tv_usec > 1000000) {
    r.tv_sec++;
    r.tv_usec -= 1000000;
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
  int r, hlen, ampl;
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
    if (icp->icmp_type != 8) print_scroll("%d bytes from %s: icmp_type=%d (%s) icmp_code=%d icmp_id=%d", len,
      inet_ntoa(from->sin_addr), icp->icmp_type, print_type(icp->icmp_type), icp->icmp_code, icp->icmp_id);
    return;
  }

  for (tp = targets; tp; tp = tp->next) {
    if (!strcmp(tp->address, inet_ntoa(from->sin_addr))) break;
  }
  if (!tp) return;

  gettimeofday(&currtv, NULL);
  packtv = (struct timeval *)icp->icmp_data;
  currtv = tvsub(currtv, *packtv);
  r = currtv.tv_sec * 1000;
  r += currtv.tv_usec / 1000;

  if ((tp == currtarget) && (icp->icmp_seq == tp->waitping)) {
    tp->waitping = 0;
    tp->rttlast = r;
    tp->rttsum += r;
    tp->rttavg = tp->rttsum / (icp->icmp_seq - tp->losscount);
    tp->sqsum += powf(r,2);
    if (r < tp->rttmin) tp->rttmin = r;
    if (r > tp->rttmax) tp->rttmax = r;
    if (!tp->okcount) tp->okavg = tp->rttavg;
    ampl = tp->okavg - tp->rttmin;
    histlog[currlog].data[tp->num].rtt = r;

    waddch(grid, '\b');
    if (tp->treecolor == STATE_LOSS) {
      tp->downsince = 0;
      ndown--;
    }
    if ((pinground <= LEARNROUNDS) || (r <= tp->okavg+JITMULT*(ampl?ampl:1))) {
      waddch(grid, GRIDMARK|COLOR_PAIR(STATE_OK));
      wattron(scroller, COLOR_PAIR(STATE_OK));
      if ((tp->lastcolor >= STATE_OK) && (tp->treecolor != STATE_OK)) {
        tp->treecolor = STATE_OK;
        print_tree();
      }
      tp->lastcolor = STATE_OK;
      tp->okcount++;
      tp->oksum += r;
      tp->okavg = tp->oksum/tp->okcount;
      if (htmlout) fprintf(htmlout, "<TD>%d\n", r);
      histlog[currlog].data[tp->num].color = STATE_OK;
    }
//    else if ((r <= LAGMULT*tp->rttmin) || (r <= LAGMIN)) {
    else if (r <= tp->okavg+LAGMULT*(ampl?ampl:1)) {
      waddch(grid, GRIDMARK|COLOR_PAIR(STATE_JIT));
      wattron(scroller, COLOR_PAIR(STATE_JIT));
      if ((tp->lastcolor >= STATE_JIT) && (tp->treecolor != STATE_JIT)) {
        tp->treecolor = STATE_JIT;
        print_tree();
      }
      tp->lastcolor = STATE_JIT;
      if (htmlout) fprintf(htmlout, "<TD class=\"j\">%d\n", r);
      histlog[currlog].data[tp->num].color = STATE_JIT;
    }
    else {
      waddch(grid, GRIDMARK|COLOR_PAIR(STATE_LAG));
      wattron(scroller, COLOR_PAIR(STATE_LAG));
      tp->delaycount++;
      if ((tp->lastcolor >= STATE_LAG) && (tp->treecolor != STATE_LAG)) {
        tp->treecolor = STATE_LAG;
        print_tree();
      }
      tp->lastcolor = STATE_LAG;
      if (htmlout) fprintf(htmlout, "<TD class=\"d\">%d\n", r);
      histlog[currlog].data[tp->num].color = STATE_LAG;
    }
    update_screen('g');
    if (tp->beepmode == 1) beep();
  }
  else if (icp->icmp_seq != tp->waitping) {
    wattron(scroller, COLOR_PAIR(STATE_LOSS));
    print_scroll("%c  %-30.30s %-15s %5d ms  (out of sync)", currtarget->id, currtarget->hostname, currtarget->address, r);
    return;
  }
  else {
    tp->rttlast = r;
    ampl = tp->okavg - tp->rttmin;
    wattron(scroller, COLOR_PAIR(STATE_LOSS));
  }

  if (tp->id == showinfo) print_info();

  print_scroll("%c  %-30.30s %-15s  %4d ms  (baseline %3d Â± %2d)", tp->id, tp->hostname, tp->address, r, tp->okavg, ampl);
  update_screen('s');
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
  int r, rank, detached = 0;
  char buf[LINEBUF+1], *tmp2;
  target *t, *tmp;
  struct addrinfo hints, *res = NULL;
  FILE *fp = NULL;

  if (!(fp = fopen(TARGETSFILE, "r"))) {
    perror("fopen()");
    return -1;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_INET;

  if (htmlout) fputs("<TABLE><TR><TD>ID<TD>Hostname<TD>IP address<TD>Comment\n", htmlout);

  while (fgets(buf, LINEBUF, fp)) {
    for (rank = 0; buf[rank] == ' '; rank++);
    if (!buf[rank]) return -1;
    if (buf[rank] == '\n') {
      detached = 1;
      continue;
    }
    strtok(&buf[rank], " \n");
    if ((r = getaddrinfo(&buf[rank], NULL, &hints, &res))) {
      fprintf(stderr, "- %s getaddrinfo(): %s\n", &buf[rank], gai_strerror(r));
      continue;
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
    if ((r = getnameinfo(res->ai_addr, sizeof(struct sockaddr), t->hostname, HOSTLEN, NULL,0,0))) {
      fprintf(stderr, "- %s getnameinfo(): %s\n", &buf[rank], gai_strerror(r));
      continue;
    }
    t->num = ntargets;
    t->id = IDSEQUENCE[ntargets];
    if (!t->id) t->id = '?';
    t->rank = rank;
    t->detached = detached;
    if (detached) ndetach++;
    memset(t->addr, 0, sizeof(struct sockaddr_in));
    memcpy(t->addr, res->ai_addr, sizeof(struct sockaddr_in));
    strncpy(t->address, inet_ntoa(t->addr->sin_addr), 15);
    t->rttmin = -1;
    t->lastcolor = 99;
    tmp2 = strtok(NULL, "\n");
    if (tmp2) {
      if (!(t->comment = (char *)malloc(strlen(tmp2)+1))) {
        perror("malloc()");
        return -1;
      }
      strcpy(t->comment, tmp2);
      if (2*rank+strlen(tmp2)+1 > maxwidth) maxwidth = 2*rank+strlen(tmp2)+1;
    }
    else if (2*rank > maxwidth) maxwidth = 2*rank;

    freeaddrinfo(res);

    if (!targets) targets = t;
    else {
      for (tmp = targets; tmp->next; tmp = tmp->next);
      tmp->next = t;
    }
    ntargets++;
    detached = 0;

    if (t->comment) {
      printf("%c %s (%s) %s\n", t->id, t->hostname, t->address, t->comment);
      if (htmlout) fprintf(htmlout, "<TR><TD>%c<TD>%s<TD>%s<TD>%s\n", t->id, t->hostname, t->address, t->comment);
    }
    else {
      printf("%c %s (%s)\n", t->id, t->hostname, t->address);
      if (htmlout) fprintf(htmlout, "<TR><TD>%c<TD>%s<TD>%s\n", t->id, t->hostname, t->address);
    }
  }

  if (htmlout) fputs("</TABLE>\n", htmlout);

  if (!ntargets) return -1;

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

void start_curses(void) {
  int c, x, y;

  initscr();
  cbreak();
  noecho();
  curs_set(0);

  start_color();
  init_pair(1, COLOR_WHITE, COLOR_BLACK);
  init_pair(2, COLOR_WHITE, COLOR_BLUE);
  init_pair(STATE_OK, COLOR_GREEN, COLOR_BLACK);
  init_pair(STATE_JIT, COLOR_YELLOW, COLOR_BLACK);
  init_pair(STATE_LAG, COLOR_BLUE, COLOR_BLACK);
  init_pair(STATE_LOSS, COLOR_RED, COLOR_BLACK);

  init_pair(7, COLOR_MAGENTA, COLOR_BLACK);
  init_pair(8, COLOR_CYAN, COLOR_BLACK);

  getmaxyx(stdscr, rows, cols);
  if ((cols < 72) || (rows < 16)) {
    noraw();
    echo();
    endwin();
    fprintf(stderr, "This program requires at least a 16*72 character display, yours has %d*%d\n", rows, cols);
    exit(-17);
  }

  header = newwin(1, cols, 0, 0);
  grid = newwin(rows-SCROLLSIZE-3, cols, 1, 0);
  footer = newwin(1, cols, rows-SCROLLSIZE-2, 0);
  scroller = newwin(SCROLLSIZE, cols, rows-SCROLLSIZE-1, 0);
  status = newwin(1, cols, rows-1, 0);
  hostinfo = newwin(15, 51, (rows-15)/2, (cols-51)/2);
  tree = newwin(ntargets+ndetach+2, maxwidth+5, 1, cols-(maxwidth+5));
  downlist = newwin(2, 40, 1, cols-40-(maxwidth+5));

  if (!header || !grid || !footer || !scroller || !status || !hostinfo) {
    noraw();
    echo();
    endwin();
    fprintf(stderr, "Error initialising windows\n");
    exit(-18);
  }

  leaveok(grid, TRUE);
  scrollok(grid, TRUE);
  leaveok(scroller, TRUE);
  scrollok(scroller, TRUE);
  leaveok(status, TRUE);

  wattron(header, COLOR_PAIR(5));
  wattron(footer, COLOR_PAIR(5));
  for (c = 0; c < 7; c++) {
    waddch(header, ACS_HLINE);
    waddch(footer, ACS_HLINE);
  }
  wattron(header, COLOR_PAIR(1));
  wattron(footer, COLOR_PAIR(1));
  for (c = 0; c < ntargets; c++) {
    waddch(header, ' ');
    waddch(footer, ' ');
    waddch(header, IDSEQUENCE[c]);
    waddch(footer, IDSEQUENCE[c]);
  }
  waddch(header, ' ');
  waddch(footer, ' ');
  wattron(header, COLOR_PAIR(5));
  wattron(footer, COLOR_PAIR(5));
  getyx(header, y, x);
  for (; x < cols; x++) {
    waddch(header, ACS_HLINE);
    waddch(footer, ACS_HLINE);
  }

  draw_border(downlist, " Hosts down ");
  if (maxwidth >= 12) draw_border(tree, " Network Map ");
  else draw_border(tree, " Map ");
  wattron(tree, COLOR_PAIR(5));
  print_tree();
  update_screen('h');

  for (c = 0; c < SCROLLSIZE; c++) waddch(scroller, '\n');
  for (c = 0; c < rows-SCROLLSIZE; c++) waddch(grid, '\n');
//  if (has_colors()) print_scroll("Terminal supports colors");
//  if (can_change_color()) print_scroll("Terminal can change color definitions");
}

void draw_border(WINDOW *win, char *title) {
  int c, x, y;

  getmaxyx(win, y, x);			// getmaxyx returns the number of available cols/rows
  if ((x-- < 2) || (y-- < 2)) return;	// -- them to get the correct index for use in wmove()

  wattron(win, COLOR_PAIR(5));
  wmove(win, 0, 0);
  waddch(win, ACS_ULCORNER);
  for (c = 1; c < x; c++) waddch(win, ACS_HLINE);
  waddch(win, ACS_URCORNER);
  for (c = 1; c < y; c++) {
    wmove(win, c, 0);
    waddch(win, ACS_VLINE);
    wmove(win, c, x);
    waddch(win, ACS_VLINE);
  }
  wmove(win, y, 0);
  waddch(win, ACS_LLCORNER);
  for (c = 1; c < x; c++) waddch(win, ACS_HLINE);
  waddch(win, ACS_LRCORNER);

  wattron(win, COLOR_PAIR(1));
  if (!title || ((c = strlen(title)) > (++x)-2)) return;

  wmove(win, 0, (x-c)/2);
  waddstr(win, title);
}  

void print_scroll(char *fmt, ...) {
  char buf[cols+1];
  va_list arglist;

  va_start(arglist, fmt);
  vsnprintf(buf, cols, fmt, arglist);
  va_end(arglist);

  waddch(scroller, '\n');
  waddstr(scroller, buf);
  wclrtoeol(scroller);
}

void print_status(char *fmt, ...) {
  int c, x, y;
  char buf[cols+1];
  va_list arglist;

  va_start(arglist, fmt);
  vsnprintf(buf, cols, fmt, arglist);
  va_end(arglist);

  wmove(status, 0, 0);
  wattron(status, COLOR_PAIR(5));
  for (c = 0; c < 7; c++) waddch(status, ACS_HLINE);
  wattron(status, COLOR_PAIR(1));
  waddch(status, ' ');
  for (c = 0; buf[c]; c++) {
    if (buf[c] == '/') waddch(status, ACS_HLINE|COLOR_PAIR(5));
    else waddch(status, buf[c]);
  }
  waddch(status, ' ');
  wattron(status, COLOR_PAIR(5));
  getyx(status, y, x);
  for (; x < cols; x++) waddch(status, ACS_HLINE);
}

void print_tree(void) {
  int c, d, n, more, nextrank, detach1 = 0, detach2;
  char *cp;
  target *t1, *t2, *t3;

  wmove(tree, 1, 2);
  for (n = 0, t1 = targets; t1; n++, t1 = t1->next) {
    wmove(tree, n+1+detach1, 2*t1->rank+2);
    switch (t1->treecolor) {
      case 3: waddch(tree, t1->id|COLOR_PAIR(STATE_OK));
              break;
      case 4: waddch(tree, t1->id|COLOR_PAIR(STATE_JIT));
              break;
      case 5: waddch(tree, t1->id|COLOR_PAIR(STATE_LAG));
              break;
      case 6: waddch(tree, t1->id|COLOR_PAIR(STATE_LOSS));
              break;
      default: waddch(tree, t1->id|COLOR_PAIR(1));
    }
    if (t1->comment) {
      waddch(tree, ' ');
      wattron(tree, COLOR_PAIR(1));
      for (cp = t1->comment; *cp; cp++) {
        switch (*cp) {
          case '\'': waddch(tree, ACS_ULCORNER|COLOR_PAIR(5));
                    break;
          case '-': waddch(tree, ACS_HLINE|COLOR_PAIR(5));
                    break;
          case '`': waddch(tree, ACS_URCORNER|COLOR_PAIR(5));
                    break;
          case '|': waddch(tree, ACS_VLINE|COLOR_PAIR(5));
                    break;
          case '\\': waddch(tree, ACS_LLCORNER|COLOR_PAIR(5));
                    break;
          case '/': waddch(tree, ACS_LRCORNER|COLOR_PAIR(5));
                    break;
          default: waddch(tree, *cp);
        }
      }
      wattron(tree, COLOR_PAIR(5));
    }

    for (c = n+1, nextrank = 100, detach2 = detach1, t2 = t1->next; t2; c++, t2 = t2->next, more = 0) {
      if (t2->rank <= t1->rank) break;
      if (t2->detached) {
        wmove(tree, c+1+detach2, 2*t1->rank+2);
        waddch(tree, ACS_VLINE);
        detach2++;
      }
      if (t2->rank < nextrank) nextrank = t2->rank;
      for (t3 = t2->next; t3; t3 = t3->next) {
        if (t3->rank <= t1->rank) break;
        if (t3->rank <= nextrank) more = 1;
      }
      wmove(tree, c+1+detach2, 2*t1->rank+2);
      if (t2->rank <= nextrank) {
        d = (t2->rank-t1->rank)*2-1;
        if (more) waddch(tree, ACS_LTEE);
        else waddch(tree, ACS_LLCORNER);
        while (d--) waddch(tree, ACS_HLINE);
      }
      else if (more) waddch(tree, ACS_VLINE);
      if (!more) break;
    }
    if (t1->next && t1->next->detached) detach1++;
  }
}

void print_info(void) {
  char buf[48];
  float stddev;
  target *tp;
  logdata *ld;

  for (tp = targets; tp; tp = tp->next) {
    if (tp->id == showinfo) break;
  }
  if (!tp || !pinground) return;

  ld = get_logdata(tp->num);

//  print_scroll("get_logdata returned: count = %d / min = %d / avg = %d / max = %d / okavg = %d / delaycount = %d / losscount = %d", ld->count, ld->rttmin, ld->rttavg, ld->rttmax, ld->okavg, ld->delaycount, ld->losscount);

  werase(hostinfo);
  draw_border(hostinfo, " Host info ");

  stddev = sqrtf(tp->sqsum/pinground-pow(tp->rttavg,2));

  if (strlen(tp->hostname)+strlen(tp->address)+5 < 48) snprintf(buf, 48, "%c %s (%s)", tp->id, tp->hostname, tp->address);
  else snprintf(buf, 48, "%c %s", tp->id, tp->hostname);
  mvwaddstr(hostinfo, 1, 2, buf);
  snprintf(buf, 48, "Overall statistics     | Last %d minutes", HISTLOG*INTERVAL/60);
  mvwaddstr(hostinfo, 2, 2, buf);
  snprintf(buf, 48, "Baseline: %5d ± %-4d | %5d ± %-4d", tp->okavg, tp->okavg-tp->rttmin, ld->okavg, ld->okavg-ld->rttmin);
  mvwaddstr(hostinfo, 3, 2, buf);
  snprintf(buf, 48, "Min:          %5d    | %5d", tp->rttmin, ld->rttmin);
  mvwaddstr(hostinfo, 4, 2, buf);
  snprintf(buf, 48, "Avg:          %5d    | %5d", tp->rttavg, ld->rttavg);
  mvwaddstr(hostinfo, 5, 2, buf);
  //if (!stddev)
  snprintf(buf, 47, "Max:          %5d    | %5d", tp->rttmax, ld->rttmax);
  //else snprintf(buf, 48, "Max:          %5d %ds |     x", tp->rttmax, (int)((tp->rttmax-tp->rttavg)/sqrt(tp->varsum/pinground)+1));
  mvwaddstr(hostinfo, 6, 2, buf);
  snprintf(buf, 48, "Last:         %5d", tp->rttlast);
  mvwaddstr(hostinfo, 7, 2, buf);
  snprintf(buf, 48, "Std.Dev.:        %5.2f |    %5.2f", stddev, ld->stddev);
  mvwaddstr(hostinfo, 8, 2, buf);
  snprintf(buf, 48, "Probes delayed: %5.1f%% |   %5.1f%%", tp->delaycount*100.0/pinground, ld->count?ld->delaycount*100.0/ld->count:0.0);
  mvwaddstr(hostinfo, 9, 2, buf);
  snprintf(buf, 48, "Probes lost:    %5.1f%% |   %5.1f%%", tp->losscount*100.0/pinground, ld->count?ld->losscount*100.0/ld->count:0.0);
  mvwaddstr(hostinfo, 10, 2, buf);
  snprintf(buf, 48, "Warning bell: %s", tp->beepmode?tp->beepmode==1?"inverse":"off":"on");
  mvwaddstr(hostinfo, 11, 2, buf);
  snprintf(buf, 48, "Current status: %s", tp->treecolor==STATE_LOSS?"down":"up");
  mvwaddstr(hostinfo, 12, 2, buf);
}

void print_down(void) {
  int ccols, crows, line = 1;
  char buf[48];
  target *tp;

  getmaxyx(downlist, crows, ccols);
  if (crows-2 != ndown) {
    delwin(downlist);
    if (showtree) downlist = newwin(ndown+2, 40, 1, cols-40-(maxwidth+5));
    else downlist = newwin(ndown+2, 40, 1, cols-40);
    draw_border(downlist, " Hosts down ");
  }
  for (tp = targets; tp; tp = tp->next) {
    if (tp->treecolor == STATE_LOSS) {
      snprintf(buf, 48, "%c %-25.25s %s", tp->id, tp->hostname, itodur((int)time(NULL)-tp->downsince));
      mvwaddstr(downlist, line++, 2, buf);
    }
  }
}

void update_screen(int win) {
  switch (win) {
    case 'h': touchwin(header);
              wnoutrefresh(header);
    case 'f': touchwin(footer);
              wnoutrefresh(footer);
    case 'a': touchwin(status);
              wnoutrefresh(status);
    case 'g': touchwin(grid);
              wnoutrefresh(grid);
    case 's': touchwin(scroller);
              wnoutrefresh(scroller);
    case 't': if (showtree) {
                touchwin(tree);
                wnoutrefresh(tree);
              }
    case 'd': if ((showdown == 2) || (showdown && ndown)) {
                touchwin(downlist);
                wnoutrefresh(downlist);
              }
    case 'i': if (showinfo) {
                touchwin(hostinfo);
                wnoutrefresh(hostinfo);
              }
    default:  doupdate();
  }
}

logdata *get_logdata(int num) {
  int i, okcount = 0;
  unsigned int totsum = 0, oksum = 0;
  float sqsum = 0;
  static logdata res;

  memset(&res, 0, sizeof(logdata));
  res.rttmin = -1;

  for (i = 0; i < HISTLOG; i++) {
    if (!histlog[i].data[num].color) {					// Might be current ping round
      if ((++i == HISTLOG) || (!histlog[i].data[num].color)) break;	// or the end of the (used) histlog
    }
    res.count++;
    if (histlog[i].data[num].color == STATE_LOSS) res.losscount++;
    else {
      totsum += histlog[i].data[num].rtt;
      sqsum += powf(histlog[i].data[num].rtt,2);
      if (histlog[i].data[num].rtt < res.rttmin) res.rttmin = histlog[i].data[num].rtt;
      if (histlog[i].data[num].rtt > res.rttmax) res.rttmax = histlog[i].data[num].rtt;
      if (histlog[i].data[num].color == STATE_LAG) res.delaycount++;
      else if (histlog[i].data[num].color != STATE_JIT) {
        oksum += histlog[i].data[num].rtt;
        okcount++;
      }
    }
  };
  if (res.count) res.rttavg = totsum/res.count;
  else res.rttavg = 0;
  if (okcount) res.okavg = oksum/okcount;
  else res.okavg = 0;
  if (sqsum) {		// if sqsum != 0 then there must've been a non-loss result and thus res.count > res.losscount
    res.stddev = sqsum/(res.count-res.losscount);	// preventing a division by zero here
    res.stddev = res.stddev - powf(res.rttavg,2);
    res.stddev = sqrtf(res.stddev);
  }
  else res.stddev = 0;

  return &res;
}

char *itoa(int digits) {
   static char buf[11];
   char *ptr = buf;
   int r, c = 1;

   while (digits/c > 9) c *= 10;
   do {
      r = digits/c;
      *ptr++ = r+48;
      digits -= r*c;
      c /= 10;
   } while (c);
   *ptr = 0;
   return buf;
}

char *itodur(int digits) {
   static char buf[9];
   static int delta[] = { 31449600, 604800, 86400, 3600, 60 };
   static char unit[] = "ywdhm";
   int c, r;
   char *ptr;

   memset(buf, 0, 9);

   if (digits < 60) {
      strcpy(buf, "0m");
      return buf;
   }

   for (c = 0; digits < delta[c]; c++);
   strcpy(buf, itoa(digits/delta[c]));
   ptr = strchr(buf, '\0');
   *ptr = unit[c];
   if ((r = digits%delta[c]) >= 60) {
      *++ptr = ' ';
      strcat(buf, itoa(r/delta[++c]));
      ptr = strchr(buf, '\0');
      *ptr = unit[c];
   }
   return buf;
}

void do_exit(int sig) {
  target *tp;

  close(sock);

  if (htmlout) {
    fputs("</TABLE>\n<HR>\n", htmlout);
    for (tp = targets; tp; tp = tp->next) {
      fputs("<P>\n", htmlout);
      fprintf(htmlout, "%c %s (%s) %s<BR>\n", tp->id, tp->hostname, tp->address, tp->comment?tp->comment:"");
      fprintf(htmlout, "Min: %d / Avg: %d / Max: %d / Last: %d<BR>\n", tp->rttmin, tp->rttavg, tp->rttmax, tp->rttlast);
      fprintf(htmlout, "Packets lost: %d (%d%%) / Packets delayed: %d (%d%%)\n", tp->losscount,
        tp->losscount*100/pinground, tp->delaycount, tp->delaycount*100/pinground);
      fputs("</P>", htmlout);
    }
    fputs("\n</BODY>\n</HTML>\n", htmlout);
  }

  noraw();
  echo();
  endwin();

  exit(0);
}

void sig_winch(int sig) {
  gotwinch = 1;
}

void got_winch(void) {
  struct winsize w;

  if (ioctl(1, TIOCGWINSZ, &w) == -1) {
    perror("ioctl()");
    return;
  }
  if ((w.ws_row == rows) && (w.ws_col == cols)) return;
  rows = w.ws_row;
  cols = w.ws_col;

  resizeterm(rows, cols);
  header = resize_win(header, 1, cols, 0, 0, 1);
  grid = resize_win(grid, rows-SCROLLSIZE-3, cols, 1, 0, 7);
  footer = resize_win(footer, 1, cols, rows-SCROLLSIZE-2, 0, 1);
  scroller = resize_win(scroller, SCROLLSIZE, cols, rows-SCROLLSIZE-1, 0, 7);
  status = resize_win(status, 1, cols, rows-1, 0, 1);
  mvwin(hostinfo, (rows-10)/2, (cols-50)/2);
  mvwin(tree, 1, cols-(maxwidth+5));
  if (showtree) mvwin(downlist, 1, cols-40);
  else mvwin(downlist, 1, cols-40-(maxwidth+5));

  leaveok(grid, TRUE);
  scrollok(grid, TRUE);
  leaveok(scroller, TRUE);
  scrollok(scroller, TRUE);
  leaveok(status, TRUE);

  clearok(curscr, TRUE);
  update_screen('h');
  gotwinch = 0;
}

/**********
 * anchor *
 * 1 2 3  *
 * 4 5 6  *
 * 7 8 9  *
 **********/
WINDOW *resize_win(WINDOW *win, int newy, int newx, int begy, int begx, int anchor) {
  int cury, curx, startrow, startcol;
  WINDOW *tmp;

  getmaxyx(win, cury, curx);

  if (cury > newy) {
    if (anchor <= 3) startrow = 0;
    else if (anchor >= 7) startrow = cury-newy;
    else startrow = (cury-newy)/2;
  }
  else if (cury < newy) {
    if (anchor <= 3) startrow = 0;
    else if (anchor >= 7) startrow = newy-cury;
    else startrow = (newy-cury)/2;
  }
  else startrow = 0;

  if (curx > newx) {
    if (anchor%3 == 1) startcol = 0;
    else if (anchor%3 == 0) startcol = curx-newx;
    else startcol = (curx-newx)/2;
  }
  else if (curx < newx) {
    if (anchor%3 == 1) startcol = 0;
    else if (anchor%3 == 0) startcol = newx-curx;
    else startcol = (newx-curx)/2;
  }
  else startcol = 0;

  tmp = newwin(newy, newx, begy, begx);
  copywin(win, tmp, startrow, startcol, 0, 0, cury, curx, FALSE);
  delwin(win);
  win = tmp;
}
