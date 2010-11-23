#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <sys/select.h>
#include <ncurses.h>
#include <time.h>
#include <signal.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

//#include <sys/param.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/file.h>
//#include <netinet/in_systm.h>
//#include <netinet/in.h>
//#include <netinet/ip.h>

#define GRIDMARK	'+'
#define TARGETSFILE	"targets"
#define INTERVAL	60
#define SCROLLSIZE	6
#define LINEBUF		512
#define HOSTLEN		64
#define MAXPACKET	4096		/* max packet size */
#define IDSEQUENCE	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

#define HTMLHEAD1	"<HTML>\n<HEAD>\n<TITLE>Ping stats</TITLE>\n<STYLE type=\"text/css\">\n"
#define HTMLHEAD2	"BODY { background-color: black; color: rgb(200,200,200) }\n"
#define HTMLHEAD3	"TABLE { text-align: center }\n"
#define HTMLHEAD8	"TABLE#results TH { color: black; background-color: rgb(200,200,200); width: 1em }\n"
#define HTMLHEAD4	"TABLE#results TD { color: black; background-color: green; width: 1em }\n"
#define HTMLHEAD5	"TABLE#results TD.j { background-color: yellow }\n"
#define HTMLHEAD6	"TABLE#results TD.d { background-color: blue }\n"
#define HTMLHEAD7	"TABLE#results TD.l { background-color: red }\n"
#define HTMLHEAD9	"</STYLE></HEAD>\n\n<BODY>\n"

typedef struct target {
  char id;
  char hostname[HOSTLEN+1];
  char address[16];
  struct sockaddr_in *addr;
  int rank;
  int detached;
  int lastcolor;
  int treecolor;
  unsigned long rttsum;
  unsigned int rttavg;
  unsigned int rttmin;
  unsigned int rttmax;
  unsigned int rttlast;
  unsigned int losscount;
  unsigned int delaycount;
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
int rows, cols;
int msinterval, maxrank;
int showdown = 1, showtree = 1;
char showinfo = '\0';

target *currtarget = NULL;

struct timeval nexttv;

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
char *itoa(int);
char *itodur(int);
void do_exit(int sig);

int main(int argc, char *argv[]) {
  int c;
  target *tp;

  memset(&nexttv, 0, sizeof(struct timeval));

  pid = getpid();

  if (open_socket() == -1) exit(-1);

  setuid(getuid()); // Drop root privileges, we don't need them anymore.

  signal(SIGHUP, do_exit);
  signal(SIGINT, do_exit);
  signal(SIGTERM, do_exit);

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

  msinterval = INTERVAL*1000/ntargets;

  sleep(2);

  if (htmlout) {
    fputs("<HR>\n<TABLE id=\"results\">\n<THEAD>\n<TR><TH>Time\n", htmlout);
    for (tp = targets; tp; tp = tp->next) fprintf(htmlout, "<TH title=\"%s\">%c\n", tp->hostname, tp->id);
    fputs("<TBODY>\n", htmlout);
  }

  start_curses();

  while (1) {
    int r;
    char *cp, *idp = IDSEQUENCE;
    fd_set fdmask;
    struct timeval timeout;

    FD_ZERO(&fdmask);
    FD_SET(0, &fdmask);
    FD_SET(sock, &fdmask);

    timeout = check_timers();

    r = select(sock+1, &fdmask, 0, 0, &timeout);
    if (r == -1) {
      if (errno == EINTR) continue;
      perror("select()");
      exit(-3);
    }
    if (FD_ISSET(0, &fdmask)) {
      if ((r = getc(stdin)) == EOF) {
        perror("getc(stdin)");
        exit(-4);
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
          mvwin(downlist, 1, cols-40-(2*maxrank+5));
        }
      }
      else if (r == showinfo) showinfo = '\0';
      else if (((cp = strchr(idp, r))) && (cp-idp < ntargets)) {
        showinfo = r;
        print_info();
      }
      update_screen('f');
    }
    if (FD_ISSET(sock, &fdmask)) read_socket(sock);
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
  struct timeval currtv;

  gettimeofday(&currtv, NULL);

  if (tvcmp(currtv, nexttv) < 0) return tvsub(nexttv, currtv);

  now = time(NULL);
  currtm = localtime(&now);

  if (currtarget) {
    if (currtarget->waitping) {
      waddch(grid, '\b');
      waddch(grid, GRIDMARK|COLOR_PAIR(6));
      wattron(scroller, COLOR_PAIR(6));
      print_scroll("%c  %-30.30s %-15s >%4d ms  (timeout)", currtarget->id, currtarget->hostname, currtarget->address,
        msinterval);
      currtarget->losscount++;
      if (!currtarget->downsince) currtarget->downsince = time(NULL);
      if ((currtarget->lastcolor == 6) && (currtarget->treecolor != 6)) {
        currtarget->treecolor = 6;
        print_tree();
        ndown++;
        if (showdown) print_down();
      }
      if (currtarget->id == showinfo) print_info();
      currtarget->lastcolor = 6;
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
      if (!pinground%30) {
        fputs("<TR>\n", htmlout);
        fprintf(htmlout, "<TH>%02d:%02d\n");
        for (tp = targets; tp; tp = tp->next) fprintf(htmlout, "<TH title=\"%s\">%c\n", tp->hostname, tp->id);
      }
      fflush(htmlout);
      fprintf(htmlout, "<TR><TD>%02d:%02d\n", currtm->tm_hour, currtm->tm_min);
    }
    if (pinground > 1) {
      for (tp = targets; tp; tp = tp->next) ellsum += tp->rttlast - tp->rttmin;
      ell = ellsum / ntargets;
    }
  }

  if (currtarget->waitping) {
  }
  send_ping(currtarget);
  waddch(grid, ' ');
  waddch(grid, GRIDMARK);
  currtarget->waitping = pinground;

  print_status("Ping round %d / Monitoring %d hosts / Estimated local latency: %d ms", pinground, ntargets, ell);

  update_screen('a');

  memcpy(&nexttv, &currtv, sizeof(struct timeval));
  currtv.tv_sec = msinterval/1000;
  currtv.tv_usec = msinterval%1000*1000;
  nexttv = tvadd(nexttv, currtv);
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

  gettimeofday(&currtv, NULL);
  packtv = (struct timeval *)icp->icmp_data;
  currtv = tvsub(currtv, *packtv);
  r = currtv.tv_sec * 1000;
  r += currtv.tv_usec / 1000;

  if (r > INTERVAL*1000) return;	// Received a ping more than INTERVAL seconds after it being sent
					// Returning to prevent a potential division by zero 3 lines down
  tp->rttlast = r;
  tp->rttsum += r;
  tp->rttavg = tp->rttsum / (icp->icmp_seq - tp->losscount);
  if (r < tp->rttmin) tp->rttmin = r;
  if (r > tp->rttmax) tp->rttmax = r;
  if (icp->icmp_seq == tp->waitping) tp->waitping = 0;
  ampl = tp->rttavg - tp->rttmin;

  if (tp == currtarget) {
    waddch(grid, '\b');
    if (tp->treecolor == 6) {
      tp->downsince = time(NULL);
      ndown--;
    }
    if ((pinground <= 3) || (r <= tp->rttavg+2*(ampl?ampl:1))) {
      waddch(grid, GRIDMARK|COLOR_PAIR(3));
      wattron(scroller, COLOR_PAIR(3));
      if ((tp->lastcolor >= 3) && (tp->treecolor != 3)) {
        tp->treecolor = 3;
        print_tree();
      }
      tp->lastcolor = 3;
      if (htmlout) fprintf(htmlout, "<TD>%d\n", r);
    }
    else if ((r <= 2*tp->rttmin) || (r <= 8)) {
      waddch(grid, GRIDMARK|COLOR_PAIR(4));
      wattron(scroller, COLOR_PAIR(4));
      if ((tp->lastcolor >= 4) && (tp->treecolor != 4)) {
        tp->treecolor = 4;
        print_tree();
      }
      tp->lastcolor = 4;
      if (htmlout) fprintf(htmlout, "<TD class=\"j\">%d\n", r);
    }
    else {
      waddch(grid, GRIDMARK|COLOR_PAIR(5));
      wattron(scroller, COLOR_PAIR(5));
      tp->delaycount++;
      if ((tp->lastcolor >= 5) && (tp->treecolor != 5)) {
        tp->treecolor = 5;
        print_tree();
      }
      tp->lastcolor = 5;
      if (htmlout) fprintf(htmlout, "<TD class=\"d\">%d\n", r);
    }
    update_screen('g');
  }
  else wattron(scroller, COLOR_PAIR(6));

  if (tp->id == showinfo) print_info();

  print_scroll("%c  %-30.30s %-15s  %4d ms  (avg %3d ± %2d)", tp->id, tp->hostname, tp->address, r, tp->rttavg, ampl);
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
  int r, rank, detached;
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

  if (htmlout) fputs("<TABLE><TR><TD>ID<TD>Hostname<TD>IP address<TD>Comment\n", htmlout);

  while (fgets(buf, LINEBUF, fp)) {
    for (rank = 0; buf[rank] == ' '; rank++);
    if (!buf[rank]) return;
    if (buf[rank] == '\n') {
      detached = 1;
      continue;
    }
    strtok(&buf[rank], " \n");
    if ((r = getaddrinfo(&buf[rank], NULL, &hints, &res))) {
      fprintf(stderr, "- %s: %s\n", &buf[rank], gai_strerror(r));
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
    t->id = IDSEQUENCE[ntargets];
    if (!t->id) t->id = '?';
    t->rank = rank;
    if (rank > maxrank) maxrank = rank;
    t->detached = detached;
    memset(t->addr, 0, sizeof(struct sockaddr_in));
    strncpy(t->hostname, res->ai_canonname, HOSTLEN);
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
    }
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
  init_pair(3, COLOR_GREEN, COLOR_BLACK);
  init_pair(4, COLOR_YELLOW, COLOR_BLACK);
  init_pair(5, COLOR_BLUE, COLOR_BLACK);
  init_pair(6, COLOR_RED, COLOR_BLACK);

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
  hostinfo = newwin(10, 50, (rows-10)/2, (cols-50)/2);
  tree = newwin(ntargets+2, 2*maxrank+5, 1, cols-(2*maxrank+5));
  downlist = newwin(2, 40, 1, cols-40-(2*maxrank+5));

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
  draw_border(tree, " Map ");
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
  int c, n, more;
  target *t1, *t2, *t3;

  wmove(tree, 1, 2);
  for (n = 0, t1 = targets; t1; n++, t1 = t1->next) {
    wmove(tree, n+1, 2*t1->rank+2);
    switch (t1->treecolor) {
      case 3: waddch(tree, t1->id|COLOR_PAIR(3));
              break;
      case 4: waddch(tree, t1->id|COLOR_PAIR(4));
              break;
      case 5: waddch(tree, t1->id|COLOR_PAIR(5));
              break;
      case 6: waddch(tree, t1->id|COLOR_PAIR(6));
              break;
      default: waddch(tree, t1->id|COLOR_PAIR(1));
    }

    for (c = n+1, t2 = t1->next; t2; c++, t2 = t2->next, more = 0) {
      if (t2->detached || (t2->rank == t1->rank)) break;
      for (t3 = t2->next; t3; t3 = t3->next) {
        if (t3->detached || (t3->rank == t1->rank)) break;
        if (t3->rank == t1->rank+1) more = 1;
      }
      wmove(tree, c+1, 2*t1->rank+2);
      if (t2->rank == t1->rank+1) {
        if (more) waddch(tree, ACS_LTEE);
        else waddch(tree, ACS_LLCORNER);
        waddch(tree, ACS_HLINE);
      }
      else if (more) waddch(tree, ACS_VLINE);
    }
  }
}

void print_info(void) {
  char buf[47];
  target *tp;

  for (tp = targets; tp; tp = tp->next) {
    if (tp->id == showinfo) break;
  }
  if (!tp || !pinground) return;

  werase(hostinfo);
  draw_border(hostinfo, " Host info ");

  snprintf(buf, 47, "%c %s (%s) %s", tp->id, tp->hostname, tp->address, tp->comment?tp->comment:"");
  mvwaddstr(hostinfo, 1, 2, buf);
  snprintf(buf, 47, "Min: %5d", tp->rttmin);
  mvwaddstr(hostinfo, 2, 2, buf);
  snprintf(buf, 47, "Avg: %5d", tp->rttavg);
  mvwaddstr(hostinfo, 3, 2, buf);
  snprintf(buf, 47, "Max: %5d", tp->rttmax);
  mvwaddstr(hostinfo, 4, 2, buf);
  snprintf(buf, 47, "Last: %4d", tp->rttlast);
  mvwaddstr(hostinfo, 5, 2, buf);
  snprintf(buf, 47, "Packets delayed: %4d (%d%%)", tp->delaycount, tp->delaycount*100/pinground);
  mvwaddstr(hostinfo, 6, 2, buf);
  snprintf(buf, 47, "Packets lost: %7d (%d%%)", tp->losscount, tp->losscount*100/pinground);
  mvwaddstr(hostinfo, 7, 2, buf);
  snprintf(buf, 47, "Current status: %s", tp->treecolor==6?"down":"up");
  mvwaddstr(hostinfo, 8, 2, buf);
}

void print_down(void) {
  int ccols, crows, line = 1;
  char buf[48];
  target *tp;

  getmaxyx(downlist, crows, ccols);
  if (crows-2 != ndown) {
    delwin(downlist);
    if (showtree) downlist = newwin(ndown+2, 40, 1, cols-40-(2*maxrank+5));
    else downlist = newwin(ndown+2, 40, 1, cols-40);
    draw_border(downlist, " Hosts down ");
  }
  for (tp = targets; tp; tp = tp->next) {
    if (tp->treecolor == 6) {
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
   if ((r = digits%delta[c] >= 60)) {
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
