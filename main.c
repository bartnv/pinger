#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <sys/select.h>
#include <ncurses.h>
#include <time.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define GRIDMARK	'+'
#define TARGETSFILE	"targets"
#define INTERVAL	60
#define SCROLLSIZE	10
#define LINEBUF		512
#define HOSTLEN		64
#define MAXPACKET	4096		/* max packet size */
#define IDSEQUENCE	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

typedef struct target {
  char id;
  char hostname[HOSTLEN+1];
  char address[16];
  struct sockaddr_in *addr;
  int rank;
  int detached;
  int lastcolor;
  unsigned long rttsum;
  unsigned int rttavg;
  unsigned int rttmin;
  unsigned int rttmax;
  unsigned int rttlast;
  unsigned int downcount;
  unsigned int delaycount;
  time_t downsince;
  time_t downdur;
  char *comment;
  struct target *next;
  int waitping;
} target;

target *targets;

int pid;
int sock;
int ntargets = 0;
int pinground = 0;
int rows, cols;
int msinterval;
int showdown = 0, showtree = 0;
char showinfo = '\0';

target *currtarget = NULL;

struct timeval nexttv;

WINDOW *header, *footer, *status, *grid, *scroller, *hostinfo, *tree, *downlist;

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

int main(int argc, char *argv[]) {
  memset(&nexttv, 0, sizeof(struct timeval));

  pid = getpid();

  if (open_socket() == -1) exit(-1);

  setuid(getuid()); // Drop root privileges, we don't need them anymore.

  if (read_targets() == -1) exit(-2);

  msinterval = INTERVAL*1000/ntargets;

  if (argc == 2) printf("%s\n", argv[1]);

  sleep(5);

  start_curses();

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
      if (currtarget->lastcolor != 6) {
        currtarget->lastcolor = 6;
        print_tree();
      }
    }
    currtarget = currtarget->next;
  }
  if (!currtarget) {
    currtarget = targets;
    pinground++;
    snprintf(timebuf, 9, "\n[%02d:%02d] ", currtm->tm_hour, currtm->tm_min);
    waddstr(grid, timebuf);
    if (pinground > 1) {
      for (tp = targets; tp; tp = tp->next) ellsum += tp->rttlast - tp->rttmin;
      ell = ellsum / ntargets;
    }
  }

  if (currtarget->waitping) {
    wattron(scroller, COLOR_PAIR(6));
    print_scroll("%c  %-30.30s %-15s Probe %d abandoned (%d second timeout)", currtarget->id, currtarget->hostname,
      currtarget->address, currtarget->waitping, INTERVAL);
    currtarget->downcount++;
    if (!currtarget->downsince) currtarget->downsince = time(NULL);
  }
  send_ping(currtarget);
  waddch(grid, ' ');
  waddch(grid, GRIDMARK);
  currtarget->waitping = pinground;

  if (showtree) {
    wnoutrefresh(grid);
    touchwin(tree);
    wrefresh(tree);
  }
  else wrefresh(grid);

  print_status("Ping round %d / Monitoring %d hosts / Estimated local latency: %d ms", pinground, ntargets, ell);

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
  tp->rttavg = tp->rttsum / (icp->icmp_seq - tp->downcount);
  if (r < tp->rttmin) tp->rttmin = r;
  if (r > tp->rttmax) tp->rttmax = r;
  if (icp->icmp_seq == tp->waitping) tp->waitping = 0;
  ampl = tp->rttavg - tp->rttmin;

  if (tp == currtarget) {
    waddch(grid, '\b');
    if ((pinground <= 3) || (r <= tp->rttavg+2*(ampl?ampl:1))) {
      waddch(grid, GRIDMARK|COLOR_PAIR(3));
      wattron(scroller, COLOR_PAIR(3));
      if (tp->downsince) {				// Note that delayed responses don't redeem a host of its
        tp->downdur = time(NULL) - tp->downsince;	// down status. However, because the amplitude is based on
        tp->downsince = 0;				// the average delay, a long series of higher-latency
      }							// responses will eventually make the window catch up.
      if (tp->lastcolor != 3) {
        tp->lastcolor = 3;
        print_tree();
      }
    }
    else if ((r <= 2*tp->rttmin) || (r <= 8)) {
      waddch(grid, GRIDMARK|COLOR_PAIR(4));
      wattron(scroller, COLOR_PAIR(4));
      if (tp->lastcolor != 4) {
        tp->lastcolor = 4;
        print_tree();
      }
    }
    else {
      waddch(grid, GRIDMARK|COLOR_PAIR(5));
      wattron(scroller, COLOR_PAIR(5));
      tp->delaycount++;
      if (tp->lastcolor != 5) {
        tp->lastcolor = 5;
        print_tree();
      }
    }
    if (showtree) {
      wnoutrefresh(grid);
      touchwin(tree);
      wrefresh(tree);
    }
    else wrefresh(grid);
  }
  else wattron(scroller, COLOR_PAIR(6));

  print_scroll("%c  %-30.30s %-15s  %4d ms  (avg %3d ± %2d)", tp->id, tp->hostname, tp->address, r, tp->rttavg, ampl);
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
  int rank, detached;
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
    for (rank = 0; buf[rank] == ' '; rank++);
    if (!buf[rank]) return;
    if (buf[rank] == '\n') {
      detached = 1;
      continue;
    }
    strtok(&buf[rank], " \n");
    if (getaddrinfo(&buf[rank], NULL, &hints, &res)) {
      fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(errno));
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
    t->detached = detached;
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
    detached = 0;
  }

  for (tmp = targets; tmp; tmp = tmp->next) {
    if (tmp->comment) printf("%c %s (%s) rank %d%s \"%s\"\n", tmp->id, tmp->hostname, tmp->address, tmp->rank,
      tmp->detached?", detached":"", tmp->comment);
    else printf("%c %s (%s) rank %d%s\n", tmp->id, tmp->hostname, tmp->address, tmp->rank, tmp->detached?", detached":"");
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

void start_curses(void) {
  int c, x, y;
  target *t;

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

  for (t = targets; t; t = t->next) {
    if (t->rank > c) c = t->rank;
  }

  header = newwin(1, cols, 0, 0);
  grid = newwin(rows-SCROLLSIZE-3, cols, 1, 0);
  footer = newwin(1, cols, rows-SCROLLSIZE-2, 0);
  scroller = newwin(SCROLLSIZE, cols, rows-SCROLLSIZE-1, 0);
  status = newwin(1, cols, rows-1, 0);
  hostinfo = newwin(8, 40, (rows-8)/2, (cols-40)/2);
  tree = newwin(ntargets+2, 2*c+5, 1, cols-(2*c+5));
  downlist = newwin(10, 40, 1, cols-40);

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
  wrefresh(header);
  wrefresh(footer);

  draw_border(downlist, " Hosts down ");
  draw_border(tree, " Map ");
  wattron(tree, COLOR_PAIR(5));
  print_tree();
  showtree = 1;

  for (c = 0; c < SCROLLSIZE; c++) waddch(scroller, '\n');
  for (c = 0; c < rows-SCROLLSIZE; c++) waddch(grid, '\n');
//  if (has_colors()) print_scroll("Terminal supports colors");
//  if (can_change_color()) print_scroll("Terminal can change color definitions");
}

void draw_border(WINDOW *win, char *title) {
  int c, x, y;

  getmaxyx(win, y, x);			// getmaxyx returns the number of available cols/rows
  if ((x-- < 3) || (y-- < 3)) return;	// -- them to get the correct index for use in wmove()

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
  wrefresh(scroller);
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
  wrefresh(status);
}

void print_tree(void) {
  int c, n, more;
  target *t1, *t2, *t3;

  wmove(tree, 1, 2);
  for (n = 0, t1 = targets; t1; n++, t1 = t1->next) {
    wmove(tree, n+1, 2*t1->rank+2);
    switch (t1->lastcolor) {
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
