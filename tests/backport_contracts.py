#!/usr/bin/env python3
"""Run offline contracts against maintenance production functions and blocks.

Configure/build first, then run: mise exec -- python tests/backport_contracts.py
Only compile-time and operating-system boundaries are substituted. No database,
network endpoint, installation, or poller setting is changed.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
workspace = tempfile.TemporaryDirectory(prefix="spine-backport-contracts-")
out = Path(workspace.name)
makefile = (root / "Makefile").read_text()
def make_variable(name):
    return shlex.split(re.search(r"^" + name + r" = (.*)$", makefile, re.M).group(1))
flags = ["-DHAVE_CONFIG_H", "-I" + str(root), "-I" + str(root / "config"),
         *make_variable("CPPFLAGS"), *make_variable("CFLAGS")]
compiler = shlex.split(os.environ.get("CC", "cc"))

def function(source, name):
    start = source.index("\n" + name) + 1
    end = source.index("\n}", start) + 2
    return source[start:end]

def run(name, source):
    path = out / (name + ".c")
    path.write_text(source)
    executable = out / name
    subprocess.run([*compiler, *flags, str(path), "-pthread", "-lm", "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)
    print(name + ": passed")

s=(root/'snmp.c').read_text();helper=function(s,'static int snmp_synchronized_response(')
run('maintenance-snmp-lock-contract','''#include "common.h"
#include "spine.h"
static int locked,locks,unlocks,expect_lock,cancel_changes;
static struct snmp_session active;
static int missing;
struct snmp_session *snmp_sess_session(void *session) { (void)session;return missing?NULL:&active; }
void thread_mutex_lock(int id) { assert(id==LOCK_SNMP&&!locked);locked=1;locks++; }
void thread_mutex_unlock(int id) { assert(id==LOCK_SNMP&&locked);locked=0;unlocks++; }
static int fixture_cancel(int state,int *previous) { if(previous)*previous=PTHREAD_CANCEL_ENABLE; if(state==PTHREAD_CANCEL_DISABLE)assert(!locked);else assert(!locked); cancel_changes++;return 0; }
int snmp_sess_synch_response(void *session,struct snmp_pdu *pdu,struct snmp_pdu **response) { (void)session;(void)pdu;(void)response;assert(locked==expect_lock);return STAT_TIMEOUT; }
#define pthread_setcancelstate fixture_cancel
'''+helper+'''
int main(void) { host_t host={0}; struct snmp_pdu *response=NULL;
 host.snmp_version=1;active.version=SNMP_VERSION_3;expect_lock=1;
 assert(snmp_synchronized_response(&host,NULL,&response)==STAT_TIMEOUT);assert(locks==1&&unlocks==1&&cancel_changes==2);
 host.snmp_version=3;active.version=SNMP_VERSION_2c;expect_lock=0;
 snmp_synchronized_response(&host,NULL,&response);assert(locks==1&&cancel_changes==2);
 missing=1;expect_lock=1;snmp_synchronized_response(&host,NULL,&response);assert(locks==2&&unlocks==2&&!locked);return 0;
}
''')
s=(root/'spine.c').read_text();a=s.index('#if RESULTS_BUFFER < 2');b=s.index('\nstatic int spine_thread_attr_init',a);size=s[a:b];helper=function(s,'static int spine_thread_attr_init(')
run('maintenance-thread-stack-contract','''#include "common.h"
#include "spine.h"
#include <stdint.h>
static size_t initial_size,configured;static int init_error,set_error,destroyed;
static int fixture_init(pthread_attr_t *a) { (void)a;return init_error; }
static int fixture_get(const pthread_attr_t *a,size_t *size) { (void)a;*size=initial_size;return 0; }
static int fixture_set(pthread_attr_t *a,size_t size) { (void)a;configured=size;return set_error; }
static int fixture_destroy(pthread_attr_t *a) { (void)a;destroyed++;return 0; }
#define pthread_attr_init fixture_init
#define pthread_attr_getstacksize fixture_get
#define pthread_attr_setstacksize fixture_set
#define pthread_attr_destroy fixture_destroy
'''+size+'\n'+helper+'''
int main(void) { pthread_attr_t a;
 initial_size=128*1024;assert(spine_thread_attr_init(&a)==0&&configured>=384*1024);
 configured=0;initial_size=8*1024*1024;assert(spine_thread_attr_init(&a)==0&&configured==0);
 initial_size=128*1024;set_error=EINVAL;assert(spine_thread_attr_init(&a)==EINVAL&&destroyed==1);
 init_error=ENOMEM;assert(spine_thread_attr_init(&a)==ENOMEM&&destroyed==1);return 0;
}
''')
s=(root/'util.c').read_text();helper=function(s,'static bool config_line_complete(')
run('maintenance-config-line-contract','''#include "common.h"
#include "spine.h"
'''+helper+'''
int main(void) { FILE *f=tmpfile();char line[16];assert(f);
 fputs("DB_Host localhost\\nDB_Pass secret\\n",f);rewind(f);
 line[15]=1;assert(fgets(line,sizeof(line),f));assert(!config_line_complete(f,line,sizeof(line)));
 assert(fgets(line,sizeof(line),f));assert(strcmp(line,"DB_Pass secret\\n")==0);fclose(f);
 f=tmpfile();fputs("DB_Host x",f);rewind(f);line[15]=1;assert(fgets(line,sizeof(line),f));assert(config_line_complete(f,line,sizeof(line)));fclose(f);return 0;
}
''')


s=(root/'poller.c').read_text();a=s.index('/* Only the final completed partition');b=s.index('\n\tif (local_cnn != NULL)',a);block=s[a:b]
run('maintenance-completion-contract','''#include "common.h"
#include "spine.h"
config_t set;
static poller_thread_t record;
poller_thread_t *details[]={&record};
static int locked,schedules,times,fail_time,fail_schedule;
void thread_mutex_lock(int id){(void)id;assert(!locked);locked=1;}
void thread_mutex_unlock(int id){(void)id;assert(locked);locked=0;}
double get_time_as_double(void){return 1;}
int db_insert(MYSQL *mysql,int mode,const char *query){(void)mysql;(void)mode;assert(!locked);if(strcmp(query,"schedule")==0){schedules++;return !fail_schedule;}times++;return !fail_time;}
static void complete(bool output_failed) {
 int device_counter=0,host_id=1;double poll_time=0,host_time_double=0;
 MYSQL *mysql=NULL;char query1[BUFSIZE];const char *query6="schedule";
 bool last_partition,failed;
'''+block+'''
}
static void reset(void){memset(&record,0,sizeof(record));record.host_threads=2;set.exit_code=0;set.active_profiles=0;schedules=times=fail_time=fail_schedule=0;}
int main(void){
 reset();complete(false);assert(!schedules&&!times&&!record.complete);complete(false);assert(schedules==1&&times==1&&record.complete);
 reset();complete(true);complete(false);assert(schedules==0&&!record.complete&&set.exit_code==EXIT_FAILURE);
 reset();complete(false);fail_time=1;complete(false);assert(!schedules&&!record.complete&&set.exit_code==EXIT_FAILURE);
 reset();complete(false);fail_schedule=1;complete(false);assert(schedules==1&&!record.complete&&set.exit_code==EXIT_FAILURE);
 reset();set.active_profiles=1;complete(false);complete(false);assert(!schedules&&record.complete);return 0;
}
''')
s=(root/'sql.c').read_text();a=s.index('bool db_row_alias(');b=s.index('\n}',a)+2;helper=s[a:b]
run('maintenance-destination-contract','''#include "common.h"
#include "spine.h"
static const char *vendor;static unsigned long version;
/* MySQL declares a const return type and MariaDB does not. */
#define mysql_get_server_info fixture_get_server_info
char *mysql_get_server_info(MYSQL *mysql){(void)mysql;return (char*)vendor;}
unsigned long mysql_get_server_version(MYSQL *mysql){(void)mysql;return version;}
'''+helper+'''
int main(void){MYSQL mysql;
 vendor="5.5.5-10.11.6-MariaDB";version=101106;assert(!db_row_alias(&mysql));
 vendor="8.0.18";version=80018;assert(!db_row_alias(&mysql));
 vendor="8.0.19";version=80019;assert(db_row_alias(&mysql));
 vendor="9.4.0";version=90400;assert(db_row_alias(&mysql));vendor=NULL;assert(!db_row_alias(&mysql));return 0;
}
''')
a=s.index('\nint db_insert(')+1;b=s.index('\n}',a)+2;insert=s[a:b]
run('maintenance-retry-contract','''#include "common.h"
#include "spine.h"
#include <setjmp.h>
config_t set;
static jmp_buf stopped;static int calls,error_code;
#undef SPINE_LOG
#define SPINE_LOG(...) ((void)0)
static void log_sql_statement(const char *query){(void)query;}
static void sql_statement_label(const char *query,char *label,size_t capacity){(void)query;snprintf(label,capacity,"fixture");}
int mysql_query(MYSQL *mysql,const char *query){(void)mysql;(void)query;calls++;errno=EINTR;return 1;}
unsigned int mysql_errno(MYSQL *mysql){(void)mysql;return error_code;}
const char *mysql_error(MYSQL *mysql){(void)mysql;return "fixture";}
int db_reconnect(MYSQL *mysql,int type,int error,char *function){(void)mysql;(void)type;(void)error;(void)function;assert(0);return 0;}
int usleep(useconds_t usec){(void)usec;return 0;}
void die(const char *format,...){(void)format;longjmp(stopped,1);}
'''+insert+'''
int main(void){MYSQL mysql;error_code=2013;if(setjmp(stopped)==0){db_insert(&mysql,LOCAL,"fixture");assert(0);}assert(calls==31);
 calls=0;error_code=1213;assert(!db_insert(&mysql,LOCAL,"fixture")&&calls==31);return 0;}
''')


s=(root/'ping.c').read_text();tcp=function(s,'static int ping_tcp_attempt(')
run('maintenance-tcp-deadline-contract','''#include "common.h"
#include "spine.h"
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
static int closed,polls,phase,waitms;static double now;
static double ping_monotonic_time(void){now+=0.001;return now;}
static int fixture_socket(int family,int type,int protocol){(void)family;(void)type;(void)protocol;return 100;}
static int fixture_fcntl(int fd,int cmd,...){(void)fd;(void)cmd;return 0;}
static int fixture_connect(int fd,const struct sockaddr *addr,socklen_t len){(void)fd;(void)addr;(void)len;errno=EINPROGRESS;return -1;}
static int fixture_close(int fd){assert(fd==100);closed++;return 0;}
static int fixture_poll(struct pollfd *p,nfds_t n,int ms){(void)p;(void)n;assert(ms>0);waitms=ms;polls++;if(phase==0){errno=EINTR;return -1;}return 1;}
static int fixture_getsockopt(int fd,int level,int opt,void *value,socklen_t *len){(void)fd;(void)level;(void)opt;(void)len;*(int*)value=ECONNREFUSED;return 0;}
#define socket fixture_socket
#define fcntl fixture_fcntl
#define connect fixture_connect
#define close fixture_close
#define poll fixture_poll
#define getsockopt fixture_getsockopt
'''+tcp+'''
int main(void){struct sockaddr_in address={0};assert(ping_tcp_attempt(&address,0.003)==ETIMEDOUT);assert(closed==1&&polls<4);phase=1;now=0;assert(ping_tcp_attempt(&address,3)==ECONNREFUSED);assert(closed==2);now=0;ping_tcp_attempt(&address,3e9);assert(waitms==INT_MAX&&closed==3);return 0;}
''')
wait=function(s,'static void ping_wait_left(')
run('maintenance-probe-timeval-contract','''#include "common.h"
#include "spine.h"
static double now;
static double ping_monotonic_time(void){return now;}
'''+wait+'''
int main(void){struct timeval t;now=0;ping_wait_left(1.5,&t);assert(t.tv_sec==1&&t.tv_usec==500000);now=2;ping_wait_left(1.5,&t);assert(!t.tv_sec&&!t.tv_usec);return 0;}
''')
s=(root/'spine.c').read_text();hostlist=function(s,'static void parse_host_list(')
run('maintenance-hostlist-contract','''#include "common.h"
#include "spine.h"
#include <limits.h>
#include <setjmp.h>
config_t set;static jmp_buf rejected;
void die(const char *format,...){(void)format;longjmp(rejected,1);}
'''+hostlist+'''
int main(void){const char *bad[]={"1) OR 1=1","1,,2","-1","2147483648","1,"};size_t i;parse_host_list(" 1 , 2 ");assert(strcmp(set.host_id_list,"1,2")==0);for(i=0;i<sizeof(bad)/sizeof(bad[0]);i++){if(setjmp(rejected)==0){parse_host_list(bad[i]);assert(0);}}return 0;}
''')
s=(root/'error.c').read_text();a=s.index('\nstatic void signal_write(')+1;b=s.index('\nstatic int spine_fatal_signals',a)
run('maintenance-fatal-signal-contract','''#include "common.h"
#include "spine.h"
config_t set;
'''+s[a:b]+'''
int main(void){pid_t child=fork();int status;assert(child>=0);if(child==0){signal(SIGINT,spine_signal_handler);raise(SIGINT);_exit(0);}assert(waitpid(child,&status,0)==child);assert(WIFSIGNALED(status)&&WTERMSIG(status)==SIGINT);return 0;}
''')


s = (root / 'poller.c').read_text()
run('maintenance-uptime-contract', '#include "common.h"\n#include "spine.h"\n#include <limits.h>\n' + function(s, 'static bool parse_uptime(') + '''
int main(void) {
 unsigned long long value=0;
 assert(parse_uptime("18446744073709551615",&value) && value==ULLONG_MAX);
 assert(!parse_uptime("18446744073709551616",&value));
 assert(!parse_uptime("1.5",&value)); assert(!parse_uptime("-1",&value));
 assert(!parse_uptime("1e9",&value)); assert(!parse_uptime("",&value));
 assert(!parse_uptime(NULL,&value)); assert(!parse_uptime("1",NULL));
 assert(parse_uptime("  42 \\n",&value)&&value==42);
 assert(parse_uptime("184467440737095516",&value)&&value<=ULLONG_MAX/100);
 assert(parse_uptime("184467440737095517",&value)&&value>ULLONG_MAX/100);
 return 0;
}
''')

declarations = '\n'.join(re.findall(r'^\s*(?:int|char)\s+last_snmp[^\n]*;', s, re.M))
a = s.index('last_snmp_port = poller_items[i].snmp_port;')
b = s.index(';', s.index('STRNCOPY(last_snmp_engine_id', a)) + 1
snapshot = s[a:b]
a = s.index('if (', s.index('/* some snmp data changed')) + 3
b = s.index(' {', a)
condition = s[a:b]
copy = function((root / 'util.c').read_text(), 'char *strncopy(')
run('maintenance-session-key-contract', '#include "common.h"\n#include "spine.h"\n' + copy + '\nint main(void) {\n' + declarations + '''
 target_t poller_items[2]={0};int i=0;
 strcpy(poller_items[0].hostname,"127.0.0.1");
 strcpy(poller_items[1].hostname,"127.0.0.1");
 poller_items[0].snmp_timeout=500;poller_items[1].snmp_timeout=1000;
''' + snapshot + '\ni=1;assert(' + condition + ''');
 poller_items[1].snmp_timeout=500;strcpy(poller_items[1].hostname,"127.0.0.2");
 assert(''' + condition + ''');return 0;}
''')

util = (root / 'util.c').read_text()
run('maintenance-result-contract', '#include "common.h"\n#include "spine.h"\n' + function(util, 'char *strip_alpha(') + '\n' + util[util.index("/* Cacti's prepare_validate_result"): ] + '''
int main(void){classified_result_t out;
 assert(classify_result("ff ff ff ff ff ff ff ff",&out)==RESULT_HEX_COUNTER);
 assert(strcmp(out.text,"18446744073709551615")==0);
 assert(classify_result("ff ff ff ff ff ff ff ff ff",&out)==RESULT_UNKNOWN);
 assert(strcmp(out.text,"U")==0);
 assert(classify_result("  '42'  ",&out)==RESULT_COUNTER&&strcmp(out.text,"42")==0);
 assert(classify_result("4096 Bytes",&out)==RESULT_COUNTER&&strcmp(out.text,"4096")==0);
 assert(classify_result("r15s:42 r1m:43",&out)==RESULT_MULTIPART);
 assert(classify_result("12 abc",&out)==RESULT_COUNTER&&strcmp(out.text,"12")==0);
 assert(classify_result("FF",&out)==RESULT_HEX_COUNTER&&strcmp(out.text,"255")==0);
 assert(classify_result("0x10",&out)==RESULT_UNKNOWN&&strcmp(out.text,"U")==0);
 assert(classify_result("-1.5e2",&out)==RESULT_FLOAT);return 0;}
''')

run('maintenance-script-log-contract', '#include "common.h"\n#include "spine.h"\n' + function(s, 'static const char *script_log_name(') + '''
int main(void){char label[64];assert(strcmp(script_log_name("/path/script --password=fixture",label,sizeof(label)),"/path/script")==0);return 0;}
''')

# Compile session construction itself with only the network-open/response calls
# replaced. All key derivation and protocol selection uses the native library.
source = r'''#include "common.h"
#include "spine.h"
static int level,opens;
static size_t auth_length,priv_length;
static unsigned char auth_key[USM_AUTH_KU_LEN];
static int replies,reply_phase;
static struct snmp_session active_request_session;
static struct snmp_session *capture_session(void *session){(void)session;active_request_session.version=SNMP_VERSION_3;return &active_request_session;}
static int capture_response(void *session,struct snmp_pdu *request,struct snmp_pdu **response){oid name[]={1,3,6,1,2,1,1,3,0};long value=42;(void)session;replies++;snmp_free_pdu(request);*response=snmp_pdu_create(SNMP_MSG_RESPONSE);assert(*response);(*response)->errstat=SNMP_ERR_GENERR;(*response)->errindex=reply_phase;snmp_pdu_add_variable(*response,name,9,ASN_INTEGER,(const unsigned char*)&value,sizeof(value));snmp_pdu_add_variable(*response,name,9,ASN_INTEGER,(const unsigned char*)&value,sizeof(value));return STAT_SUCCESS;}
static void *capture_open(struct snmp_session *session){level=session->securityLevel;auth_length=session->securityAuthKeyLen;priv_length=session->securityPrivKeyLen;memcpy(auth_key,session->securityAuthKey,sizeof(auth_key));opens++;return (void*)1;}
#define snmp_sess_session capture_session
#define snmp_sess_synch_response capture_response
#define snmp_sess_open capture_open
#include "snmp.c"
#undef snmp_sess_open
int fixture_sem_trywait(sem_t *value){(void)value;return 0;}
int fixture_sem_post(sem_t *value){(void)value;return 0;}
extern int *debug_devices;
static void *open_case(char *auth,char *password,char *priv,char *private_password,int timeout){return snmp_host_init(1,"127.0.0.1",3,"","fixture",password,auth,private_password,priv,"","",161,timeout);}
int main(void){static int devices[100];char password[]="authpass123";int count;debug_devices=devices;init_mutexes();set.stdout_notty=set.stderr_notty=TRUE;
 assert(open_case("[None]","","[None]","",500)!=NULL&&level==SNMP_SEC_LEVEL_NOAUTH);
 assert(open_case("SHA",password,"[None]","",500)!=NULL&&level==SNMP_SEC_LEVEL_AUTHNOPRIV&&auth_length>0);assert(strcmp(password,"authpass123")==0);
 assert(open_case("SHA",password,"AES","privpass123",500)!=NULL&&level==SNMP_SEC_LEVEL_AUTHPRIV&&auth_length>0&&priv_length>0);
 count=opens;assert(open_case("[None]","","AES","privpass123",500)==NULL&&opens==count);
 assert(open_case("bogus","","[None]","",500)==NULL&&opens==count);
 assert(open_case("",password,"[None]","",500)==NULL&&opens==count);
 assert(open_case("SHA",password,"","privpass123",500)==NULL&&opens==count);
 assert(open_case("SHA",password,"[None]","",0)==NULL&&opens==count);
 assert(open_case("[None]",password,"[None]","",500)!=NULL&&level==SNMP_SEC_LEVEL_NOAUTH);
 {host_t host={0};target_t items[2]={0};snmp_oids_t oids[2]={0};host.snmp_session=(void*)1;strcpy(oids[0].oid,".1.3.6.1.2.1.1.3.0");strcpy(oids[1].oid,".1.3.6.1.2.1.1.3.0");
 snmp_get_multi(&host,items,oids,2);assert(host.snmp_status==STAT_ERROR&&strcmp(oids[0].result,"U")==0&&strcmp(oids[1].result,"U")==0);
 reply_phase=1;replies=0;memset(oids[0].result,0,sizeof(oids[0].result));memset(oids[1].result,0,sizeof(oids[1].result));snmp_get_multi(&host,items,oids,2);assert(replies<=2&&strcmp(oids[0].result,"U")==0&&strcmp(oids[1].result,"U")==0);
 }return 0;}
'''
path = out / "snmp-security-contract.c"
path.write_text(source)
spine_object = out / "spine-fixture.o"
subprocess.run([*compiler, *flags, "-Dmain=fixture_spine_main", "-c", str(root / "spine.c"), "-o", str(spine_object)], check=True)
objects = [str(root / (name + ".o")) for name in ["sql", "util", "locks", "nft_popen", "php", "ping", "keywords", "error", "poller"]]
executable = out / "snmp-security-contract"
subprocess.run([*compiler, *flags, str(path), str(spine_object), *objects,
                *make_variable("LDFLAGS"), *make_variable("LIBS"), "-o", str(executable)], check=True)
subprocess.run([str(executable)], check=True, timeout=20)
print("maintenance-snmp-security-and-error-contracts: passed")

sql = (root / 'sql.c').read_text()
run('maintenance-required-tls-contract', '#include "common.h"\n#include "spine.h"\n#include <setjmp.h>\n' + '''
config_t set;static int options,fail_option;static jmp_buf failed;
int mysql_options(MYSQL *mysql,enum mysql_option option,const void *value){(void)mysql;(void)option;assert(value);options++;return fail_option;}
void die(const char *format,...){(void)format;longjmp(failed,1);}
''' + function(sql, 'static int db_tls_required(') + '\n' + function(sql, 'static void db_require_tls(') + '''
int main(void){MYSQL mysql;set.db_ssl=0;db_require_tls(&mysql,LOCAL,"db.example","");assert(options==0);
 set.db_ssl=1;db_require_tls(&mysql,LOCAL,"db.example","");assert(options==1);
 set.db_ssl=1;db_require_tls(&mysql,LOCAL,"db.example","/etc/ca.pem");assert(options==2);
 set.rdb_ssl=1;db_require_tls(&mysql,REMOTE,"db.example","");assert(options==3);
 db_require_tls(&mysql,LOCAL,NULL,"");db_require_tls(&mysql,LOCAL,"localhost","");assert(options==3);
 assert(!db_tls_required(LOCAL,NULL)&&!db_tls_required(LOCAL,"localhost")&&db_tls_required(LOCAL,"127.0.0.1"));
 fail_option=1;if(setjmp(failed)==0){db_require_tls(&mysql,LOCAL,"db.example","");assert(0);}return 0;}
''')

# Every connection attempt must start from a fresh handle with the TLS policy
# applied, and a plaintext session must never be accepted when TLS is required.
connect_stubs = '''
#define mysql_init fixture_mysql_init
#define mysql_options fixture_mysql_options
#define mysql_real_connect fixture_mysql_real_connect
#define mysql_close fixture_mysql_close
#define mysql_errno fixture_mysql_errno
#define mysql_error fixture_mysql_error
#define mysql_get_ssl_cipher fixture_mysql_get_ssl_cipher
'''
run('maintenance-connect-retry-tls-contract', '#include "common.h"\n#include "spine.h"\n#include <setjmp.h>\n' + connect_stubs + '''
config_t set;static jmp_buf failed;
static int inits,tls_options,connects,closes,first_error,have_cipher;
MYSQL *mysql_init(MYSQL *mysql){inits++;return mysql;}
int mysql_options(MYSQL *mysql,enum mysql_option option,const void *value){(void)mysql;(void)value;
#ifdef HAS_MYSQL_OPT_SSL_MODE
 if(option==MYSQL_OPT_SSL_MODE)tls_options++;
#else
 if(option==MYSQL_OPT_SSL_ENFORCE)tls_options++;
#endif
 return 0;}
MYSQL *mysql_real_connect(MYSQL *mysql,const char *host,const char *user,const char *pass,const char *db,unsigned int port,const char *sock,unsigned long flags){
 (void)host;(void)user;(void)pass;(void)db;(void)port;(void)sock;(void)flags;errno=0;return ++connects==1?NULL:mysql;}
void mysql_close(MYSQL *mysql){(void)mysql;closes++;}
unsigned int mysql_errno(MYSQL *mysql){(void)mysql;return first_error;}
const char *mysql_error(MYSQL *mysql){(void)mysql;return "fixture";}
const char *mysql_get_ssl_cipher(MYSQL *mysql){(void)mysql;return have_cipher?"AES":NULL;}
void die(const char *format,...){(void)format;longjmp(failed,1);}
int usleep(useconds_t usec){(void)usec;return 0;}
unsigned int sleep(unsigned int seconds){(void)seconds;return 0;}
int spine_log(const char *format,...){(void)format;return TRUE;}
static void fixture_exit(int status){(void)status;longjmp(failed,1);}
#define exit fixture_exit
''' + function(sql, 'static int db_tls_required(') + '\n' + function(sql, 'static void db_require_tls(') + '\n' + function(sql, 'static void db_prepare_handle(') + '\n' + function(sql, 'void db_connect(') + '''
static void reset(int error){inits=tls_options=connects=closes=0;first_error=error;have_cipher=0;}
int main(void){MYSQL mysql;
 snprintf(set.db_host,sizeof(set.db_host),"%s","db.example");set.poller_id=1;set.db_ssl=1;
 /* a transient failure, then a plaintext session: the retry must have the TLS
  * policy applied again and the session must be refused */
 reset(2013);if(setjmp(failed)==0){db_connect(LOCAL,&mysql);assert(0);}
 assert(inits==2&&tls_options==2&&closes>=2);
 /* a TLS handshake failure is final */
 reset(2026);if(setjmp(failed)==0){db_connect(LOCAL,&mysql);}
 assert(connects==1&&inits==1);
 return 0;}
''')

util = (root / 'util.c').read_text()
a = util.index('static struct {')
b = util.index('} opttable[256];', a) + len('} opttable[256];')
run('maintenance-option-capacity-contract', '#include "common.h"\n#include "spine.h"\n#include <setjmp.h>\n' + '''
static jmp_buf rejected;static int nopts;
void die(const char *format,...){(void)format;longjmp(rejected,1);}
''' + util[a:b] + '\n' + function(util, 'void set_option(') + '''
int main(void){int i;for(i=0;i<256;i++)set_option("fixture","value");if(setjmp(rejected)==0){set_option("fixture","value");assert(0);}return 0;}
''')

sql = (root / 'sql.c').read_text()
run('maintenance-sql-log-contract', '#include "common.h"\n#include "spine.h"\n#include <setjmp.h>\n' + '''
config_t set;static char logs[LRG_BUFSIZE];static jmp_buf stopped;
int spine_log(const char *format,...){va_list args;size_t used=strlen(logs);va_start(args,format);vsnprintf(logs+used,sizeof(logs)-used,format,args);va_end(args);return TRUE;}
int mysql_query(MYSQL *mysql,const char *query){(void)mysql;(void)query;return 1;}
unsigned int mysql_errno(MYSQL *mysql){(void)mysql;return 1064;}
const char *mysql_error(MYSQL *mysql){(void)mysql;return "fixture_sql_secret";}
const char *mysql_sqlstate(MYSQL *mysql){(void)mysql;return "42000";}
MYSQL_RES *mysql_store_result(MYSQL *mysql){(void)mysql;return NULL;}
int db_reconnect(MYSQL *mysql,int type,int error,char *location){(void)mysql;(void)type;(void)error;(void)location;return FALSE;}
int usleep(useconds_t usec){(void)usec;return 0;}
void die(const char *format,...){(void)format;longjmp(stopped,1);}
static void fixture_exit(int status){assert(status==1);longjmp(stopped,1);}
#define exit fixture_exit
''' + function(sql, 'static const char *sql_skip_space(') + '\n' + function(sql, 'static int sql_word_is(') + '\n' + function(sql, 'static const char *sql_target_table(') + '\n' + function(sql, 'static void sql_statement_label(') + '\n' + function(sql, 'static void log_sql_statement(') + '\n' + function(sql, 'int db_insert(') + '\n' + function(sql, 'MYSQL_RES *db_query(') + '''
int main(void){MYSQL mysql;set.log_level=POLLER_VERBOSITY_DEVDBG;
 assert(!db_insert(&mysql,LOCAL,"INSERT INTO settings(name,value) VALUES('password','fixture_sql_secret')"));
 if(setjmp(stopped)==0){db_query(&mysql,LOCAL,"SELECT fixture_sql_secret");assert(0);}
 assert(strstr(logs,"1064")!=NULL);assert(strstr(logs,"42000")!=NULL);assert(strstr(logs,"Statement:'INSERT settings'")!=NULL);assert(strstr(logs,"fixture_sql_secret")==NULL);return 0;}
''')


# Transport-qualified device names must resolve to the address family of the
# address itself, not fail the lookup because of the prefix or the port.
ping_source = (root / "ping.c").read_text()
util_source = (root / "util.c").read_text()
run('maintenance-address-type-contract', '#include "common.h"\n#include "spine.h"\n#include "ping.h"\n' + '''
config_t set;
int spine_log(const char *format,...){(void)format;return TRUE;}
''' + function(util_source, 'int char_count(') + '\n' + function(ping_source, 'static int split_host_spec(') + '\n' + function(ping_source, 'static const char *ping_address(') + '\n' + function(ping_source, 'int get_address_type(') + '''
int main(void){host_t host;const char *ipv4[]={"127.0.0.2","tcp:127.0.0.2","tcp:127.0.0.2:8080","UDP:127.0.0.2:161"};size_t i;
 memset(&host,0,sizeof(host));
 for(i=0;i<sizeof(ipv4)/sizeof(ipv4[0]);i++){snprintf(host.hostname,sizeof(host.hostname),"%s",ipv4[i]);assert(get_address_type(&host)==SPINE_IPV4);}
 snprintf(host.hostname,sizeof(host.hostname),"%s","[::1]");assert(get_address_type(&host)!=SPINE_IPV4);return 0;}
''')
