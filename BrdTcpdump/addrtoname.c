/*
addrtoname.c 主要负责将网络地址（如IP地址、MAC地址）转换为易于理解的名称（如主机名、设备名称）
例：IP地址:192.168.1.1转换为主机名 example.com
*/

#include<config.h>      //帮助代码处理不同的系统差异

#ifdef HAVE_CASPER      //条件编译，检查HAVE_CASPER宏是否已经被定义，跨平台适配
#include<libcasper.h>      //网络函数库，特别是安全性和协议分析方面
#include<casper/cap_dns.h>      //与DNS（域名系统）相关的部分
#endif

#include "netdissect-stdinc.h"    //提供一些标准化设置、数据结构、常量、函数声明等

#ifdef USE_ETHER_NTOHOST    //?? USE_ETHER_NTOHOST具体有什么功能暂且不清楚，可能与某些网络功能有关
  #if defined(NET_ETHERNET_H_DECLARES_ETHER_NTOHOST)
  /*
   * OK,just include <net/ethernet.h>
   */
    #include<net/ethernet.h>     // 网络头文件，主要是以太网的协议，定义了以太网帧的结构
  #elif defined (NETINET_ETHER_HDECLARES_ETHER_NTOHOST)
    #include<netinet/ether.h>      //网络协议，特别是netinet子系统相关的协议，如IPv4、ARP等，常用于实现和解析以太帧时
  #elif defined(SYS_ETHERNET_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, just include <sys/ethernet.h>
     */
    #include <sys/ethernet.h>      //提供以太网帧和网络接口相关的低级别操作
  #elif defined(ARPA_INET_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, just include <arpa/inet.h>
     */
    #include <arpa/inet.h>
  #elif defined(NETINET_IF_ETHER_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, include <netinet/if_ether.h>, after all the other stuff we
     * need to include or define for its benefit.
     */
    #define NEED_NETINET_IF_ETHER_H
  #else
    /*
     * We'll have to declare it ourselves.
     * If <netinet/if_ether.h> defines struct ether_addr, include
     * it.  Otherwise, define it ourselves.
     */
    #ifdef HAVE_STRUCT_ETHER_ADDR
      #define NEED_NETINET_IF_ETHER_H
    #else /* HAVE_STRUCT_ETHER_ADDR */
	struct ether_addr {
		/* Beware FreeBSD calls this "octet". */
		unsigned char ether_addr_octet[MAC48_LEN];
	};
    #endif /* HAVE_STRUCT_ETHER_ADDR */
  #endif /* what declares ether_ntohost() */

  #ifdef NEED_NETINET_IF_ETHER_H
    #include <net/if.h>		/* Needed on some platforms */
    #include <netinet/in.h>	/* Needed on some platforms */
    #include <netinet/if_ether.h>
  #endif /* NEED_NETINET_IF_ETHER_H */

  #ifndef HAVE_DECL_ETHER_NTOHOST
    /*
     * No header declares it, so declare it ourselves.
     */
    extern int ether_ntohost(char *, const struct ether_addr *);      //没有标准头文件声明该函数，我们自己声明
                                                                      //char* 储存解析的主机名，第二个参数表示指向以太网地址（MAC地址）的指针
  #endif /* !defined(HAVE_DECL_ETHER_NTOHOST) */
#endif /* USE_ETHER_NTOHOST */
//以上一段主要是为了处理ether_ntohost()函数的跨平台兼容性，该函数主要是用于将以太网地址（MAC地址）转换为主机名


#include <pcap.h>		//libpcap库的头文件，提供网络接口上的数据包捕获、过滤、保存等，常用于wireshark等网络分析工具
#include <pcap-namedb.h>		//存储、查询网络接口名称
#ifndef HAVE_GETSERVENT			
 #include <getservent.h>		//用于查找服务名称和其对应的端口号，例如"http"对应的端口是80,"ftp"对应的端口是21
#endif
#include <signal.h>		//信号处理函数
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "netdissect.h"			//自定义函数？？可能与网络抓包或数据包解析相关
#include "addrtoname.h"
#include "addrtostr.h"
#include "ethertype.h"
#include "llc.h"
#include "extract.h"
#include "oui.h"


#define HASHNAMESIZE 4096		//定义哈希表的大小

struct hnamemem {		//用于存储地址和名称映射的结构体
	uint32_t addr;			//IP 地址、端口号或其他类型的地址；uint32_t无符号整型，超过最大值会回绕到0，int溢出会出现负数或者无定义行为
	const char *name;		//存储与地址相关联的名称，通常是与地址对应的主机名、服务名等；const，表示一个不可修改的量
	struct hnamemem *nxt;		//构成链式哈希表
};

static struct hnamemem hnametable[HASHNAMESIZE];		//存储“地址到主机名”的映射（可以是 IP 地址到主机名，或其他类型的地址到名称）；静态储存，在整个程序执行期间持续存在
static struct hnamemem tporttable[HASHNAMESIZE];		//存储传输层端口号（如 TCP 或 UDP 端口号）到名称的映射。可能用于将端口号转换为服务名称（例如，端口 80 对应 HTTP）
static struct hnamemem uporttable[HASHNAMESIZE];		//存储用户定义的端口号到名称的映射。通常用于存储一些特定应用程序或协议的端口号
static struct hnamemem eprototable[HASHNAMESIZE];		//存储协议类型到名称的映射，例如将协议编号转换为协议名称（例如，将协议 ID 1 转换为 ICMP，6 转换为 TCP）
static struct hnamemem dnaddrtable[HASHNAMESIZE];		//存储 DNS 地址到名称的映射，可能用于进行 DNS 查询和反向查找
static struct hnamemem ipxsaptable[HASHNAMESIZE];		// 存储 IPX 地址到名称的映射。如果代码涉及到 IPX 协议，可能用于将 IPX 地址转换为名称
//主要作用，地址到名称的映射；

#ifdef _WIN32
/*
 * fake gethostbyaddr for Win2k/XP
 * gethostbyaddr() returns incorrect value when AF_INET6 is passed
 * to 3rd argument.
 *
 * h_name in struct hostent is only valid.
 */
static struct hostent *
win32_gethostbyaddr(const char *addr, int len, int type)
{
	static struct hostent host;
	static char hostbuf[NI_MAXHOST];
	char hname[NI_MAXHOST];

	host.h_name = hostbuf;
	switch (type) {
	case AF_INET:
		return gethostbyaddr(addr, len, type);
		break;
#ifdef AF_INET6
	case AF_INET6: {
		struct sockaddr_in6 addr6;
		memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		memcpy(&addr6.sin6_addr, addr, len);
		if (getnameinfo((struct sockaddr *)&addr6, sizeof(addr6),
		    hname, sizeof(hname), NULL, 0, 0)) {
			return NULL;
		} else {
			strlcpy(host.h_name, hname, NI_MAXHOST);
			return &host;
		}
		break;
	}
#endif /* AF_INET6 */
	default:
		return NULL;
	}
}
#define gethostbyaddr win32_gethostbyaddr
#endif /* _WIN32 */
// 这段代码是为了解决在 Windows 2000/XP 系统上调用 gethostbyaddr() 函数时，遇到 AF_INET6（IPv6）地址族时返回错误值的问题
// gethostbyaddr() 根据IP地址获取主机名的函数

struct h6namemem {
	nd_ipv6 addr;
	char *name;
	struct h6namemem *nxt;
};

static struct h6namemem h6nametable[HASHNAMESIZE];

