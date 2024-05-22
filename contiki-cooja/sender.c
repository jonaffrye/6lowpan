#include "contiki.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip.h"
#include "net/ip/uip-udp-packet.h"
#include "sys/etimer.h"
#include <stdio.h>
#include <string.h>

#define SEND_INTERVAL (10 * CLOCK_SECOND)
#define UDP_PORT 1234

static struct uip_udp_conn *conn;
static uip_ipaddr_t dest_ipaddr;

PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);

const char* BigPayload = "mdaeqgwnlbfgkrgesxiurvgzcfibpkmbhneivcsmikuekgnjmlvlcrnkvhchsnghpentjesvxglanmrebuvyqvmhvzgpjfaweosvuunspilazzmjekignytqyyemdyczgfffmfupscglntzyttbrskoworzpczjycqhzdlrdqwnfjikkkivmkeolcvbiqhhavaebdyxfdifhrsxwucxlcxfzxfntpfspxntwfkbjetbednohpohqkmylawjmwzoivgesydksnjyhuotgxajfhyxnhswpaetkplysoegbgqsaostvtrfefwhrhqekailpslbeljwxshxcwspmlejqfifpfcgeyohaoahhjgbbionoskhstrucnnfemqaqjfccjgdvvnbarhjzlxgbpnnrdukokfyweuzaiqirjydkqepagmddrovandweryzobmrjrlsdbpczitthiwkxkbplgtfevcjcupbrgguzpuainwpfnvjsrqa"
                        "mdaeqgwnlbfgkrgesxiurvgzcfibpkmbhneivcsmikuekgnjmlvlcrnkvhchsnghpentjesvxglanmrebuvyqvmhvzgpjfaweosvuunspilazzmjekignytqyyemdyczgfffmfupscglntzyttbrskoworzpczjycqhzdlrdqwnfjikkkivmkeolcvbiqhhavaebdyxfdifhrsxwucxlcxfzxfntpfspxntwfkbjetbednohpohqkmylawjmwzoivgesydksnjyhuotgxajfhyxnhswpaetkplysoegbgqsaostvtrfefwhrhqekailpslbeljwxshxcwspmlejqfifpfcgeyohaoahhjgbbionoskhstrucnnfemqaqjfccjgdvvnbarhjzlxgbpnnrdukokfyweuzaiqirjydkqepagmddrovandweryzobmrjrlsdbpczitthiwkxkbplgtfevcjcupbrgguzpuainwpfnvjsrqad";

const char* Payload2 = "mdaeqgwnlbfgkrgesxiurvgzcfibpkmbhneivcsmikuekgnjmlvlcrnkvhchsnghpentjesvxglanmrebuvyqvmhvzgpjfaweosvuunspilazzmjekignytqyyemdyczgfffmfupscglntzyttbrskoworzpczjycqhzdlrdqwnfjikkkivmkeolcvbiqhhavaebdyxfdifhrsxwucxlcxfzxfntpfspxntwfkbjetbednohpohqkmylawjmwzoivgesydksnjyhuotgxajfhyxnhswpaetkplysoegbgqsaostvtrfefwhrhqekailpslbeljwxshxcwspmlejqfifpfcgeyohaoahhjgbbionoskhstrucnnfemqaqjfccjgdvvnbarhjzlxgbpnnrdukokfyweuzaiqirjydkqepagmddrovandweryzobmrjrlsdbpczitthiwkxkbplgtfevcjcupbrgguzpuainwpfnvjsrqad";

const char* Payload = "Hello world";

static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  // Set the link-local address
  uip_ip6addr(&ipaddr, 0xfe80, 0, 0, 0, 0xcafe, 0xdeca, 0, 0x0001); // Change last part for different nodes
  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
  uip_ip6addr(&dest_ipaddr, 0xfe80, 0, 0, 0, 0xcafe, 0xdeca, 0, 0x0002); // Destination address
}

static void
tcpip_handler(void)
{
  if(uip_newdata()) {
    char buf[UIP_BUFSIZE];
    memcpy(buf, uip_appdata, uip_datalen());
    buf[uip_datalen()] = '\0';
    printf("Received packet from ");
    uip_debug_ipaddr_print(&UIP_IP_BUF->srcipaddr);
    printf(": '%s'\n", buf);
  }
}

PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  static int count = 0;

  PROCESS_BEGIN();

  set_global_address();

  conn = udp_new(NULL, UIP_HTONS(UDP_PORT), NULL);
  udp_bind(conn, UIP_HTONS(UDP_PORT));

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
    if(etimer_expired(&periodic_timer)) {
      etimer_reset(&periodic_timer);

      if (count % 3 == 0) {
        uip_udp_packet_sendto(conn, BigPayload, strlen(BigPayload), &dest_ipaddr, UIP_HTONS(UDP_PORT));
      } else if (count % 3 == 1) {
        uip_udp_packet_sendto(conn, Payload2, strlen(Payload2), &dest_ipaddr, UIP_HTONS(UDP_PORT));
      } else {
        uip_udp_packet_sendto(conn, Payload, strlen(Payload), &dest_ipaddr, UIP_HTONS(UDP_PORT));
      }
      count++;
    }
  }

  PROCESS_END();
}
