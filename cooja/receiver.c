#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "net/ipv6/uip-debug.h"

#define UDP_PORT 1234

static struct uip_udp_conn *conn;

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);

static void tcpip_handler(void)
{
  if(uip_newdata()) {
    char *appdata = (char *)uip_appdata;
    appdata[uip_datalen()] = 0;
    PRINTF("Received: '%s'\n", appdata);
  }
}

PROCESS_THREAD(udp_server_process, ev, data)
{
  PROCESS_BEGIN();
  PRINTF("Starting UDP server\n");

  uip_ip6addr_t my_ipaddr;
  uip_ip6addr(&my_ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0002);
  uip_ds6_addr_add(&my_ipaddr, 0, ADDR_MANUAL);

  conn = udp_new(NULL, UIP_HTONS(UDP_PORT), NULL);
  udp_bind(conn, UIP_HTONS(UDP_PORT));

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
