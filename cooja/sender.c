#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "net/ipv6/uip-debug.h"
#include "sys/etimer.h"

#define SEND_INTERVAL (10 * CLOCK_SECOND)
#define UDP_PORT 1234

static struct uip_udp_conn *conn;
static uip_ipaddr_t dest_ipaddr;

const char* Payload = "Hello world";

PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);

PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;

  PROCESS_BEGIN();
  PRINTF("Starting UDP client\n");

  uip_ip6addr(&dest_ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0002);
  conn = udp_new(NULL, UIP_HTONS(UDP_PORT), NULL);
  udp_bind(conn, UIP_HTONS(UDP_PORT));

  etimer_set(&periodic_timer, SEND_INTERVAL);

  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&periodic_timer)) {
      etimer_reset(&periodic_timer);
      uip_udp_packet_sendto(conn, Payload, strlen(Payload), &dest_ipaddr, UIP_HTONS(UDP_PORT));
    }
  }

  PROCESS_END();
}
