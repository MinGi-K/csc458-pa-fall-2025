#include "sr_router.h"

#include <assert.h>
#include <stdio.h>
#include <string.h> /* memset, memcpy */
#include <stdlib.h> /* malloc, free   */

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %u\n", len);

  struct sr_packet_parts *packet_parts = malloc(sizeof(struct sr_packet_parts));
  if (!packet_parts)
  {
    printf("*** drop: malloc sr_packet_parts failed\n");
    return;
  }

  int error = parse_frame(packet, len, packet_parts);
  if (error != 0)
  {
    printf("*** drop: parse_frame error=%d\n", error);
    free(packet_parts);
    return;
  }

  /* check for ARP */
  if (packet_parts->packet_type == L2_ARP)
  {
    struct sr_if *sr_interface = sr_get_interface(sr, interface);
    /* sanity check */
    if (!sr_interface)
    {
      printf("*** drop: ARP but sr_get_interface('%s') NULL\n", interface);
      free(packet_parts);
      return;
    }
    if (!packet_parts->arp_header)
    {
      printf("*** drop: ARP path but arp_header NULL\n");
      free(packet_parts);
      return;
    }

    uint16_t op = ntohs(packet_parts->arp_header->ar_op);
    if (op == arp_op_request)
    {
      handle_arp_request(sr, sr_interface, packet_parts);
    }
    else
    {
      /* TODO: handle arp dispatch later. */
      printf("*** note: ARP op=0x%04x ignored for now\n", op);
    }

    free(packet_parts);
    return;
  }

  /* temporary - only process IP packets */
  if (packet_parts->packet_type != L2_IP)
  {
    printf("*** drop: non-IP EtherType=0x%04x, packet_type=%d\n",
           packet_parts->ether_type, (int)packet_parts->packet_type);
    free(packet_parts);
    return;
  }

  /* verify checksum */
  if (verify_ip_checksum(packet_parts->ip_header, (size_t)packet_parts->ip_header_length) != 1)
  {
    printf("*** drop: bad IPv4 header checksum\n");
    free(packet_parts);
    return; /* wrong checksum */
  }

  /* check if dst is for router */
  if (is_dst_sr_router_interface(sr, packet_parts->ip_header->ip_dst))
  {
    /* ICMP echo request */
    if (packet_parts->packet_type == L2_IP &&
        packet_parts->ip_protocol_type == L3_ICMP &&
        packet_parts->icmp_header &&
        packet_parts->icmp_header->icmp_code == 0 &&
        packet_parts->icmp_header->icmp_type == 8)
    {
      struct sr_if *actual_interface = sr_get_interface(sr, interface);
      if (!actual_interface)
      {
        printf("*** drop: sr_get_interface('%s') returned NULL\n", interface);
        free(packet_parts);
        return;
      }
      handle_icmp_echo_req(sr, actual_interface, packet_parts);
    }
    /* else: other to-me traffic (TCP/UDP) not handled yet in Phase 2 */
  }
  else
  {
    /* Not for me; forwarding not implemented yet */
    printf("*** drop: dst is not router IP (forwarding not implemented yet)\n");
  }

  free(packet_parts);
}

/* parses and returns pointer to ethernet header. */
int parse_frame(uint8_t *frame, unsigned int len, struct sr_packet_parts *packet_parts)
{
  memset(packet_parts, 0, sizeof(*packet_parts));

  /* useful constants */
  unsigned int ether_header_offset = sizeof(sr_ethernet_hdr_t);

  /* Whole Frame */
  packet_parts->frame = frame;
  packet_parts->frame_length = len;

  /* L1 Ethernet Header */
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    printf("*** drop: too short for Ethernet header: len=%u need>=%zu\n",
           len, sizeof(sr_ethernet_hdr_t));
    return 1;
  }

  packet_parts->ether_header = (sr_ethernet_hdr_t *)frame;
  packet_parts->ether_type = ntohs(packet_parts->ether_header->ether_type);

  if (packet_parts->ether_type == ethertype_ip)
  {
    packet_parts->packet_type = L2_IP;
  }
  else if (packet_parts->ether_type == ethertype_arp)
  {
    packet_parts->packet_type = L2_ARP;
  }
  else
  {
    /* not IP/ARP is allowed to fall through and succeed as UNKNOWN */
  }

  /* L2 IP Header (if L2_IP) */
  if (packet_parts->packet_type == L2_IP)
  {
    if (len < ether_header_offset + sizeof(sr_ip_hdr_t))
    {
      printf("*** drop: too short for minimal IP header: len=%u need>=%u\n",
             len, (unsigned)(ether_header_offset + sizeof(sr_ip_hdr_t)));
      return 1;
    }

    packet_parts->ip_header = (sr_ip_hdr_t *)(frame + ether_header_offset);
    packet_parts->ip_header_length = (unsigned)packet_parts->ip_header->ip_hl * 4u;

    if (packet_parts->ip_header->ip_v != 4)
    {
      printf("*** drop: not IPv4: ip_v=%u\n", packet_parts->ip_header->ip_v);
      return 2; /* version wrong */
    }

    if (packet_parts->ip_header_length < sizeof(sr_ip_hdr_t))
    {
      printf("*** drop: invalid IP header length: ihl=%u (%u bytes) < %zu\n",
             packet_parts->ip_header->ip_hl,
             packet_parts->ip_header_length,
             sizeof(sr_ip_hdr_t));
      return 1;
    }

    if (len < sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length)
    {
      printf("*** drop: frame too short for full IP header: len=%u need>=%u\n",
             len, (unsigned)(sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length));
      return 1;
    }

    uint16_t ip_total_len = ntohs(packet_parts->ip_header->ip_len);

    if (ether_header_offset + ip_total_len > len)
    {
      printf("*** drop: IP total length exceeds frame: ip_total_len=%u, frame_len=%u, eth_off=%u\n",
             ip_total_len, len, ether_header_offset);
      return 1;
    }

    /* L3 ICMP Header and Protocol Types */
    switch (packet_parts->ip_header->ip_p)
    {
    case 1: /* ICMP */
      packet_parts->ip_protocol_type = L3_ICMP;

      if (len < sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length + sizeof(sr_icmp_hdr_t))
      {
        printf("*** drop: frame too short for ICMP header: len=%u need>=%u\n",
               len, (unsigned)(sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length + sizeof(sr_icmp_hdr_t)));
        return 1;
      }

      if (ip_total_len < packet_parts->ip_header_length + sizeof(sr_icmp_hdr_t))
      {
        printf("*** drop: IP total length too small for ICMP header: ip_total_len=%u need>=%u\n",
               ip_total_len, (unsigned)(packet_parts->ip_header_length + sizeof(sr_icmp_hdr_t)));
        return 1;
      }

      packet_parts->icmp_header = (sr_icmp_hdr_t *)(frame + sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length);
      break;

    case 6:
      packet_parts->ip_protocol_type = L3_TCP;
      break;

    case 17:
      packet_parts->ip_protocol_type = L3_UDP;
      break;

    default:
      packet_parts->ip_protocol_type = L3_NONE;
      break;
    }
  }
  else if (packet_parts->ether_type == ethertype_arp)
  {
    packet_parts->packet_type = L2_ARP;

    if (len < ether_header_offset + sizeof(sr_arp_hdr_t))
    {
      printf("*** drop: too short for ARP header: len=%u need>=%u\n",
             len, (unsigned)(ether_header_offset + sizeof(sr_arp_hdr_t)));
      return 1;
    }

    packet_parts->arp_header = (sr_arp_hdr_t *)(frame + ether_header_offset);
  }
  return 0;
}

int is_dst_sr_router_interface(struct sr_instance *sr, uint32_t dst_address_nbo)
{
  struct sr_if *sr_interface = sr->if_list;
  while (sr_interface)
  {
    if (sr_interface->ip == dst_address_nbo)
    {
      return 1;
    }
    sr_interface = sr_interface->next;
  }
  return 0;
}

int verify_ip_checksum(sr_ip_hdr_t *ip_header, size_t len)
{
  uint16_t original = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t new = cksum(ip_header, len);

  ip_header->ip_sum = original; /* restore back */
  if (original == new)
  {
    return 1;
  }
  return 0;
}

int handle_icmp_echo_req(struct sr_instance *sr, struct sr_if *sr_interface, struct sr_packet_parts *packet_parts)
{
  /* ETHERNET */
  uint8_t dst_mac[ETHER_ADDR_LEN];
  memcpy(dst_mac, packet_parts->ether_header->ether_shost, ETHER_ADDR_LEN); /* set destination MAC address to source MAC */
  memcpy(packet_parts->ether_header->ether_dhost, dst_mac, ETHER_ADDR_LEN);
  memcpy(packet_parts->ether_header->ether_shost, sr_interface->addr, ETHER_ADDR_LEN); /* set source to interface MAC address */

  /* IP4 */
  sr_ip_hdr_t *ip_header = packet_parts->ip_header;
  ip_header->ip_ttl = 64;           /* set ttl */
  uint32_t tmp = ip_header->ip_src; /* update IP addresses. */
  ip_header->ip_src = ip_header->ip_dst;
  ip_header->ip_dst = tmp;
  ip_header->ip_off = htons(0);                                              /* sanity check */
  ip_header->ip_sum = 0;                                                     /* reset header to 0 to recalculate checksum */
  ip_header->ip_sum = cksum(ip_header, (int)packet_parts->ip_header_length); /* set to new checksum */

  /* ICMP */
  sr_icmp_hdr_t *icmp_header = packet_parts->icmp_header;
  if (!icmp_header)
  {
    printf("*** drop: ICMP header pointer NULL in echo handler\n");
    return -1;
  }
  icmp_header->icmp_code = 0; /* set code to 0 for echo reply */
  icmp_header->icmp_type = 0; /* set type to 0 for echo reply */

  /* recalculate icmp checksum */
  int total_ip_len = (int)ntohs(ip_header->ip_len);
  int icmp_len = total_ip_len - (int)packet_parts->ip_header_length;
  if (icmp_len < (int)sizeof(sr_icmp_hdr_t))
  {
    printf("*** drop: computed ICMP length too small: %d\n", icmp_len);
    return -1;
  }
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header, icmp_len);

  int total_len = (int)sizeof(sr_ethernet_hdr_t) + total_ip_len;
  sr_send_packet(sr, (uint8_t *)packet_parts->ether_header, (unsigned)total_len, sr_interface->name);
  printf("*** note: sent ICMP echo reply (%d bytes) on %s\n", total_len, sr_interface->name);
  return 0;
}

int handle_arp_request(struct sr_instance *sr, struct sr_if *sr_interface, struct sr_packet_parts *packet_parts)
{
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)packet_parts->arp_header;
  if (!arp_header)
  {
    printf("*** drop: ARP request handler but arp_header NULL\n");
    return -1;
  }

  /* Find which of my interfaces owns the target IP (arp->ar_tip) */
  struct sr_if *owner = sr->if_list;
  while (owner && owner->ip != arp_header->ar_tip)
    owner = owner->next;

  if (!owner)
  {
    /* Not for me; ignore and drop silently */
    uint32_t tip_h = ntohl(arp_header->ar_tip);
    printf("*** note: ARP request not for me (tip=%u.%u.%u.%u)\n",
           (tip_h >> 24) & 0xFF, (tip_h >> 16) & 0xFF, (tip_h >> 8) & 0xFF, tip_h & 0xFF);
    return 0;
  }

  /* Construct ARP reply */

  /* L2 Ethernet: dst = requester MAC, src = my MAC (of interface that owns the IP) */
  sr_ethernet_hdr_t *ethernet_header = packet_parts->ether_header;
  memcpy(ethernet_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN); /* set destination MAC address to ARP MAC source*/
  memcpy(ethernet_header->ether_shost, owner->addr, ETHER_ADDR_LEN);        /* set source MAC to interface MAC address*/
  ethernet_header->ether_type = htons(ethertype_arp);

  /* L3 ARP: reply with my MAC/IP to the original sender MAC/IP */
  arp_header->ar_hrd = htons(arp_hrd_ethernet); /* hardware is ethernet */
  arp_header->ar_pro = htons(ethertype_ip);     /* resolving an IP request */
  arp_header->ar_hln = ETHER_ADDR_LEN;
  arp_header->ar_pln = 4;

  arp_header->ar_op = htons(arp_op_reply); /* this is a reply */

  unsigned char req_sha[ETHER_ADDR_LEN];               /* requester's source hardware */
  memcpy(req_sha, arp_header->ar_sha, ETHER_ADDR_LEN); /* copy the requester's hardware to temp var */
  uint32_t req_sip = arp_header->ar_sip;               /* requester's source ip */

  memcpy(arp_header->ar_sha, owner->addr, ETHER_ADDR_LEN); /* set source hardware to interface MAC */
  arp_header->ar_sip = owner->ip;                          /* set source ip to interface IP   */
  memcpy(arp_header->ar_tha, req_sha, ETHER_ADDR_LEN);     /* set target MAC to saved requester MAC */
  arp_header->ar_tip = req_sip;                            /* set target IP to saved requester IP  */

  int send_len = (int)(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_send_packet(sr, (uint8_t *)ethernet_header, (unsigned)send_len, sr_interface->name);

  /* LOGGING THAT IT WORKS */
  uint32_t myip_h = ntohl(owner->ip);
  printf("*** note: sent ARP reply %u.%u.%u.%u on %s\n",
         (myip_h >> 24) & 0xFF, (myip_h >> 16) & 0xFF, (myip_h >> 8) & 0xFF, myip_h & 0xFF,
         sr_interface->name);

  return 0;
}
