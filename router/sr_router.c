#include "sr_router.h"

#include <assert.h>
#include <stdio.h>

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

  printf("*** -> Received packet of length %d \n", len);

  struct sr_packet_parts *packet_parts;
  int error = parse_frame(packet, len, packet_parts);
  if (error != 0)
  {
    return;
  }

  // temporary - only process IP packets
  if (packet_parts->packet_type != L2_IP)
  {
    return;
  }

  // verify checksum
  if (verify_ip_checksum(packet_parts->ip_header, (size_t)packet_parts->ip_header_length) != 1)
  {
    return 3; // wrong checksum
  }

  // check if dst is for router
  if (is_dst_sr_router_interface(sr, packet_parts->ip_header->ip_dst))
  {
    // ICMP echo request
    if (packet_parts->packet_type == L2_IP && packet_parts->ip_protocol_type == L3_ICMP && packet_parts->icmp_header->icmp_code == 0)
    {
    }
  }
}

// parses and returns pointer to ethernet header.
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
    fprintf(stderr, "[parse_frame] too short for Ethernet header: len=%u need>=%zu\n",
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
      fprintf(stderr, "[parse_frame] too short for minimal IP header: len=%u need>=%u\n",
              len, (unsigned)(ether_header_offset + sizeof(sr_ip_hdr_t)));
      return 1;
    }

    packet_parts->ip_header = (sr_ip_hdr_t *)(frame + ether_header_offset);
    packet_parts->ip_header_length = (unsigned)packet_parts->ip_header->ip_hl * 4u;

    if (packet_parts->ip_header->ip_v != 4)
    {
      fprintf(stderr, "[parse_frame] not IPv4: ip_v=%u\n", packet_parts->ip_header->ip_v);
      return 2; /* version wrong */
    }

    if (packet_parts->ip_header_length < sizeof(sr_ip_hdr_t))
    {
      fprintf(stderr, "[parse_frame] invalid IP header length: ihl=%u (%u bytes) < %zu\n",
              packet_parts->ip_header->ip_hl,
              packet_parts->ip_header_length,
              sizeof(sr_ip_hdr_t));
      return 1;
    }

    if (len < sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length)
    {
      fprintf(stderr, "[parse_frame] frame too short for full IP header: len=%u need>=%u\n",
              len, (unsigned)(sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length));
      return 1;
    }

    uint16_t ip_total_len = ntohs(packet_parts->ip_header->ip_len);

    if (ether_header_offset + ip_total_len > len)
    {
      fprintf(stderr, "[parse_frame] IP total length exceeds frame: ip_total_len=%u, frame_len=%u, eth_off=%u\n",
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
        fprintf(stderr, "[parse_frame] frame too short for ICMP header: len=%u need>=%u\n",
                len, (unsigned)(sizeof(sr_ethernet_hdr_t) + packet_parts->ip_header_length + sizeof(sr_icmp_hdr_t)));
        return 1;
      }

      if (ip_total_len < packet_parts->ip_header_length + sizeof(sr_icmp_hdr_t))
      {
        fprintf(stderr, "[parse_frame] IP total length too small for ICMP header: ip_total_len=%u need>=%u\n",
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
      fprintf(stderr, "[parse_frame] too short for ARP header: len=%u need>=%u\n",
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
  }
  return 0;
}

uint16_t calculate_ip_checksum(sr_ip_hdr_t *ip_header, size_t len)
{
  const uint8_t *pointer = (const uint8_t *)ip_header;
  ip_header->ip_sum = 0;
  uint32_t sum = 0;

  for (size_t i = 0; i + 1 < len; i += 2)
  {
    uint16_t word = ((uint16_t)pointer[i] << 8) | (uint16_t)pointer[i + 1];
    sum += word;
  }

  /* If odd length, pad last byte with zeros on the right. */
  if (len & 1)
  {
    uint16_t last = (uint16_t)pointer[len - 1] << 8;
    sum += last;
  }
  /* Fold carries to 16 bits. */
  while (sum >> 16)
    sum = (sum & 0xFFFFu) + (sum >> 16);

  return (uint16_t)~sum;
}

int verify_ip_checksum(sr_ip_hdr_t *ip_header, size_t len)
{
  uint16_t original = ip_header->ip_sum;
  uint16_t new = calculate_ip_checksum(ip_header, len);

  ip_header->ip_sum = original; // restore back
  if (original == new)
  {
    return 1;
  }
  return 0;
}

int handle_icmp_echo_req(struct sr_if *sr_interface, struct sr_packet_parts *packet_parts)
{
  // ETHERNET
  uint8_t dst_mac[ETHER_ADDR_LEN];
  memcpy(dst_mac, packet_parts->ether_header->ether_shost, ETHER_ADDR_LEN); // set destination MAC address to source MAC
  memcpy(packet_parts->ether_header->ether_dhost, dst_mac, ETHER_ADDR_LEN);
  memcpy(packet_parts->ether_header->ether_shost, sr_interface->addr, ETHER_ADDR_LEN); // set source to interface MAC address
}