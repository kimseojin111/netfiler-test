#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <stdbool.h> // bool
#include <netinet/ip.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h> 
#include <sys/wait.h>
#include <libnetfilter_queue/libnetfilter_queue.h>



char* malhost;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ",
			//ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		//printf("hw_src_addr=");
		//for (i = 0; i < hlen-1; i++)
			//printf("%02x:", hwph->hw_addr[i]);
		//printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		//printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		//printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		//printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		//printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		//printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		//printf("payload_len=%d\n", ret);

	//fputc('\n', stdout);

	return id;
}

void dump(char* buf, int size) {


	printf("-----------------------start dump-----------------------\n");
	int i;
	for (i = 0; i < size; i++) {
		//if (i != 0 && i % 16 == 0)
		//	printf("\n");
		printf("%c", buf[i]);
	}
	printf("\n------------------------------------------------------------------------------\n");

}


static int check_pkt(struct nfq_data *tb){
	//int drop_check=NF_ACCEPT;
	int flag = 1;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(tb);
	if (ntohs(ph->hw_protocol) != 0x0800) return 1; 
	//printf("1\n");
	unsigned char *data;
	nfq_get_payload(tb, &data);
	//dump(data, 64);
	struct iphdr* ipv4_header = (struct iphdr*)data; 
	//printf("wtf?\n");
	//printf("ipv4 header length : %d\n",ipv4_header->ihl);
	// printf("ipv4 protocol : %x\n",ipv4_header->protocol);
	if(ipv4_header->protocol != 6) return 1; 

	struct tcphdr* tcp_header = (struct tcphdr*)(data + (ipv4_header->ihl)*4); 

	//printf("Source Port: %d\n", ntohs(tcp_header->th_dport));
    //printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    //printf("Sequence Number: %u\n", ntohl(tcp_header->seq));
    //printf("Acknowledgement Number: %u\n", ntohl(tcp_header->ack_seq));
    //printf("Header Length: %d\n", tcp_header->th_off);
	//printf("tcp header destination %x",ntohs(tcp_header->th_dport));
	//if(ntohs(tcp_header->th_dport)!=0x80) return 1; // tcp protocol 
	//printf("2222222222222222222222222222222222222222222222222222222222222222\n");
	if(ntohs(tcp_header->th_dport)!=80) return 1;
	printf("tcp offset%d!!\n",tcp_header->th_off);
	//char* http_header = (data + (tcp_header->th_off)*4 + (ipv4_header->ihl)*4);
	//char* http_header = (char*)(tcp_header+(char*)(tcp_header->th_off)*4);


	unsigned char* http_header = (data + (ipv4_header->ihl*4) + (tcp_header->th_off*4));
	//printf("\nip %d\ntcp %d\nhttp %d\n",(int)ipv4_header,(int)tcp_header,(int)http_header);
	//printf("start dump\n");
	//printf("\n\n\n-----------------------------------------------------");
	dump(http_header, 256);

	char *line = strtok(http_header, "\r\n");
    printf("First line: %s\n", line);
	//char *method = strtok(line, " ");
	//printf("Method : %s\n",method);
	if ((strncmp(line, "GET", 3)!=0)&&(strncmp(line, "POST", 4)!=0)&&(strncmp(line, "DELETE", 6)!=0)) return 1; 
	if(strstr(line, malhost)!= NULL) return 0; 
	else return 1;

	/*
	struct libnet_ipv4_hdr* ip_header = (struct libnet_ipv4_hdr*)data;
	int offset = ip_header->ip_hl * 4;
	struct libnet_tcp_hdr* tcp_header = (struct libnet_tcp_hdr*)(data + offset);
	// data_idx += tcp_header->th_off * 4;
	
	if (ip_header->ip_p == TCP_PROTOCOL){
		if(ntohs(tcp_header->th_dport) == http_port){
			char* http_header = (data+tcp_header->th_off * 4);
			int check_http_packet = (strncmp((const char *)http_header, "GET ", 4) != 0) && (strncmp((const char *)http_header, "POST", 4) != 0) && (strncmp((const char *)http_header, "PUT", 3) != 0) && (strncmp((const char *)http_header, "DELETE", 5) != 0) ;
			if(check_http_packet) return flag;
			if (strstr(http_header,host)!=NULL){
				printf("report!!!!!!!!!!!!!!!!!11\n");
				return 0;
			}

		}
	
	}*/
	return flag;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");


	//if(check_pkt(nfa)) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); 
	//else return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	check_pkt(nfa);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



void usage() {
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test test.gilgil.net\n");
}



void main(int argc, char **argv)
{
	if(argc!=2) {
		usage();
		return ;
	}
	malhost = argv[1];
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
