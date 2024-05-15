#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <string.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "set_wrapper.h"
#include <time.h>

int flag=0;
char* filename = NULL;
StringSet* set;
void usage() {
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test test.gilgil.net\n");
}

int IpHeader(unsigned char* buf){
	int HeaderLen = (buf[0] & 0xf) * 4;
	int i;
	printf("[ip header : %dbytes]\n", HeaderLen);
	for(i=0; i<HeaderLen; i++){
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
	printf("protocol num : %d\n", buf[9]);
	/*Check TCP protocol*/
	if(buf[9]!=6){
		printf("[Not TCP protocol]\n");
		return -1;
	}
	return i;
}

int TcpHeader(unsigned char* buf, int offset){
	int HeaderLen = (buf[offset+12] >> 4) * 4;
	int i;
	printf("[tcp header : %dbytes]\n", HeaderLen);
	for(i=0; i<HeaderLen; i++){
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i+offset]);
	}
	printf("\n");
	return i+offset;
}

int CheckHttp(unsigned char* buf, int offset){
	//check Request's method, Response's status line
	char *Method[9] = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"};
	int LeterrLen[9] = {3,4,3,5,6,4,7,7,5};
	int ret=0;
	int flag=0; //When flag=1 -> HTTP / flag=0 -> Not HTTP
	/*Check requeset*/
	for(int i=0; i<9; i++){
		ret = memcmp(buf+offset, Method[i], LeterrLen[i]);
		if(ret==0){
			flag=1;
			break;
		}
	}
	/*return flag*/
	return flag;
}

int Http(unsigned char* buf, int offset, int size){
	printf("[HTTP hex dump]\n");
	for(int i=0; i<size-offset; i++){
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i+offset]);
	}
	printf("\n");
	
	char* ptr1 = strstr(buf+offset, "Host:");
	int detect=0;
	if (ptr1){
	  	ptr1 = strtok(ptr1, "\r\n");
		printf("%s\n", ptr1);
		clock_t start = clock();
		detect = set_contains(set,ptr1+6);
		clock_t end = clock();
		printf("Find host algorithm time: %lf\n", (double)(end - start) / CLOCKS_PER_SEC);
	 	if(detect){
			printf("[Detect domain name!!!]\n");
			return 0;
		}
		else return 1;
	}
	else{
		printf("[No exist host]\n");
		return 1;
	}
}

int dump(unsigned char* buf, int size) {
	printf("\n");
	int i;
	int check;
	i = IpHeader(buf);
	/*Check TCP protocol*/
	if(i<0){
		return 1;
	}
	i = TcpHeader(buf, i);
	check = CheckHttp(buf, i);
	if(check){
		return Http(buf, i, size); //if return 0 -> detect site, 1 -> safe site
	}
	else{
		printf("[Not HTTP packet!!!]\n");
		return 1;
	}
}

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
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		if(!dump(data, ret)){
			id = -1;
		}
		printf("payload_len=%d\n", ret);
	}
	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(id<0) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if(argc!=2){
		usage();
		return -1;
	}
	filename = argv[1];
	printf("file name : %s\n",filename);
	/*check host in list*/
	FILE* pFile = fopen(filename, "r");
	char string[128];
	char* ptr;
	set = set_create();
	if(pFile==NULL){
		fprintf(stderr, "File open fail!!!\n");
		exit(1);
	}
	/*insert domain name to set*/
	clock_t start = clock(); //check time insert algorithm
	while(fgets(string, 128, pFile)!=NULL){
		strtok(string, ",");
		ptr = strtok(NULL,"\n");
		set_insert(set, ptr);
	}
	clock_t end = clock(); //end
	printf("Insert set algorithm time: %lf\n", (double)(end - start) / CLOCKS_PER_SEC);
	printf("\n");
	fclose(pFile);

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
			printf("pkt received\n");
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
	/*destroy set*/
	set_destroy(set);

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