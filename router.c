//STOIAN MIRUNA MARIA
//325CB
#include "skel.h"
#include <unistd.h> /* pentru open(), exit() */
#include <fcntl.h> /* O_RDWR */
#include <errno.h> /* perror() **/

#include "parser.h"

#define IP_OFF (sizeof(struct ether_header))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))

int interfaces[ROUTER_NUM_INTERFACES];
struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

int comparaMask(uint32_t mask1, uint32_t mask2){
	if(mask1 < mask2)
			return 1;
	else
			return -1;
	return 0;
}

int compara(const void*pa ,const void*pb){
	struct route_table_entry a =*(struct route_table_entry*)pa;
	struct route_table_entry b=*(struct route_table_entry*)pb;

	if(a.prefix == b.prefix){
		return comparaMask(a.mask,b.mask);
	}
	return a.prefix-b.prefix;
}

void fatal(char * mesaj_eroare){
    perror(mesaj_eroare);
    exit(1);
}
//INTORC NUMARUL TOTAL DE LINII DIN FISIER
int verifica_linii(){
	int nr_linii=0;
	int fd=open("rtable.txt",O_RDONLY);
	if(fd < 0)
		fatal("nu pot deschide fisierul");
	int length_file = lseek(fd,0,SEEK_END);
	char buf[length_file];
	lseek(fd,0,SEEK_SET);
	read(fd,buf,length_file);
	char*token;
	token=strtok(buf,"\n");
	while(token != NULL){
		nr_linii++;
		token=strtok(NULL,"\n");
	}

	close(fd);
	return nr_linii;

}
//PARSEZ TABELA DE RUTARE
//CITESC ELEMENTELE DIN FISIER  COMPLETEZ CAMPURILE SPECIFICE
void read_rtable(struct route_table_entry *rtable){

	int fd=open("rtable.txt",O_RDONLY);

	if(fd < 0)
		fatal("nu pot deschide fisierul");
	int length_file = lseek(fd,0,SEEK_END);
	char buf[length_file];
	lseek(fd,0,SEEK_SET);
	read(fd,buf,length_file);
	char*token;
	token=strtok(buf," \n");
	int index=0;
	while(token != NULL){
		rtable[index].prefix=inet_addr(token);
		token=strtok(NULL," \n");
		rtable[index].next_hop=inet_addr(token);
		token=strtok(NULL," \n");
		rtable[index].mask=inet_addr(token);
		token=strtok(NULL," \n");
		rtable[index].interface=atoi(token);
		token=strtok(NULL," \n");
		
		index++;
	}
	close(fd);
}
//INTORC NUMARUL TOTAL DE LINII DIN FISIER
int nr_lines_arp(){
	int nr_linii=0;
	int fd=open("arp_table.txt",O_RDONLY);
	if(fd < 0)
		fatal("nu pot deschide fisierul");
	int length_file = lseek(fd,0,SEEK_END);
	char buf[length_file];
	lseek(fd,0,SEEK_SET);
	read(fd,buf,length_file);
	char*token;
	token=strtok(buf,"\n");
	while(token != NULL){
		nr_linii++;
		token=strtok(NULL,"\n");
	}

	close(fd);
	return nr_linii-1;
}
//CITESC ELEMENTELE DIN FISIER  COMPLETEZ CAMPURILE SPECIFICE
void read_arp_tabel(struct arp_entry *arp_table){

	int fd=open("arp_table.txt",O_RDONLY);

	if(fd < 0)
		fatal("nu pot deschide fisierul");
	int length_file = lseek(fd,0,SEEK_END);
	char buf[length_file];
	lseek(fd,0,SEEK_SET);
	read(fd,buf,length_file);
	char*token;
	token=strtok(buf," \n");
	int index=0;
	while(token != NULL){
		arp_table[index].ip=inet_addr(token);
		token=strtok(NULL," \n");
		if(token == NULL)
			break;
		hwaddr_aton(token,arp_table[index].mac);
		token=strtok(NULL," \n");
		
		index++;
	}
	close(fd);
}
//Algoritm de cautare in tabela de rutare
//CAUT VALOAREA CEA MAI SPECIFICA
int maxim(struct route_table_entry* arr,int mid,uint32_t prefix){
	while(arr[mid].prefix == prefix){
		mid--;
	}
	return mid+1;
}
//RETURNEZ INDEXUL LA CARE SE GASESTE CEA MAI BUNA INTRARE
//ACEASTA SE REALIZEAZA CU O CAUTARE BINARA
int binarySearch(struct route_table_entry* arr, int l, int r, uint32_t dest_ip)  { 
    if (r >= l) { 
        int mid = l + (r - l) / 2; 
  
        if ((arr[mid].mask&dest_ip) == arr[mid].prefix) {
			return maxim(arr,mid,arr[mid].prefix);
        }
        if ((arr[mid].mask&dest_ip) < arr[mid].prefix)
            return binarySearch(arr, l, mid - 1, dest_ip); 
        return binarySearch(arr, mid + 1, r, dest_ip); 
    } 
    return -1; 
}
//RETURNEZ ADRESA CELEI MAI BUNA RUTE
struct route_table_entry *get_best_route(__u32 ip){
	int valoare = binarySearch(rtable,0,rtable_size-1,ip);
	if(valoare == -1)
		return NULL;
	return &rtable[valoare];
}
//RETURNEZ ADRESA CELEI MAI BUNA RUTE
struct arp_entry *get_arp_entry( __u32 ip) {
   
    for(int i = 0; i < arp_table_len; i++){
    	if(arp_table[i].ip == ip)
    		return &arp_table[i];
    }
    return NULL;
}

uint16_t ip_checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;

	uint64_t acc=0xffff;

	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}


	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}
	return htons(~acc);
}
int main(int argc, char *argv[]) {
	packet m;
	int rc;
	

	rtable_size=verifica_linii();
	rtable = malloc(sizeof(struct route_table_entry) *(rtable_size));//ALOC TABELA CU NUMARUL DE LINII
	read_rtable(rtable);//COMPLETEZ CAMPURILE SPECIFICE
	qsort(rtable,rtable_size,sizeof(struct route_table_entry),compara);//SORTEZ TABELA

	arp_table_len=nr_lines_arp();
	arp_table = malloc(sizeof(struct arp_entry) * (arp_table_len));//ALOC TABELA
	read_arp_tabel(arp_table);//COMPLETEZ CAMPURILE SPECIFICE

	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

	init();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		if(eth_hdr->ether_type ==htons( ETHERTYPE_IP)){

			
			if(ip_hdr->protocol == IPPROTO_ICMP){

				if(icmp_hdr->type == ICMP_ECHO && ((ip_hdr->daddr) ==inet_addr(get_interface_ip(m.interface)))){
					//CREEZ UN NOU PACHET IAR 
					//COMPLETEZ CAMPURILE CU VALORILE SPECIFICE
					packet reply_packet;
					memset(reply_packet.payload,0,sizeof(reply_packet.payload));
					reply_packet.len = sizeof(struct ether_header) + sizeof(struct iphdr)+ sizeof(struct icmphdr);
					reply_packet.interface = m.interface;

					struct icmphdr *copie_icpm = (struct icmphdr *)(reply_packet.payload + ICMP_OFF);
					struct iphdr* copie_ip_hdr =(struct iphdr *)(reply_packet.payload + IP_OFF);
					struct ether_header* eth_hdr_copie = (struct ether_header*)(reply_packet.payload);

					copie_ip_hdr->version = 4;
					copie_ip_hdr->ihl = 5;
					copie_ip_hdr->tos = 0;
					copie_ip_hdr->tot_len = htons(reply_packet.len-sizeof(struct ether_header));
					copie_ip_hdr->id = htons(25);
					copie_ip_hdr->ttl=ip_hdr->ttl;
					copie_ip_hdr->protocol = IPPROTO_ICMP;
					copie_ip_hdr->check = 0;
					copie_ip_hdr->check = ip_checksum(copie_ip_hdr,sizeof(struct iphdr));
					

					copie_icpm->code = 0;
					copie_icpm->type = 0;
					copie_icpm->un.echo.id=htons(25);
					copie_icpm->un.echo.sequence=htons(1);
					copie_icpm->checksum=0;
					copie_icpm->checksum=ip_checksum(copie_icpm,sizeof(struct icmphdr));


					memcpy(eth_hdr_copie->ether_dhost,eth_hdr->ether_shost,6);
					memcpy(eth_hdr_copie->ether_shost,eth_hdr->ether_dhost,6);
					eth_hdr_copie->ether_type = htons(ETHERTYPE_IP);

					copie_ip_hdr->daddr = ip_hdr->saddr;
					copie_ip_hdr->saddr =inet_addr(get_interface_ip(m.interface));
					get_best_route(copie_ip_hdr->daddr);
					send_packet((get_best_route(copie_ip_hdr->daddr))->interface,&reply_packet);
					continue;

				}
			}
			if(ip_checksum(ip_hdr,sizeof(struct iphdr))!=0){
				continue;
			}

			if(ip_hdr->ttl <=1){
					//CREEZ UN NOU PACHET IAR 
					//COMPLETEZ CAMPURILE CU VALORILE SPECIFICE
					packet reply_packet;
					memset(reply_packet.payload,0,sizeof(reply_packet.payload));
					reply_packet.len = sizeof(struct ether_header) + sizeof(struct iphdr)+ sizeof(struct icmphdr);
					reply_packet.interface = m.interface;

					struct icmphdr *copie_icpm = (struct icmphdr *)(reply_packet.payload + ICMP_OFF);
					struct iphdr* copie_ip_hdr =(struct iphdr *)(reply_packet.payload + IP_OFF);
					struct ether_header* eth_hdr_copie = (struct ether_header*)(reply_packet.payload);

					copie_ip_hdr->version = 4;
					copie_ip_hdr->ihl = 5;
					copie_ip_hdr->tos = 0;
					copie_ip_hdr->tot_len = htons(reply_packet.len-sizeof(struct ether_header));
					copie_ip_hdr->id = htons(25);
					copie_ip_hdr->ttl=ip_hdr->ttl;
					copie_ip_hdr->protocol = IPPROTO_ICMP;
					copie_ip_hdr->check = 0;
					copie_ip_hdr->check = ip_checksum(copie_ip_hdr,sizeof(struct iphdr));
					

					copie_icpm->code = 0;
					copie_icpm->type =11;
					copie_icpm->un.echo.id=htons(25);
					copie_icpm->un.echo.sequence=htons(1);
					copie_icpm->checksum=0;
					copie_icpm->checksum=ip_checksum(copie_icpm,sizeof(struct icmphdr));


					memcpy(eth_hdr_copie->ether_dhost,eth_hdr->ether_shost,6);
					memcpy(eth_hdr_copie->ether_shost,eth_hdr->ether_dhost,6);
					eth_hdr_copie->ether_type = htons(ETHERTYPE_IP);

					copie_ip_hdr->daddr = ip_hdr->saddr;
					copie_ip_hdr->saddr =inet_addr(get_interface_ip(m.interface));

					get_best_route(copie_ip_hdr->daddr);
					send_packet((get_best_route(copie_ip_hdr->daddr))->interface,&reply_packet);
					continue;
			}

			struct route_table_entry *route=get_best_route((ip_hdr->daddr));
			if(route == NULL){
					//CREEZ UN NOU PACHET IAR 
					//COMPLETEZ CAMPURILE CU VALORILE SPECIFICE
					packet reply_packet;
					memset(reply_packet.payload,0,sizeof(reply_packet.payload));
					reply_packet.len = sizeof(struct ether_header) + sizeof(struct iphdr)+ sizeof(struct icmphdr);
					reply_packet.interface = m.interface;

					struct icmphdr *copie_icpm = (struct icmphdr *)(reply_packet.payload + ICMP_OFF);
					struct iphdr* copie_ip_hdr =(struct iphdr *)(reply_packet.payload + IP_OFF);
					struct ether_header* eth_hdr_copie = (struct ether_header*)(reply_packet.payload);

					copie_ip_hdr->version = 4;
					copie_ip_hdr->ihl = 5;
					copie_ip_hdr->tos = 0;
					copie_ip_hdr->tot_len = htons(reply_packet.len-sizeof(struct ether_header));
					copie_ip_hdr->id = htons(25);
					copie_ip_hdr->ttl=ip_hdr->ttl;
					copie_ip_hdr->protocol = IPPROTO_ICMP;
					copie_ip_hdr->check = 0;
					copie_ip_hdr->check = ip_checksum(copie_ip_hdr,sizeof(struct iphdr));
					

					copie_icpm->code = 0;
					copie_icpm->type =3;
					copie_icpm->un.echo.id=htons(25);
					copie_icpm->un.echo.sequence=htons(1);
					copie_icpm->checksum=0;
					copie_icpm->checksum=ip_checksum(copie_icpm,sizeof(struct icmphdr));


					memcpy(eth_hdr_copie->ether_dhost,eth_hdr->ether_shost,6);
					memcpy(eth_hdr_copie->ether_shost,eth_hdr->ether_dhost,6);
					eth_hdr_copie->ether_type = htons(ETHERTYPE_IP);
					copie_ip_hdr->daddr = ip_hdr->saddr;
					copie_ip_hdr->saddr =inet_addr(get_interface_ip(m.interface));
					get_best_route(copie_ip_hdr->daddr);
					send_packet((get_best_route(copie_ip_hdr->daddr))->interface,&reply_packet);
					continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check=ip_checksum(ip_hdr,sizeof(struct iphdr));

			struct arp_entry *arp = get_arp_entry(ip_hdr->daddr);
			if(arp == NULL){
				continue;
			}
			memcpy(eth_hdr->ether_dhost,arp->mac,6);
			get_interface_mac(route->interface,eth_hdr->ether_shost);
			send_packet(route->interface, &m);
		}
	}
}
