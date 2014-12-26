#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <fstream>

#define A32 2
#define A24 1
#define A16 0

#define D32 2
#define D16 1
#define D8  0

int vme_write(int sock,int am, int dm, unsigned int address, unsigned int value);
int vme_read(int sock, int am, int dm, unsigned int address, unsigned int* value);
int connect(int sock, const char *host, int port, double timeout_sec);

int main(int argc, char *argv[])
{
  //open infile
  std::ifstream ifs(argv[1]);
  if(!ifs) {
    printf("can not open %s\n",argv[1]);
    exit(EXIT_FAILURE);
  }

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  connect(sock, "192.168.30.41", 24, 0.5);    
 
  //read file and setting
  unsigned int vme_addr=0;
  std::string line;
  while( ifs && getline(ifs, line) ) {
    if(line[0]=='#') continue;
    if(line.substr(0,4)=="VME:"){
      sscanf(line.c_str(),"VME:%x",&vme_addr);
      printf("%s\n",line.c_str());
      
      int Vth[16]={0};
      int Enable[16]={0};
      
      while( ifs && getline(ifs, line) ) {
	if(line[0]=='#') continue;
	if(line.substr(0,3)=="END"){
	 
	  unsigned int value;
	  value=255;
	  //Output width ch 0-7
	  vme_write(sock, A32, D16, vme_addr+0x40, value);
	  //Output width ch 8-15
	  vme_write(sock, A32, D16, vme_addr+0x42, value);
	  //Majority threshpld
	  vme_write(sock, A32, D16, vme_addr+0x48, value);
	  
	  //Pattern of inhibit
	  value=0;
	  for(int i=0;i<16;i++){
	    if(Enable[i]==1){
	      value = value|(0x1<<i);
	    }
	  }	 
	  vme_write(sock, A32, D16, vme_addr+0x4A, value);
	  
	  //Discriminator thresholds
	  for(int i=0;i<16;i++){
	    value = Vth[i];
	    vme_write(sock, A32, D16, vme_addr+0x2*i, value);
	  }

	  break;
	}

	int p1,p2,p3;
	if( sscanf(line.c_str(),"%d %d %d",&p1, &p2, &p3) == 3 ){
	  printf("%s\n",line.c_str());
	  Vth[p1] = p2;
	  Enable[p1] = p3;
	}
      }
    }
  }

  close(sock);
  
  return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////
// internal functions
/////////////////////////////////////////////////////////////////////////////////////////////

int connect(int sock, const char *host, int port, double timeout_sec)
{
  struct timeval tv={(int)timeout_sec, (timeout_sec-(int)timeout_sec)*1000000.};
  
  struct sockaddr_in addr;
  addr.sin_family       = AF_INET;
  addr.sin_port         = htons(port);
  addr.sin_addr.s_addr  = inet_addr(host);

  fd_set set;
  FD_ZERO(&set);
  FD_SET(sock, &set);

  int flags = fcntl(sock, F_GETFL, NULL);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK); 

  connect(sock, (struct sockaddr*)&addr, sizeof(addr));

  if(select(sock+1, NULL, &set, NULL, &tv) < 1){
    printf("cannot connect to %s:%d\n",host,port);
    close(sock);
    exit(0);
  }

  fcntl(sock, F_SETFL, flags);
  printf("#socket open\n");
  return 0;
}


struct sitcp_vme_master_header{
  unsigned int address;
  unsigned int length;
  unsigned short mode;
  unsigned char id;
  unsigned char crc;
};

int receive(int s, char* buf, int len);
unsigned char crcCal(unsigned char crc, unsigned char data);

int vme_read(int sock, int am, int dm, unsigned int address, unsigned int* value)
{
  struct sitcp_vme_master_header sndHeader;
  unsigned char crc;
  unsigned char sndBuf[12];
  
  try
    {

      if(am!=0 && am!=1 && am!=2){
	printf("Unknown Address Mode: %d\n",am);
	throw 1;
      }

      if(dm==0){
	sndHeader.length=htonl(1);
      }else if(dm==1){
	sndHeader.length=htonl(2);
      }else if(dm==2){
	sndHeader.length=htonl(4);
      }else{
	printf("Unknown Data Mode: %d\n",dm);
	throw 1;
      }
  
      sndHeader.address=htonl(address);
      sndHeader.mode=htons(am<<8 | dm<<10);
      sndHeader.id=1;
  
      memcpy(sndBuf, &sndHeader, sizeof(sndHeader));

      crc = 0xFF;
      for(int i=0;i<11;i++) crc=crcCal(crc,sndBuf[i]);  
      sndBuf[11]=crc;

      //send CMD packet
      if(send(sock, sndBuf, sizeof(sndHeader), 0)<0){
	printf("send() failed\n");
	throw 1;
      }

      unsigned char recvBuf[16];
      struct sitcp_vme_master_header rcvHeader;
      
      //receive ACK packet   
      int rLen=0;
      
      rLen = receive(sock, (char*)&rcvHeader, sizeof(rcvHeader));
      if(rLen != sizeof(rcvHeader)){
	printf("Header receive() failed\n");
	throw 1;
      }
  
      memcpy(recvBuf, &rcvHeader, sizeof(rcvHeader));
      
      rcvHeader.address = ntohl(rcvHeader.address);
      rcvHeader.length  = ntohl(rcvHeader.length);
      rcvHeader.mode    = ntohs(rcvHeader.mode);
      
      //Caluculate the received CRC 
      crc=0xFF;
      for(int i=0; i<12; i++) crc=crcCal(crc, recvBuf[i]);
      if(crc!=0){
	printf("ACK CRC ERROR!! : %x (Hex)\n",crc);
	throw 1;
      }
      
      //Error Check
      if((rcvHeader.mode & 0x1)==0x1){
	printf(" ----- Parameter Error !! -----\n");
	throw 1;
      }
      if((rcvHeader.mode & 0x4)==0x4){
	printf(" ----- VME bus TIMEOUT !! -----\n");
	throw 1;
      }
      
      //read VME data
      if(dm==0){
	rLen=0;
	rLen = receive(sock, (char*)(recvBuf+12), 1);
	if(rLen != 1){
	  printf("VME data receive() failed\n");
	  throw 1;
	}
	*value = (unsigned int)recvBuf[12];
	
      }else if(dm==1){
	rLen=0;
	rLen = receive(sock, (char*)(recvBuf+12), 2);
	if(rLen != 2){
	  printf("VME data receive() failed\n");
	  throw 1;
	}
	*value = (unsigned int)(recvBuf[12]<<8 | recvBuf[13]);
	
      }else if(dm==2){
	rLen=0;
	rLen = receive(sock, (char*)(recvBuf+12), 4);
	if(rLen != 4){
	  printf("VME data receive() failed\n");
	  throw 1;
	}
	*value = (unsigned int)(recvBuf[12]<<24 | recvBuf[13]<<16 | recvBuf[14]<<8 | recvBuf[15]);
      }
      
    } 
  catch(...)
    {
      sleep(1);
      close(sock);
      printf("#socket close\n");
      exit(-1);
    }
  return 0;
}

int vme_write(int sock, int am, int dm, unsigned int address, unsigned int value)
{
  struct sitcp_vme_master_header sndHeader;
  unsigned char crc;
  unsigned char sndBuf[16];
  
  try
    {

      if(am!=0 && am!=1 && am!=2){
	printf("Unknown Address Mode: %d\n",am);
	throw 1;
      }

      if(dm==0){
	sndHeader.length=htonl(1);
      }else if(dm==1){
	sndHeader.length=htonl(2);
      }else if(dm==2){
	sndHeader.length=htonl(4);
      }else{
	printf("Unknown Data Mode: %d\n",dm);
	throw 1;
      }
  
      sndHeader.address=htonl(address);
      sndHeader.mode=htons(0x1<<15 | am<<8 | dm<<10);
      sndHeader.id=1;
      
      memcpy(sndBuf, &sndHeader, sizeof(sndHeader));
      
      crc = 0xFF;
      for(int i=0;i<11;i++) crc=crcCal(crc,sndBuf[i]);
      
      sndBuf[11]=crc;
      
      if(dm==0){
	sndBuf[12]=(unsigned char)value;
	if(send(sock, sndBuf, sizeof(sndHeader)+1, 0)<0){
	  printf("send() failed\n");
	  throw 1;
	}
      }else if(dm==1){
	sndBuf[12]=(unsigned char)((value>>8) &0xFF);
	sndBuf[13]=(unsigned char)( value &0xFF);
	if(send(sock, sndBuf, sizeof(sndHeader)+2, 0)<0){
	  printf("send() failed\n");
	  throw 1;
	}
      }else if(dm==2){
	sndBuf[12]=(unsigned char)((value>>24) &0xFF);
	sndBuf[13]=(unsigned char)((value>>16) &0xFF);
	sndBuf[14]=(unsigned char)((value>>8) &0xFF);
	sndBuf[15]=(unsigned char)( value &0xFF);
	if(send(sock, sndBuf, sizeof(sndHeader)+4, 0)<0){
	  printf("send() failed\n");
	  throw 1;
	}
      }
      
      unsigned char recvBuf[12];
      struct sitcp_vme_master_header rcvHeader;
      
      //receive ACK packet
      int rLen=0;
      
      rLen = receive(sock, (char*)&rcvHeader, sizeof(rcvHeader));
      if(rLen != sizeof(rcvHeader)){
	printf("Header receive() failed\n");
	throw 1;
      }
      
      memcpy(recvBuf, &rcvHeader, sizeof(rcvHeader));
      
      rcvHeader.address = ntohl(rcvHeader.address);
      rcvHeader.length  = ntohl(rcvHeader.length);
      rcvHeader.mode    = ntohs(rcvHeader.mode);
      
      //Caluculate the received CRC 
      crc=0xFF;
      for(int i=0; i<12; i++) crc=crcCal(crc, recvBuf[i]);
      if(crc!=0){
	printf("ACK CRC ERROR!! : %x (Hex)\n",crc);
	throw 1;
      }
  
      //Error Check
      if((rcvHeader.mode & 0x1)==0x1){
	printf(" ----- Parameter Error !! -----\n");
	throw 1;
      }
      if((rcvHeader.mode & 0x4)==0x4){
	printf(" ----- VME bus TIMEOUT !! -----\n");
	throw 1;
      }
      
    }
  catch(...)
    {
      sleep(1);
      close(sock);
      printf("#socket close\n");
      exit(-1);
    }

  return 0;
}

int receive(int s,char* buf,int len){
    int revd_size;
    int tmp;
    revd_size=0;
    while(revd_size<len){                       
        tmp=recv(s,buf+revd_size,len-revd_size,0);
        if(tmp==-1){         
            return -1;
        }
        if(tmp==0){
            return 0;
        }
        revd_size+=tmp;
    }
    return revd_size;
}

unsigned char crcCal(unsigned char crc, unsigned char data)
{
  unsigned char crcReg[9];
  unsigned char inBit;
  
  int i, j;
  unsigned char crcMask = 1;
  
  for(i=0; i<8; i++){
    crcReg[i]=crc;
    crcReg[i]&=crcMask;
    if(crcReg[i]!=0) crcReg[i]=0xFF;
    crcMask<<=1;
  }

  for(i=0; i<8; i++){
    inBit=data & 0x80;
    if(inBit!=0) inBit=0xFF;
    
    crcReg[8]=inBit^crcReg[7];
    
    for(j=7; j>0; j--){
      if(j<3){
	crcReg[j]=crcReg[j-1]^crcReg[8];
      }else{
	crcReg[j]=crcReg[j-1];
      }
    }
    crcReg[0]=crcReg[8];
    data<<=1;
  }
  
  crc=0;
  crcMask=1;
  
  for(i=0; i<8; i++){
    if(crcReg[i]!=0) crc|=crcMask;
    crcMask<<=1;
  }
  return(crc);
}
