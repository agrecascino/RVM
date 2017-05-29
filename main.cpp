#include <iostream>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <bitset>
#include <string.h>
#include <chrono>
#include <thread>
#include <limits>
#include <cstdint>
#include <assert.h>
#include <functional>
#include <vector>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <map>
#include <sys/socket.h>
#include <netdb.h>
#include <algorithm>
#include <fstream>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <SDL/SDL.h>
#include <SDL/SDL_ttf.h>
#include <math.h>
#include <semaphore.h>
#define STORE32C 3
#define STORE32 2
#define STORE16 1
#define STORE8 0
#define MAX INT32_MAX
#define MIN INT32_MIN
#define ILLEGAL_INSTRUCTION 0
#define PERMISSION_EXCEPTION 1
#define RAPIC_EOI 4
#define RAPIC_DANCE 1
#define RAPIC_FAIRY 2
#define RAPIC_WAIFU 3
#define int128_t __int128_t
#define dispatch goto *handlers[inst.split[0] & 0xFE];
#define fetch         pc += 4; \
                      inst.full = *baseaddr.read32(pc);

class CPUException : public std::exception {
    public:
    CPUException(int exception_type) {
        type = exception_type;
    }
    int getExceptionType() const {
        return type;
    }

    private:
    int type;

};

void split_string(std::string const &k, std::string const &delim, std::vector<std::string> &output)
{
    // Due to the use of strpbrk here, this will stop copying at a null char. This is in fact desirable.
    char const *last_ptr = k.c_str(), *next_ptr;
    while ((next_ptr = strpbrk(last_ptr, delim.c_str())) != nullptr)
    {
        output.emplace_back(last_ptr, next_ptr - last_ptr);
        last_ptr = next_ptr + 1;
    }
    output.emplace_back(last_ptr);
}


int checked_add(int64_t a, int64_t b, int64_t *rp) {
  int128_t lr = (int128_t)a + (int128_t)b;
  if(rp != NULL)
      *rp = lr;
  return lr > MAX || lr < MIN;
}

int checked_sub(int64_t a, int64_t b, int64_t *rp) {
  int128_t lr = (int128_t)a - (int128_t)b;
  if(rp != NULL)
    *rp = lr;
  return lr > MAX || lr < MIN;
}

template<bool is_signed, typename T>
class IsNegativeFunctor;

template<typename T>
class IsNegativeFunctor<true, T> {
 public:
  bool operator()(T x) {
    return x < 0;
  }
};

template<typename T>
class IsNegativeFunctor<false, T> {
 public:
  bool operator()(T x) {
    // Unsigned type is never negative.
    return false;
  }
};

template<typename T>
bool IsNegative(T x) {
  return IsNegativeFunctor<std::numeric_limits<T>::is_signed, T>()(x);
}

template<typename To, typename From>
bool WillOverflow(From val) {
  assert(std::numeric_limits<From>::is_integer);
  assert(std::numeric_limits<To>::is_integer);
  if (std::numeric_limits<To>::is_signed) {
    return (!std::numeric_limits<From>::is_signed &&
              (uintmax_t)val > (uintmax_t)INTMAX_MAX) ||
           (intmax_t)val < (intmax_t)std::numeric_limits<To>::min() ||
           (intmax_t)val > (intmax_t)std::numeric_limits<To>::max();
  } else {
    return IsNegative(val) ||
           (uintmax_t)val > (uintmax_t)std::numeric_limits<To>::max();
  }
}

struct MemRange {
    MemRange(unsigned int address, unsigned int length) : address(address), length(length) {}
    unsigned long address;
    unsigned long length;
};


class RMMU {
    public:
    RMMU(unsigned char* baseptr) {
        baseaddr = baseptr;
    }

    unsigned char* read8(unsigned int offset) {
        return (unsigned char*)(baseaddr + offset);
    }

    unsigned short* read16(unsigned int offset) {
        return (unsigned short*)(baseaddr + offset);
    }

    unsigned int* read32(unsigned int offset) {
        return (unsigned int*)(baseaddr + offset);
    }

    unsigned long* read64(unsigned int offset) {
        return (unsigned long*)(baseaddr + offset);
    }

    void write(unsigned int assign, unsigned int length, void* val) {
        //unsigned char endian[length];
        //for(int i = length - 1;i <= 0;i--) {
        //    endian[i] = ((unsigned char*)val)[(length - i)];
        //}
        memcpy((baseaddr + assign),&val,length);
    }
    /*
    unsigned char* safecopy(unsigned int length, void* dest, void* src) {
        return baseaddr;
    }
    */

    void map(MemRange mrange,std::function<void(unsigned int, unsigned int, bool)> &func) {
        //maps[mrange] = func;
    }


    private:
    //std::map<MemRange,std::function<void(unsigned int, unsigned int, bool)>> maps;
    unsigned char* baseaddr;
};

class RIOMMU {

};


class RVM;

union instruction {
    unsigned char split[4];
    unsigned int full;
};

class RVM {
    public:
    RVM(RMMU &mmu) : baseaddr(mmu){
        gettimeofday(&initial,NULL);
    }
    void add_to_clock(std::function<void()> function) {
        function_list.push_back(function);
    }

    int irq(unsigned char interrupt) {
        if(flags[2] == 1) {
            while(flags[2] == 1){
                std::this_thread::sleep_for(std::chrono::microseconds(20));
            }
        }
        this->interrupt = true;
        interrupt_vector = interrupt;
        std::cout << "Interrupt recieved: " << (int)interrupt_vector << std::endl;
        return 1;
    }

    void start(bool debug, bool silent) {
        instruction inst;
        inst.full = *baseaddr.read32(pc);
        static void* handlers[] = { &&privcode, &&reserved, &&reserved };
        dispatch
        privcode:
        fetch
        dispatch
        thing2:
        fetch
        dispatch
        thing3:
        fetch
        dispatch
        interrupt:
        dispatch
        reserved:
        dispatch
    }
    unsigned char interrupt_vector;
    std::bitset<8> flags;
    unsigned long r[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    std::vector<std::function<void()>> function_list;
    private:
    long breakpoint = -1;
    unsigned long n_inst = 0;
    RMMU &baseaddr;
    int interrupt = false;
    int interrupts_enabled = true;
    unsigned long itableptr = 0;
    unsigned long callstackptr = 0;
    unsigned long pc = 0;
    timeval initial, stop;

};

class RAPIC {
public:
    RAPIC(RVM &rvm, RMMU &mmu) : mmu(mmu), r(rvm) {
        sem_init(&semaphore, 0, 1);
    }

    void interrupt(unsigned char num){
        std::cout << "Maxed: " << std::min((int)num,64) << std::endl;
        interrupts[std::min((int)num,64)] = 1;
        sem_post(&semaphore);
    }

    void check_for_interrupts() {
        for(size_t i = 0; i < 64; i++){
            if(interrupts[i] == 1) {
                interrupts[i] = 0;
                holding_line = true;
                current_interrupt = i;
                r.irq(i + 16);
                break;
            }
        }
    }

    void work_loop() {
        while(true) {
            if(!holding_line) {
                check_for_interrupts();
                if(!holding_line) {
                    sem_wait(&semaphore);
                }
            }
            if(holding_line && (*mmu.read8(16000) == RAPIC_EOI)) {
                holding_line = false;
                current_interrupt = 0x9001;
                unsigned int zero = 0;
                mmu.write(16000, 1, &zero);
            }
        }
    }

private:
    sem_t semaphore;
    RMMU &mmu;
    RVM &r;
    unsigned char current_interrupt;
    bool holding_line = false;
    std::bitset<64> interrupts;
};

class RGA {
    public:
        RGA(unsigned char* ptr, RAPIC &rapic): rapic(rapic) {
            SDL_Init(SDL_INIT_EVERYTHING);
            screen = SDL_SetVideoMode(320,240,32,SDL_DOUBLEBUF);
            TTF_Init();
            memory = ptr;
            palette[0].r = 0;
            palette[0].g = 0;
            palette[0].b = 0;
            palette[1].r = 0;
            palette[1].g = 0;
            palette[1].b = 170;
            palette[2].r = 0;
            palette[2].g = 170;
            palette[2].b = 0;
        }
        void do_stuff() {
            if(memory[16383] != 0) {
                //std::cout << "Blitting framebuffer to screen" << std::endl;
                SDL_Surface *buf = SDL_CreateRGBSurfaceFrom(&memory[16384],320,240,8,320,0,0,0,0);
                SDL_SetPalette(buf,SDL_LOGPAL | SDL_PHYSPAL,palette,0,256);
                SDL_BlitSurface(buf,NULL,screen,NULL);
                SDL_Flip(screen);
                memory[16383] = 0;
                SDL_FreeSurface(buf);
            }
        }
        ~RGA() {
            delete[] palette;
        }
    private:
        RAPIC &rapic;
        SDL_Color *palette = new SDL_Color[256];
        SDL_Surface *screen;
        unsigned char* memory;
};


class RTTY {
    public:
        RTTY(unsigned char *ptr, RAPIC &rapic): rapic(rapic) {
            memory = ptr;
            server = socket(AF_INET,SOCK_STREAM,0);
            int enable = 1;
            setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&enable,sizeof(int));
            sockaddr_in localhost;
            memset(&localhost,'0',sizeof(localhost));
            localhost.sin_family = AF_INET;
            localhost.sin_port = htons(3423);
            localhost.sin_addr.s_addr = htonl(INADDR_ANY);
            bind(server,(struct sockaddr*)&localhost,sizeof(localhost));
            listen(server,4);
            conn_thread = std::thread(&RTTY::acceptconnections,this);
            conn_thread.detach();
            signal(SIGPIPE,SIG_IGN);
        }
        void acceptconnections() {
            while(true) {
                clients.push_back(accept(server,NULL,NULL));
            }
        }

        void do_stuff() {
            if(memory[16282] != 0) {
                rapic.interrupt(24);
                for(int client : clients) {
                    char data = 0;

                    ssize_t retval = recv(client,&data,1,MSG_DONTWAIT);
                    if(retval == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            clients.erase(std::remove(clients.begin(),clients.end(),client),clients.end());
                            continue;
                        }

                    }
                    if(retval == 0) {
                        clients.erase(std::remove(clients.begin(),clients.end(),client),clients.end());
                        continue;
                    }
                    send(client,&memory[16281],1,0);
                }

            }
            memory[16282] = 0;

        }
    private:
        RAPIC &rapic;
        std::thread conn_thread;
        std::vector<int> clients;
        int server;
        unsigned char *memory;
};

using namespace std;

int main()
{
    unsigned char *arr = new unsigned char[16777216]; //16M of ram
    memset(arr,0x00,16777216);
    RMMU mmu(arr);
    RVM rvm(mmu);
    RAPIC rapic(rvm, mmu);
    RTTY tty(arr,rapic);
    RGA rga(arr,rapic);
    rvm.add_to_clock(std::bind(&RTTY::do_stuff,&tty));
    rvm.add_to_clock(std::bind(&RGA::do_stuff,&rga));
    fstream f("test.rom");
    if(f.is_open()) {
        char c;
        int i =0;
        while(f.get(c)) {
            arr[i] = c;
            i++;
        }
    }
    /*arr[255] = 'H';
    arr[256] = 'e';
    arr[257] = 'l';
    arr[258] = 'l';
    arr[259] = 'o';
    arr[260] = ' ';
    arr[261] = 'w';
    arr[262] = 'o';
    arr[263] = 'r';
    arr[264] = 'l';
    arr[265] = 'd';
    arr[266] = '!';
    arr[267] = '\n';
    arr[16383] = 1;
    arr[43] = HLT;
    arr[0] = SSP;
    arr[1] = 0x01;
    arr[2] = 0x00;
    arr[3] = 0x00;
    arr[4] = 0x00;
    arr[5] = 0xff;
    arr[6] = POP8;
    arr[7] = 0xe0;
    arr[8] = 0xff;
    arr[9] = 0xe1;
    arr[10] = 0x00;
    arr[11] = 0x00;
    arr[12] = 0x00;
    arr[13] = 0x00;
    arr[14] = JZ;
    arr[15] = 0x01;
    arr[16] = 0x00;
    arr[17] = 0x00;
    arr[18] = 0x00;
    arr[19] = 0x2b;
    arr[20] = MOV;
    arr[21] = 0x01;
    arr[22] = 0x00;
    arr[23] = 0x00;
    arr[24] = 0x3f;
    arr[25] = 0x99;
    arr[26] = ST;
    arr[27] = 0xe0;
    arr[28] = INC;
    arr[29] = 0x00;
    arr[30] = ST;
    arr[31] = 0xe0;
    arr[32] = DEC;
    arr[33] = 0x00;
    arr[34] = JMP;
    arr[35] = 0x01;
    arr[36] = 0x00;
    arr[37] = 0x00;
    arr[38] = 0x00;
    arr[39] = 0x06;*/
    std::thread t ([&](){rapic.work_loop();});
    t.detach();
    rvm.start(true, false);
    delete[] arr;
    return 0;
}
