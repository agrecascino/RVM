#include <iostream>
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
#define STORE32C 3
#define STORE32 2
#define STORE16 1
#define STORE8 0
#define MAX INT32_MAX
#define MIN INT32_MIN
#define ILLEGAL_INSTRUCTION 0

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


int checked_add(int32_t a, int32_t b, int32_t *rp) {
  int64_t lr = (int64_t)a + (int64_t)b;
  if(rp != NULL)
      *rp = lr;
  return lr > MAX || lr < MIN;
}

int checked_sub(int32_t a, int32_t b, int32_t *rp) {
  int64_t lr = (int64_t)a - (int64_t)b;
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

enum instructions {
    ADD = 0,
    SUB,
    MUL,
    DIV,
    INC,
    AND,
    OR,
    XOR,
    NOT,
    JMP,
    JZ,
    JO,
    LD,
    ST,
    CLC,
    CLZ,
    CALL,
    RET,
    INT,
    HLT,
    ADC,
    MOV,
    PUSH,
    POP,
    SSP,
    GSP,
    CMP,
    LIT,
    CLF,
    C2S,
    C2A,
    C2M,
    C2D,
    OUT,
    IN,
    DEC,
    C2I,
    CDD,
    SBP,
    GBP,
    MOD,
    CMD,
    IRET,
    GFR,
    SFR,
    DSI,
    ENI,
    LSL,
    RSL,
    DSP,
    DBP,
    SWBS,
    POP8,
    POP16,
    PUSH8,
    PUSH16

    //maybe add a conditional move

};


class RMMU {
    public:
    RMMU(unsigned char* baseptr) {
        baseaddr = baseptr;
    }
    void write(unsigned int offset, unsigned char value) {
        baseaddr[offset] = value;
    }
    unsigned char& read(unsigned int offset) {
        return baseaddr[offset];
    }
    unsigned char& operator[](unsigned int assign) {
        return baseaddr[assign];
    }
    unsigned char* get_base() {
        return baseaddr;
    }

    private:
    unsigned char* baseaddr;
};

class RIOMMU {

};

class RTTY {
    public:
        RTTY(unsigned char *ptr) {
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
        }
        void acceptconnections() {
            while(true) {
                clients.push_back(accept(server,NULL,NULL));
            }
        }

        void do_stuff() {
            signal(SIGPIPE,SIG_IGN);
            if(memory[16282] != 0) {
                for(int client : clients) {
                    char data = 0;

                    size_t retval = recv(client,&data,1,MSG_DONTWAIT);
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
        std::thread conn_thread;
        std::vector<int> clients;
        int server;
        unsigned char *memory;
};

class RVM;

class RGA {
    public:
        RGA(unsigned char* ptr) {
            SDL_Init(SDL_INIT_EVERYTHING);
            screen = SDL_SetVideoMode(320,240,32,SDL_DOUBLEBUF);
            TTF_Init();
            memory = ptr;
        }
        void do_stuff() {
            if(memory[16383] != 0) {
                //std::cout << "Blitting framebuffer to screen" << std::endl;
                SDL_Surface *buf = SDL_CreateRGBSurfaceFrom(&memory[16384],320,240,8,320,0,0,0,0);
                SDL_Color *palette = new SDL_Color[256];
                palette[0].r = 0;
                palette[0].g = 0;
                palette[0].b = 0;
                palette[1].r = 0;
                palette[1].g = 0;
                palette[1].b = 170;
                palette[2].r = 0;
                palette[2].g = 170;
                palette[2].b = 0;
                SDL_SetPalette(buf,SDL_LOGPAL | SDL_PHYSPAL,palette,0,256);
                SDL_BlitSurface(buf,NULL,screen,NULL);
                SDL_Flip(screen);
                memory[16383] = 0;

            }
        }

    private:
        SDL_Surface *screen;
        unsigned char* memory;
};

class RVM {
    public:
    RVM(RMMU &mmu) {
        for(int i = ADD;i <= PUSH16;i++) {
            jump_offset[i] = 6;
            inst_length[i] = 2;
        }
        jump_offset[PUSH8] = 3;
        jump_offset[PUSH16] = 4;
        jump_offset[LD] = 2;
        jump_offset[ST] = 2;
        inst_length[DSP] = 1;
        inst_length[DBP] = 1;
        inst_length[CLF] = 1;
        inst_length[SWBS] = 1;
        inst_length[RET] = 1;
        inst_length[IRET] = 1;
        inst_length[HLT] = 1;
        baseaddr = mmu;
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
        interrupt = true;
        return 1;
    }

    void start(bool debug, bool silent) {
        while(1) {
            for(size_t i = 0; i < function_list.size(); i++) {
                // use this to fake hardware properties and do cool processing stuff
                function_list[i]();
            }
            if(pc == breakpoint) {
                gettimeofday(&stop,NULL);
                std::cout << "Hit breakpoint: pc=" << pc << std::endl;
                std::cout << stop.tv_sec << ":" << stop.tv_usec << std::endl;
                std::cout << initial.tv_sec << ":" << initial.tv_usec << std::endl;
                goto breakhit;
            }
            if(debug) {
                breakhit:
                std::string action;
                std::locale ascii;
                back:
                std::cout << "Step(s) Read pointer(r) Get current instruction(i) Get number of instructions ran(n) Go(g) Set Breakpoint(b) Quiet(q) [S/r/i/n/g/b/q]" << std::endl;
                std::getline(std::cin,action);
                if(action.size() == 0) {
                    goto step;
                }
                char eval_this = std::toupper(action[0],ascii);
                if(eval_this == 'S') {
                    goto step;
                } else if(eval_this == 'R') {
                    std::cout << "Unimplemented debugging feature" << std::endl;
                    goto back;
                } else if(eval_this == 'N') {
                    std::cout << "Number of instructions ran: " << n_inst << std::endl;
                    goto back;
                } else if(eval_this == 'I') {
                    std::cout << "Instruction: " << std::hex  << (int)baseaddr[pc] << " " << (int)baseaddr[pc+1] << std::dec << std::endl;
                    goto back;
                } else if(eval_this == 'G') {
                    debug = false;
                    gettimeofday(&initial,NULL);
                    goto step;
                } else if(eval_this == 'B') {
                    std::vector<std::string> output;
                    split_string(action," ",output);
                    breakpoint = atoi(output[1].c_str());
                    goto back;
                } else if(eval_this == 'Q') {
                    silent = !silent;
                    goto back;
                }

            }
            step:
            int halt = false;
            int jump = false;
            try {
                switch(baseaddr[pc]) {
                case MOD:
                    if((baseaddr[pc+1] % 2) != 0) {
                        unsigned int modval = 0;
                        modval |= (baseaddr[pc+2] << 24);
                        modval |= (baseaddr[pc+3] << 16);
                        modval |= (baseaddr[pc+4] << 8);
                        modval |= (baseaddr[pc+5]);
                        r[(baseaddr[pc+1] & 0x1c) >> 2] = r[(baseaddr[pc+1] & 0xe0) >> 5] % modval;
                        break;

                    }
                    r[(baseaddr[pc+1] & 0x1c) >> 2] = r[(baseaddr[pc+1] & 0xe0) >> 5] % r[(baseaddr[pc+1] & 0x1c) >> 2];
                    break;
                case RSL:
                    if((baseaddr[pc+1] % 2) != 0) {
                        unsigned int shiftval = 0;
                        shiftval |= (baseaddr[pc+2] << 24);
                        shiftval |= (baseaddr[pc+3] << 16);
                        shiftval |= (baseaddr[pc+4] << 8);
                        shiftval |= (baseaddr[pc+5]);
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = r[(baseaddr[pc+1] & 0xe0) >> 5] >> shiftval;
                        break;
                    }
                    r[(baseaddr[pc+1] & 0xe0) >> 5] = r[(baseaddr[pc+1] & 0xe0) >> 5] >> r[(baseaddr[pc+1] & 0x1c) >> 2];
                    break;
                case LSL:
                    if((baseaddr[pc+1] % 2) != 0) {
                        unsigned int shiftval = 0;
                        shiftval |= (baseaddr[pc+2] << 24);
                        shiftval |= (baseaddr[pc+3] << 16);
                        shiftval |= (baseaddr[pc+4] << 8);
                        shiftval |= (baseaddr[pc+5]);
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = r[(baseaddr[pc+1] & 0xe0) >> 5] << shiftval;
                        break;
                    }
                    r[(baseaddr[pc+1] & 0xe0) >> 5] = r[(baseaddr[pc+1] & 0xe0) >> 5] << r[(baseaddr[pc+1] & 0x1c) >> 2];
                    break;
                case JO:
                    if(!(flags[1] == 1)) {
                        break;
                    }
                    if((baseaddr[pc+1] % 2) != 0) {
                        unsigned int oldpc = pc;
                        pc = 0;
                        pc |= (baseaddr[oldpc+2] << 24);
                        pc |= (baseaddr[oldpc+3] << 16);
                        pc |= (baseaddr[oldpc+4] << 8);
                        pc |= (baseaddr[oldpc+5]);
                        jump = true;
                        break;
                    }
                    jump = true;
                    pc = r[(baseaddr[pc+1] & 0xe0) >> 5];
                    break;
                case C2I: {
                        int *regptr = (int*)&r[(baseaddr[pc+1] & 0xe0) >> 5];
                        flags[1] = checked_add(*regptr,1,NULL);
                        *regptr += 1;
                    }
                    break;
                case CDD: {
                        int *regptr = (int*)&r[(baseaddr[pc+1] & 0xe0) >> 5];
                        flags[1] = checked_sub(*regptr,1,NULL);
                        *regptr -= 1;
                    }
                    break;
                case C2S: {
                        int *regptr = (int*)&r[(baseaddr[pc+1] & 0xe0) >> 5];
                        if((baseaddr[pc+1] % 2) != 0) {
                            int addval = 0;
                            addval |= (baseaddr[pc+2] << 24);
                            addval |= (baseaddr[pc+3] << 16);
                            addval |= (baseaddr[pc+4] << 8);
                            addval |= (baseaddr[pc+5]);
                            flags[1] = checked_sub(*regptr,addval,NULL);
                            *regptr -= addval;
                            break;
                        }
                        flags[1] = checked_sub(*regptr,*(int*)r[(baseaddr[pc+1] & 0x1c) >> 2],NULL);
                        *regptr -= *(int*)r[(baseaddr[pc+1] & 0x1c) >> 2];
                    }
                    break;
                    case C2A: {
                            int *regptr = (int*)&r[(baseaddr[pc+1] & 0xe0) >> 5];
                            if((baseaddr[pc+1] % 2) != 0) {
                                int addval = 0;
                                addval |= (baseaddr[pc+2] << 24);
                                addval |= (baseaddr[pc+3] << 16);
                                addval |= (baseaddr[pc+4] << 8);
                                addval |= (baseaddr[pc+5]);
                                flags[1] = checked_add(*regptr,addval,NULL);
                                *regptr += addval;
                                break;
                            }
                            flags[1] = checked_add(*regptr,*(int*)r[(baseaddr[pc+1] & 0x1c) >> 2],NULL);
                            *regptr += *(int*)r[(baseaddr[pc+1] & 0x1c) >> 2];
                        }
                        break;
                    case NOT:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int orval = 0;
                            orval |= (baseaddr[pc+2] << 24);
                            orval |= (baseaddr[pc+3] << 16);
                            orval |= (baseaddr[pc+4] << 8);
                            orval |= (baseaddr[pc+5]);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] = ~orval;
                            break;
                        }
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = ~r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case XOR:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int orval = 0;
                            orval |= (baseaddr[pc+2] << 24);
                            orval |= (baseaddr[pc+3] << 16);
                            orval |= (baseaddr[pc+4] << 8);
                            orval |= (baseaddr[pc+5]);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] ^= orval;
                            break;
                        }
                        r[(baseaddr[pc+1] & 0xe0) >> 5] ^= r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case OR:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int orval = 0;
                            orval |= (baseaddr[pc+2] << 24);
                            orval |= (baseaddr[pc+3] << 16);
                            orval |= (baseaddr[pc+4] << 8);
                            orval |= (baseaddr[pc+5]);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] |= orval;
                            break;
                        }
                        r[(baseaddr[pc+1] & 0xe0) >> 5] |= r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case AND:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int andval = 0;
                            andval |= (baseaddr[pc+2] << 24);
                            andval |= (baseaddr[pc+3] << 16);
                            andval |= (baseaddr[pc+4] << 8);
                            andval |= (baseaddr[pc+5]);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] &= andval;
                            break;
                        }
                        r[(baseaddr[pc+1] & 0xe0) >> 5] &= r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case GBP:
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = baseptr;
                        break;
                    case SBP:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int stckval = 0;
                            stckval |= (baseaddr[pc+2] << 24);
                            stckval |= (baseaddr[pc+3] << 16);
                            stckval |= (baseaddr[pc+4] << 8);
                            stckval |= (baseaddr[pc+5]);
                            baseptr = stckval;
                            break;
                        }
                        baseptr = r[(baseaddr[pc+1] & 0xe0) >> 5];
                        break;
                    case GSP:
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = stackptr;
                        break;
                    case ADD:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int addval = 0;
                            addval |= (baseaddr[pc+2] << 24);
                            addval |= (baseaddr[pc+3] << 16);
                            addval |= (baseaddr[pc+4] << 8);
                            addval |= (baseaddr[pc+5]);
                            flags[1] = WillOverflow<unsigned int>((unsigned long)r[(baseaddr[pc+1] & 0xe0) >> 5] + (unsigned long)addval);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] += addval;
                            break;
                        }
                        flags[1] = WillOverflow<unsigned int>((unsigned long)r[(baseaddr[pc+1] & 0xe0) >> 5] + (unsigned long)r[(baseaddr[pc+1] & 0x1c) >> 2]);
                        r[(baseaddr[pc+1] & 0xe0) >> 5] += r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case SUB:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int subval = 0;
                            subval |= (baseaddr[pc+2] << 24);
                            subval |= (baseaddr[pc+3] << 16);
                            subval |= (baseaddr[pc+4] << 8);
                            subval |= (baseaddr[pc+5]);
                            flags[1] = WillOverflow<unsigned int>((long)r[(baseaddr[pc+1] & 0xe0) >> 5] - (long)subval);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] -= subval;
                            break;
                        }
                        flags[1] = WillOverflow<unsigned int>((long)r[(baseaddr[pc+1] & 0xe0) >> 5] - (long)r[(baseaddr[pc+1] & 0x1c) >> 2]);
                        r[(baseaddr[pc+1] & 0xe0) >> 5] -= r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case DSP:
                        baseptr = stackptr;
                        break;
                    case DBP:
                        stackptr = baseptr;
                        break;
                    case SWBS: {
                        unsigned int stck_dup = stackptr;
                        unsigned int base_dup = baseptr;
                        stackptr = base_dup;
                        baseptr = stck_dup;
                        break; }
                    case PUSH:
                        if((baseaddr[pc+1] % 2) != 0) {
                            stackptr -= 4;
                            baseaddr[stackptr - 3] = (baseaddr[pc+5]);
                            baseaddr[stackptr - 2] = (baseaddr[pc+4]);
                            baseaddr[stackptr - 1] = (baseaddr[pc+3]);
                            baseaddr[stackptr] = (baseaddr[pc+2]);
                            break;
                        }
                        stackptr -= 4;
                        baseaddr[stackptr - 3] = r[(baseaddr[pc+1] & 0xe0) >> 5];
                        baseaddr[stackptr - 2] = r[(baseaddr[pc+1] & 0xe0) >> 5] << 8;
                        baseaddr[stackptr - 1] = r[(baseaddr[pc+1] & 0xe0) >> 5] << 16;
                        baseaddr[stackptr] = r[(baseaddr[pc+1] & 0xe0) >> 5] << 24;
                        break;
                    case CALL:
                        if((baseaddr[pc+1] % 2) != 0) {
                            baseaddr[stackptr - 3] = pc + 6;
                            baseaddr[stackptr - 2] = (pc + 6) << 8;
                            baseaddr[stackptr - 1] = (pc + 6) << 16;
                            baseaddr[stackptr] = (pc + 6) << 24;
                            stackptr -= 4;
                            pc = 0;
                            pc |= (baseaddr[pc+5]);
                            pc |= (baseaddr[pc+4]) << 8;
                            pc |= (baseaddr[pc+3]) << 16;
                            pc |= (baseaddr[pc+2]) << 24;
                            jump = true;
                            break;
                        }
                        baseaddr[stackptr - 3] = pc + 2;
                        baseaddr[stackptr - 2] = (pc + 2) << 8;
                        baseaddr[stackptr - 1] = (pc + 2) << 16;
                        baseaddr[stackptr] = (pc + 2) << 24;
                        pc = r[(baseaddr[pc+1] & 0xe0) >> 5];
                        stackptr -= 4;
                        jump = true;
                        break;
                    case RET:
                        memcpy(&pc,(baseaddr.get_base() + stackptr - 3),4);
                        jump = true;
                        break;
                    case POP:
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = 0;
                        if(!silent)
                            std::cout << (unsigned long)(baseaddr.get_base() + stackptr) << std::endl;
                        memcpy(&r[(baseaddr[pc+1] & 0xe0) >> 5],(baseaddr.get_base() + stackptr - 3),4);
                        //r[(baseaddr[pc+1] & 0xe0) >> 5] = (baseaddr[stackptr - (stackdepth*4) + 3] << 24) | (baseaddr[stackptr - (stackdepth*4) + 2] << 16) | (baseaddr[stackptr - (stackdepth*4) + 1] << 8) | baseaddr[stackptr - (stackdepth*4)];
                        stackptr += 4;
                        break;
                    case SSP:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int stckval = 0;
                            stckval |= (baseaddr[pc+2] << 24);
                            stckval |= (baseaddr[pc+3] << 16);
                            stckval |= (baseaddr[pc+4] << 8);
                            stckval |= (baseaddr[pc+5]);
                            stackptr = stckval;
                            break;
                        }
                        stackptr = r[(baseaddr[pc+1] & 0xe0) >> 5];
                        break;
                    case DEC:
                        r[(baseaddr[pc+1] & 0xe0) >> 5]--;
                        break;
                    case CLF:
                        flags = 0;
                        break;
                    case CMP:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned int cmpval = 0;
                            cmpval |= (baseaddr[pc+2] << 24);
                            cmpval |= (baseaddr[pc+3] << 16);
                            cmpval |= (baseaddr[pc+4] << 8);
                            cmpval |= (baseaddr[pc+5]);
                            flags[0] = r[(baseaddr[pc+1] & 0xe0) >> 5] == cmpval;
                            break;
                        }
                        flags[0] = r[(baseaddr[pc+1] & 0xe0) >> 5] == r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case JZ:
                        if(!(flags[0] == 1)) {
                            break;
                        }
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned long oldpc = pc;
                            pc = 0;
                            pc |= (baseaddr[oldpc+2] << 24);
                            pc |= (baseaddr[oldpc+3] << 16);
                            pc |= (baseaddr[oldpc+4] << 8);
                            pc |= (baseaddr[oldpc+5]);
                            jump = true;
                            break;
                        }
                        jump = true;
                        pc = r[(baseaddr[pc+1] & 0xe0) >> 5];
                        break;


                    case JMP:
                        if((baseaddr[pc+1] % 2) != 0) {
                            unsigned long oldpc = pc;
                            pc = 0;
                            pc |= (baseaddr[oldpc+2] << 24);
                            pc |= (baseaddr[oldpc+3] << 16);
                            pc |= (baseaddr[oldpc+4] << 8);
                            pc |= (baseaddr[oldpc+5]);
                            jump = true;
                            break;
                        }
                        jump = true;
                        pc = r[(baseaddr[pc+1] & 0xe0) >> 5];
                        break;
                    case MOV:
                        if((baseaddr[pc+1] % 2) != 0) {
                            r[(baseaddr[pc+1] & 0xe0) >> 5] = 0;
                            r[(baseaddr[pc+1] & 0xe0) >> 5] |= (baseaddr[pc+2] << 24);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] |= (baseaddr[pc+3] << 16);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] |= (baseaddr[pc+4] << 8);
                            r[(baseaddr[pc+1] & 0xe0) >> 5] |= (baseaddr[pc+5]);
                            break;
                        }
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case INC:
                        r[(baseaddr[pc+1] & 0xe0) >> 5]++;
                        break;
                    case HLT:
                        halt = true;
                        break;
                    case LIT:
                        if((baseaddr[pc+1] % 2) != 0) {
                            itableptr = 0;
                            itableptr |= (baseaddr[pc+2] << 24);
                            itableptr |= (baseaddr[pc+3] << 16);
                            itableptr |= (baseaddr[pc+4] << 8);
                            itableptr |= (baseaddr[pc+5]);
                            break;
                        }
                        itableptr = r[(baseaddr[pc+1] & 0x1c) >> 2];
                        break;
                    case INT:
                        if((baseaddr[pc+1] % 2) != 0) {
                            stackptr -= 4;
                            baseaddr[stackptr - 3] = pc + 3;
                            baseaddr[stackptr - 2] = (pc + 3) << 8;
                            baseaddr[stackptr - 1] = (pc + 3) << 16;
                            baseaddr[stackptr] = (pc + 3) << 24;
                            stackptr -= 4;
                            baseaddr[stackptr - 3] = flags.to_ulong();
                            baseaddr[stackptr - 2] = (flags.to_ulong()) << 8;
                            baseaddr[stackptr - 1] = (flags.to_ulong()) << 16;
                            baseaddr[stackptr] = (flags.to_ulong()) << 24;
                            jump = true;
                            int interrupt = 0;
                            interrupt |= baseaddr[pc+2];
                            pc = 0;
                            pc |= (baseaddr[itableptr + interrupt] << 24);
                            pc |= (baseaddr[itableptr + interrupt + 1] << 16);
                            pc |= (baseaddr[itableptr + interrupt + 2] << 8);
                            pc |= (baseaddr[itableptr + interrupt + 3]);

                            break;
                        }
                        stackptr -= 4;
                        baseaddr[stackptr - 3] = pc + 2;
                        baseaddr[stackptr - 2] = (pc + 2) << 8;
                        baseaddr[stackptr - 1] = (pc + 2) << 16;
                        baseaddr[stackptr] = (pc + 2) << 24;
                        stackptr -= 4;
                        baseaddr[stackptr - 3] = flags.to_ulong();
                        baseaddr[stackptr - 2] = (flags.to_ulong()) << 8;
                        baseaddr[stackptr - 1] = (flags.to_ulong()) << 16;
                        baseaddr[stackptr] = (flags.to_ulong()) << 24;

                        jump = true;
                        pc = 0;
                        pc |= (baseaddr[itableptr +  r[(baseaddr[pc+1] & 0x1c) >> 2]] << 24);
                        pc |= (baseaddr[itableptr +  r[(baseaddr[pc+1] & 0x1c) >> 2] + 1] << 16);
                        pc |= (baseaddr[itableptr +  r[(baseaddr[pc+1] & 0x1c) >> 2] + 2] << 8);
                        pc |= (baseaddr[itableptr +  r[(baseaddr[pc+1] & 0x1c) >> 2] + 3]);
                        break;
                    case IRET: {
                        unsigned int val = 0;
                        memcpy(&val,(baseaddr.get_base() + stackptr - 3),4);
                        flags = std::bitset<8>(val);
                        stackptr += 4;
                        memcpy(&pc,(baseaddr.get_base() + stackptr - 3),4);
                        stackptr += 4;
                        jump = true;
                        break; }
                    case LD: {
                        unsigned int bytes = (baseaddr[pc+1] & 0x03);
                        if(bytes == 2) {
                            break;
                        }
                        if(!silent) {
                            std::cout << r[(baseaddr[pc+1] & 0x1c) >> 2] << std::endl;
                            std::cout << ((baseaddr[pc+1] & 0x1c) >> 2) << std::endl;
                        }
                        unsigned int stval = r[(baseaddr[pc+1] & 0x1c) >> 2];
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = 0;
                        for(unsigned char i = 0; i < bytes + 1; i++) {
                            r[(baseaddr[pc+1] & 0xe0) >> 5] |= baseaddr[stval + i] << i*8;
                        }
                        break; }
                    case ST: {
                        unsigned int bytes = (baseaddr[pc+1] & 0x03);
                        if(bytes == 2) {
                            break;
                        }
                        if(!silent) {
                            std::cout << r[(baseaddr[pc+1] & 0x1c) >> 2] << std::endl;
                            std::cout << ((baseaddr[pc+1] & 0x1c) >> 2) << std::endl;
                        }
                        unsigned int stval = r[(baseaddr[pc+1] & 0x1c) >> 2];
                        for(unsigned char i = 0; i < bytes + 1;i++) {
                            baseaddr[stval + i] = (r[(baseaddr[pc+1] & 0xe0) >> 5] >> (i)*8) & 0x000000ff;
                            if(!silent)
                                std::cout << "Value of memory address:" << (int)baseaddr[stval + i] << std::endl;
                        }
                        break; }
                    case POP8:
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = 0;
                        if(!silent)
                            std::cout << (unsigned long)(baseaddr.get_base() + stackptr) << std::endl;
                        memcpy(&r[(baseaddr[pc+1] & 0xe0) >> 5],(baseaddr.get_base() + stackptr),1);
                        stackptr += 1;
                        break;
                    case POP16:
                        r[(baseaddr[pc+1] & 0xe0) >> 5] = 0;
                        if(!silent)
                            std::cout << (unsigned long)(baseaddr.get_base() + stackptr) << std::endl;
                        memcpy(&r[(baseaddr[pc+1] & 0xe0) >> 5],(baseaddr.get_base() + stackptr - 1),2);
                        stackptr += 2;
                        break;
                    case PUSH16:
                        if((baseaddr[pc+1] % 2) != 0) {
                            stackptr -= 2;
                            baseaddr[stackptr - 1] = (baseaddr[pc+3]);
                            baseaddr[stackptr] = (baseaddr[pc+2]);
                            break;
                        }
                        stackptr -= 2;
                        baseaddr[stackptr - 1] = r[(baseaddr[pc+1] & 0xe0) >> 5] << 16;
                        baseaddr[stackptr] = r[(baseaddr[pc+1] & 0xe0) >> 5] << 24;
                        break;
                    case PUSH8:
                        if((baseaddr[pc+1] % 2) != 0) {
                            stackptr -= 1;
                            baseaddr[stackptr] = (baseaddr[pc+2]);
                            break;
                        }
                        stackptr -= 1;
                        baseaddr[stackptr] = r[(baseaddr[pc+1] & 0xe0) >> 5] << 24;
                        break;
                    default:
                        throw CPUException(ILLEGAL_INSTRUCTION);
                        break;


                }
            } catch(const CPUException &exception) {
                stackptr -= 4;
                baseaddr[stackptr - 3] = pc + 3;
                baseaddr[stackptr - 2] = (pc + 3) << 8;
                baseaddr[stackptr - 1] = (pc + 3) << 16;
                baseaddr[stackptr] = (pc + 3) << 24;
                stackptr -= 4;
                baseaddr[stackptr - 3] = flags.to_ulong();
                baseaddr[stackptr - 2] = (flags.to_ulong()) << 8;
                baseaddr[stackptr - 1] = (flags.to_ulong()) << 16;
                baseaddr[stackptr] = (flags.to_ulong()) << 24;
                jump = true;
                pc = 0;
                pc |= (baseaddr[itableptr + interrupt] << 24);
                pc |= (baseaddr[itableptr + interrupt + 1] << 16);
                pc |= (baseaddr[itableptr + interrupt + 2] << 8);
                pc |= (baseaddr[itableptr + interrupt + 3]);
                switch(exception.getExceptionType()) {
                    default:
                        stackptr -= 4;
                        baseaddr[stackptr - 3] = exception.getExceptionType();
                        baseaddr[stackptr - 2] = (exception.getExceptionType()) << 8;
                        baseaddr[stackptr - 1] = (exception.getExceptionType()) << 16;
                        baseaddr[stackptr] = (exception.getExceptionType()) << 24;
                        if(!silent)
                            std::cout << "Handling Exception." << std::endl;
                        break;
                }
            }

            n_inst++;
            if(!silent) {
                std::cout << n_inst << std::endl;
                std::cout << "Base pointer location:" << baseptr << std::endl;
                std::cout << "Current stack location:" << stackptr << std::endl;

                /*
                if(baseptr != 0) {
                    for(size_t i =0; i <= (stackptr - baseptr);i++) {
                        std::cout << (unsigned long)(baseaddr + stackptr - i) << std::endl;
                        std::cout << (unsigned int)(baseaddr[stackptr - i]) << std::endl;
                    }
                }
                */
                std::cout << "Registers: ";
                for(int i =0;i < 8;i++) {
                    std::cout << r[i];
                    if(i != 7)
                        std::cout << ":";
                }
                std::cout << std::endl;
                std::cout << "Program Counter: " << pc << std::endl;
            }
            if(halt) {
                if(!silent)
                    std::cout << "Halting." << std::endl;
                HLTed = true;
                break;
            } else if (jump) {
                if(!silent)
                    std::cout << "Jumping to: " << pc << std::endl;
                continue;
            }
            if(((baseaddr[pc+1] % 2) != 0) && !(inst_length[baseaddr[pc]] == 1)) {
                pc += jump_offset[baseaddr[pc]];
                continue;
            }

            pc += inst_length[baseaddr[pc]];
        }
    }
    std::bitset<8> flags;
    unsigned int r[8] = {0,0,0,0,0,0,0,0};
    std::vector<std::function<void()>> function_list;
    std::map<int,int> jump_offset;
    std::map<int,int> inst_length;
    private:
    long breakpoint = -1;
    unsigned long n_inst = 0;
    RMMU baseaddr = RMMU(0);
    int HLTed = false;
    int interrupt = false;
    int interrupts_enabled = true;
    unsigned int itableptr = 0;
    unsigned int stackptr = 0;
    unsigned int baseptr = 0;
    unsigned int pc = 0;
    timeval initial,stop;

};

using namespace std;

int main()
{
    unsigned char *arr = new unsigned char[16777216]; //16M of ram
    memset(arr,0x00,16777216);

    RMMU mmu(arr);
    //RTTY tty(arr);
    //RGA rga(arr);
    RVM rvm(mmu);
    //rvm.add_to_clock(std::bind(&RTTY::do_stuff,&tty));
    //rvm.add_to_clock(std::bind(&RGA::do_stuff,&rga));
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
    /*std::thread t ([&](){*/rvm.start(false, true);//});
    //t.join();
    return 0;
}
