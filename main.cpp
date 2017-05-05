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
    PUSH16,

    //maybe add a conditional move

};
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
        while(1) {
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
                std::cout << "Step(s) Peek memory(p) Get current instruction(i) Get number of instructions ran(n) Go(g) Set Breakpoint(b) Quiet(q) [S/r/i/n/g/b/q]" << std::endl;
                std::getline(std::cin,action);
                if(action.size() == 0) {
                    goto step;
                }
                char eval_this = std::toupper(action[0],ascii);
                if(eval_this == 'S') {
                    goto step;
                } else if(eval_this == 'P') {
                    int mvalue = std::stoul(action.substr(1).c_str(),0,10);
                    std::cout << "The memory at " << mvalue << " is " << *baseaddr.read32(mvalue) << std::endl;
                    goto back;
                } else if(eval_this == 'N') {
                    std::cout << "Number of instructions ran: " << n_inst << std::endl;
                    goto back;
                } else if(eval_this == 'I') {
                    std::cout << "Instruction: " << std::hex  << *baseaddr.read16(pc) << std::dec << std::endl;
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
            for(size_t i = 0; i < function_list.size(); i++) {
                // use this to fake hardware properties and do cool processing stuff
                function_list[i]();
            }
            int halt = false;
            int jump = false;
            if(interrupt) {
                interrupt = false;
                stackptr -= 4;
                baseaddr.write(stackptr - 3, 4,&pc);
                stackptr -= 4;
                unsigned int flagval = flags.to_ulong();
                baseaddr.write(stackptr - 3,4, &flagval);
                jump = true;
                pc = *baseaddr.read32(itableptr + interrupt_vector);
                goto irq;
            }
            try {
                unsigned char cachedargs = *baseaddr.read8(pc+1);
                switch(*baseaddr.read8(pc)) {
                case MOD:
                    if((cachedargs % 2) != 0) {
                        unsigned int modval = 0;
                        modval = *baseaddr.read32(pc+2);
                        r[(cachedargs & 0x1c) >> 2] = r[(cachedargs & 0xe0) >> 5] % modval;
                        break;

                    }
                    r[(cachedargs & 0x1c) >> 2] = r[(cachedargs & 0xe0) >> 5] % r[(cachedargs & 0x1c) >> 2];
                    break;
                case RSL:
                    if((cachedargs % 2) != 0) {
                        unsigned int shiftval = 0;
                        shiftval = *baseaddr.read32(pc+2);
                        r[(cachedargs & 0xe0) >> 5] = r[(cachedargs & 0xe0) >> 5] >> shiftval;
                        break;
                    }
                    r[(cachedargs & 0xe0) >> 5] = r[(cachedargs & 0xe0) >> 5] >> r[(cachedargs & 0x1c) >> 2];
                    break;
                case LSL:
                    if((cachedargs % 2) != 0) {
                        unsigned int shiftval = 0;
                        shiftval = *baseaddr.read32(pc+2);
                        r[(cachedargs & 0xe0) >> 5] = r[(cachedargs & 0xe0) >> 5] << shiftval;
                        break;
                    }
                    r[(cachedargs & 0xe0) >> 5] = r[(cachedargs & 0xe0) >> 5] << r[(cachedargs & 0x1c) >> 2];
                    break;
                case JO:
                    if(!(flags[1] == 1)) {
                        break;
                    }
                    if((cachedargs % 2) != 0) {
                        unsigned int oldpc = pc;
                        pc = 0;
                        pc = *baseaddr.read32(oldpc+2);
                        jump = true;
                        break;
                    }
                    jump = true;
                    pc = r[(cachedargs & 0xe0) >> 5];
                    break;
                case C2I: {
                        int *regptr = (int*)&r[(cachedargs & 0xe0) >> 5];
                        flags[1] = checked_add(*regptr,1,NULL);
                        *regptr += 1;
                    }
                    break;
                case CDD: {
                        int *regptr = (int*)&r[(cachedargs & 0xe0) >> 5];
                        flags[1] = checked_sub(*regptr,1,NULL);
                        *regptr -= 1;
                    }
                    break;
                case C2S: {
                        int *regptr = (int*)&r[(cachedargs & 0xe0) >> 5];
                        if((cachedargs % 2) != 0) {
                            int addval;
                            addval = *baseaddr.read32(pc+2);
                            flags[1] = checked_sub(*regptr,addval,NULL);
                            *regptr -= addval;
                            break;
                        }
                        flags[1] = checked_sub(*regptr,*((int*)r[(cachedargs & 0x1c) >> 2]),NULL);
                        *regptr -= *((int*)r[(cachedargs & 0x1c) >> 2]);
                    }
                    break;
                    case C2A: {
                            int *regptr = (int*)&r[(cachedargs & 0xe0) >> 5];
                            if((cachedargs % 2) != 0) {
                                int addval;
                                addval = *baseaddr.read32(pc+2);
                                flags[1] = checked_add(*regptr,addval,NULL);
                                *regptr += addval;
                                break;
                            }
                            flags[1] = checked_add(*regptr,*((int*)r[(cachedargs & 0x1c) >> 2]),NULL);
                            *regptr += *((int*)r[(cachedargs & 0x1c) >> 2]);
                        }
                        break;
                    case NOT:
                        if((cachedargs % 2) != 0) {
                            unsigned int orval;
                            orval = *baseaddr.read32(pc+2);
                            r[(cachedargs & 0xe0) >> 5] = ~orval;
                            break;
                        }
                        r[(cachedargs & 0xe0) >> 5] = ~r[(cachedargs & 0x1c) >> 2];
                        break;
                    case XOR:
                        if((cachedargs % 2) != 0) {
                            unsigned int orval;
                            orval = *baseaddr.read32(pc+2);
                            r[(cachedargs & 0xe0) >> 5] ^= orval;
                            break;
                        }
                        r[(cachedargs & 0xe0) >> 5] ^= r[(cachedargs & 0x1c) >> 2];
                        break;
                    case OR:
                        if((cachedargs % 2) != 0) {
                            unsigned int orval;
                            orval = *baseaddr.read32(pc+2);
                            r[(cachedargs & 0xe0) >> 5] |= orval;
                            break;
                        }
                        r[(cachedargs & 0xe0) >> 5] |= r[(cachedargs & 0x1c) >> 2];
                        break;
                    case AND:
                        if((cachedargs % 2) != 0) {
                            unsigned int andval;
                            andval = *baseaddr.read32(pc+2);
                            r[(cachedargs & 0xe0) >> 5] &= andval;
                            break;
                        }
                        r[(cachedargs & 0xe0) >> 5] &= r[(cachedargs & 0x1c) >> 2];
                        break;
                    case GSP:
                        r[(cachedargs & 0xe0) >> 5] = stackptr;
                        break;
                    case ADD:
                        if((cachedargs % 2) != 0) {
                            unsigned int addval;
                            addval = *baseaddr.read32(pc+2);
                            flags[1] = WillOverflow<unsigned int>((unsigned long)r[(cachedargs & 0xe0) >> 5] + (unsigned long)addval);
                            r[(cachedargs & 0xe0) >> 5] += addval;
                            break;
                        }
                        flags[1] = WillOverflow<unsigned int>((unsigned long)r[(cachedargs & 0xe0) >> 5] + (unsigned long)r[(cachedargs & 0x1c) >> 2]);
                        r[(cachedargs & 0xe0) >> 5] += r[(cachedargs & 0x1c) >> 2];
                        break;
                    case SUB:
                        if((cachedargs % 2) != 0) {
                            unsigned int subval;
                            subval = *baseaddr.read32(pc+2);
                            flags[1] = WillOverflow<unsigned int>((long)r[(cachedargs & 0xe0) >> 5] - (long)subval);
                            r[(cachedargs & 0xe0) >> 5] -= subval;
                            break;
                        }
                        flags[1] = WillOverflow<unsigned int>((long)r[(cachedargs & 0xe0) >> 5] - (long)r[(cachedargs & 0x1c) >> 2]);
                        r[(cachedargs & 0xe0) >> 5] -= r[(cachedargs & 0x1c) >> 2];
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
                        if((cachedargs % 2) != 0) {
                            stackptr -= 4;
                            baseaddr.write(stackptr - 3, 4,baseaddr.read32(pc+2));
                            break;
                        }
                        stackptr -= 4;
                        baseaddr.write(stackptr - 3, 4, &r[(cachedargs & 0xe0) >> 5]);
                        break;
                    case CALL: {
                        if((cachedargs % 2) != 0) {
                            unsigned int pc6 = pc+6;
                            baseaddr.write(stackptr - 3, 4, &pc6);
                            stackptr -= 4;
                            pc = *baseaddr.read32(pc+2);
                            jump = true;
                            break;
                        }
                        unsigned int pc2= pc+2;
                        baseaddr.write(stackptr - 3, 4, &pc2);
                        pc = r[(cachedargs & 0xe0) >> 5];
                        stackptr -= 4;
                        jump = true;
                        break; }
                    case RET:
                        pc = *baseaddr.read32(stackptr - 3);
                        stackptr += 4;
                        jump = true;
                        break;
                    case POP:
                        if(!silent)
                            std::cout << (unsigned long)(stackptr) << std::endl;
                        r[(cachedargs & 0xe0) >> 5] = *baseaddr.read32(stackptr - 3);
                        //r[(cachedargs & 0xe0) >> 5] = (*baseaddr.read8(stackptr - (stackdepth*4) + 3] << 24) | (*baseaddr.read8(stackptr - (stackdepth*4) + 2] << 16) | (*baseaddr.read8(stackptr - (stackdepth*4) + 1] << 8) | *baseaddr.read8(stackptr - (stackdepth*4)];
                        stackptr += 4;
                        break;
                    case SSP:
                        if((cachedargs % 2) != 0) {
                            unsigned int stckval;
                            stckval = *baseaddr.read32(pc+2);
                            stackptr = stckval;
                            break;
                        }
                        stackptr = r[(cachedargs & 0xe0) >> 5];
                        break;
                    case DEC:
                        r[(cachedargs & 0xe0) >> 5]--;
                        break;
                    case CLF:
                        flags = 0;
                        break;
                    case CMP:
                        if((cachedargs % 2) != 0) {
                            unsigned int cmpval;
                            cmpval = *baseaddr.read32(pc+2);
                            flags[0] = r[(cachedargs & 0xe0) >> 5] == cmpval;
                            break;
                        }
                        flags[0] = r[(cachedargs & 0xe0) >> 5] == r[(cachedargs & 0x1c) >> 2];
                        break;
                    case JZ:
                        if(!(flags[0] == 1)) {
                            break;
                        }
                        if((cachedargs % 2) != 0) {
                            unsigned long oldpc = pc;
                            pc = *baseaddr.read32(oldpc+2);
                            jump = true;
                            break;
                        }
                        jump = true;
                        pc = r[(cachedargs & 0xe0) >> 5];
                        break;


                    case JMP:
                        if((cachedargs % 2) != 0) {
                            unsigned long oldpc = pc;
                            pc = *baseaddr.read32(oldpc+2);
                            jump = true;
                            break;
                        }
                        jump = true;
                        pc = r[(cachedargs & 0xe0) >> 5];
                        break;
                    case MOV:
                        if((cachedargs % 2) != 0) {
                            std::cout << std::hex << baseaddr.read32(pc + 2) << std::dec << std::endl;
                            r[(cachedargs & 0xe0) >> 5] = *baseaddr.read32(pc + 2);
                            break;
                        }
                        r[(cachedargs & 0xe0) >> 5] = r[(cachedargs & 0x1c) >> 2];
                        break;
                    case INC:
                        r[(cachedargs & 0xe0) >> 5]++;
                        break;
                    case HLT:
                        halt = true;
                        break;
                    case LIT:
                        if((cachedargs % 2) != 0) {
                            itableptr = *baseaddr.read32(pc+2);
                            break;
                        }
                        itableptr = r[(cachedargs & 0x1c) >> 2];
                        break;
                    case INT: {
                        if((cachedargs % 2) != 0) {
                            stackptr -= 4;
                            unsigned int pc3 = pc + 3;
                            baseaddr.write(stackptr - 3, 4, &pc3);
                            stackptr -= 4;
                            unsigned int flagval = flags.to_ulong();
                            baseaddr.write(stackptr - 3,4, &flagval);
                            jump = true;
                            pc = *baseaddr.read32(itableptr + interrupt + *baseaddr.read8(pc+2));
                            break;
                        }
                        stackptr -= 4;
                        unsigned int pc2 = pc + 2;
                        baseaddr.write(stackptr - 3, 4, &pc2);
                        stackptr -= 4;
                        unsigned int flagval = flags.to_ulong();
                        baseaddr.write(stackptr - 3,4, &flagval);
                        jump = true;
                        pc = *baseaddr.read32(itableptr + r[(cachedargs & 0x1c) >> 2]);
                        break; }
                    case IRET: {
                        flags = std::bitset<8>(*baseaddr.read32(stackptr - 3));
                        stackptr += 4;
                        pc = baseaddr.read32(stackptr - 3);
                        stackptr += 4;
                        jump = true;
                        break; }
                    case LD: {
                        unsigned int bytes = (cachedargs & 0x03);
                        if(bytes == 2) {
                            throw CPUException(ILLEGAL_INSTRUCTION);
                        }
                        if(!silent) {
                            std::cout << r[(cachedargs & 0x1c) >> 2] << std::endl;
                            std::cout << ((cachedargs & 0x1c) >> 2) << std::endl;
                        }
                        unsigned int stval = r[(cachedargs & 0x1c) >> 2];
                        r[(cachedargs & 0xe0) >> 5] = 0;
                        switch(bytes) {
                        case 0:
                            r[(cachedargs & 0xe0) >> 5] = *baseaddr.read8(stval);
                            break;
                        case 1:
                            r[(cachedargs & 0xe0) >> 5] = *baseaddr.read16(stval);
                            break;
                        case 3:
                            r[(cachedargs & 0xe0) >> 5] = *baseaddr.read32(stval);
                            break;
                        }
                        break; }
                    case ST: {
                        unsigned int bytes = (cachedargs & 0x03);
                        if(bytes == 2) {
                            throw CPUException(ILLEGAL_INSTRUCTION);
                        }
                        if(!silent) {
                            std::cout << "storing to " << std::endl;
                            std::cout << r[(cachedargs & 0x1c) >> 2] << std::endl;
                            std::cout << ((cachedargs & 0x1c) >> 2) << std::endl;
                        }
                        unsigned int stval = r[(cachedargs & 0x1c) >> 2];
                        baseaddr.write(stval, bytes, &r[(cachedargs & 0xe0) >> 5]);
                        break; }
                    default:
                        throw CPUException(ILLEGAL_INSTRUCTION);
                        break;


                }
            } catch(const CPUException &exception) {
                stackptr -= 4;
                baseaddr.write(stackptr - 3, 4, &pc);
                stackptr -= 4;
                unsigned int flagval = flags.to_ulong();
                baseaddr.write(stackptr - 3,4, &flagval);
                jump = true;
                pc = *baseaddr.read32(itableptr + exception.getExceptionType());
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
                        std::cout << (unsigned int)(*baseaddr.read8(stackptr - i]) << std::endl;
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
                irq:
                if(!silent)
                    std::cout << "Jumping to: " << pc << std::endl;
                continue;
            }
            if(((*baseaddr.read8(pc+1) % 2) != 0) && !(inst_length[*baseaddr.read8(pc)] == 1)) {
                pc += jump_offset[*baseaddr.read8(pc)];
                continue;
            }

            pc += inst_length[*baseaddr.read8(pc)];
        }
    }
    unsigned char interrupt_vector;
    std::bitset<8> flags;
    unsigned long r[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    std::vector<std::function<void()>> function_list;
    private:
    long breakpoint = -1;
    unsigned long n_inst = 0;
    RMMU &baseaddr;
    int HLTed = false;
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
