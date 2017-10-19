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
#define MAX64 UINT64_MAX
#define MIN64 0
#define MAX32 UINT32_MAX
#define MIN32 0
#define ILLEGAL_INSTRUCTION 0
#define PERMISSION_EXCEPTION 1
#define ALIGNMENT_EXCEPTION 2
#define OVERFLOW_EXCEPTION 3
#define RAPIC_EOI 4
#define uint128_t __uint128_t
#define fetch         pc += 4; \
    for(int i = 0; i < 32;i++) { std::cout << ":" << r[i];} \
                        std::cout << std::endl;\
                      inst.full = __bswap_32(*mmu.read32(pc));
#define getra ((inst.full & 0b00000001111100000000000000000000) >> 20)
#define getrb ((inst.full & 0b00000000000011111000000000000000) >> 15)
#define getrc (inst.full & 0b00000000000000000000000000011111)
#define getdisp (unsigned short)((inst.split[3] & 0b01111111) << 9) | (unsigned short)((inst.split[3]) << 1)
#define getintegerfunction (unsigned short)((inst.full & 0b00000000000000000000011111100000) >> 5)
#define getliteral ((unsigned char)((inst.full & 0b00000000000011111111000000000000) >> 12))
#define dispatch std::cout << "dispatching handler :" << ((inst.full & 0b11111110000000000000000000000000) >> 25) << std::endl;\
                    std::cout << std::bitset<32>(inst.full) << " " << (int)getliteral <<  ((std::bitset<32>(inst.full)[19] == 1) == true) << std::endl; \
                    goto *handlers[(inst.full & 0b11111110000000000000000000000000) >> 25];
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

int checked_add_32(uint64_t a, uint64_t b, uint64_t *rp) {
  uint128_t lr = (uint64_t)a + (uint64_t)b;
  if(rp != NULL)
      *rp = lr;
  return lr > MAX32;
}

int checked_sub_32(uint64_t a, uint64_t b, uint64_t *rp) {
  uint128_t lr = (uint64_t)a - (uint64_t)b;
  if(rp != NULL)
    *rp = lr;
  return lr > MAX32;
}

int checked_add_64(uint64_t a, int64_t b, uint64_t *rp) {
  uint128_t lr = (uint128_t)a + (uint128_t)b;
  if(rp != NULL)
      *rp = lr;
  return lr > MAX64;
}

int checked_sub_64(uint64_t a, uint64_t b, uint64_t *rp) {
  uint128_t lr = (uint128_t)a - (uint128_t)b;
  if(rp != NULL)
    *rp = lr;
  return lr > MAX64;
}

struct MemRange {
    MemRange() {}
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

    unsigned short* read16wa(unsigned int offset) {
            if((offset % 2)) {
                throw CPUException(ALIGNMENT_EXCEPTION);
            }
        return (unsigned short*)(baseaddr + offset);
    }

    unsigned int* read32wa(unsigned int offset) {
            if((offset % 4)) {
                throw CPUException(ALIGNMENT_EXCEPTION);
            }
        return (unsigned int*)(baseaddr + offset);
    }

    unsigned long* read64wa(unsigned int offset) {
            if((offset % 8)) {
                throw CPUException(ALIGNMENT_EXCEPTION);
            }
        return (unsigned long*)(baseaddr + offset);
    }

    void write(unsigned int assign, unsigned int length, void* val) {
        //unsigned char endian[length];
        //for(int i = length - 1;i <= 0;i--) {
        //    endian[i] = ((unsigned char*)val)[(length - i)];
        //}
        memcpy((baseaddr + assign),&val,length);
    }


    void writewa(unsigned int assign, unsigned int length, void* val) {
        if(assign % length) {
            throw CPUException(ALIGNMENT_EXCEPTION);
        }
        memcpy((baseaddr + assign),&val,length);
    }

    void map(MemRange mrange,std::function<void(unsigned int, unsigned int, bool)> &func) {
        //maps[mrange] = func;
    }

    private:
    std::map<MemRange,std::function<void(unsigned int, unsigned int, bool)>> maps;
    unsigned char* baseaddr;
};

class RIOMMU {

};
template <class type, size_t size> class RegisterBank {
public:
    RegisterBank() {
        for(size_t i = 0; i < size; i++) {
            registers[i] = 0;
        }
        zero = 0;
    }

    type& operator[](std::size_t id) { zero = 0; if(id == (size - 1)) { return zero; } return registers[id]; }
private:
    type zero;
    type registers[size];
};

class RVM;

union instruction {
    unsigned char split[4];
    unsigned int full;
};

long sign_extend_32(int var) {
    long value = (0x00000000FFFFFFFF & var);
    long mask =  (0x0000000080000000);
    if(mask & var) {
        value += 0xFFFFFFFF00000000;
    }
    return value;
    //i have no idea if this'll work
    //check it later doofus
}

long sign_extend(short var) {
    short value = (0x7FFF & var);
    long mask =  (0x0000000000004000);
    if(mask & var) {
        value += 0xFFFFFFFFFFFF8000;
    }
    return value;
    //i have no idea if this'll work
    //check it later doofus
}

class RVM {
    public:
    RVM(RMMU &mmu) : mmu(mmu){
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
        static void* handlers[] = { &&privcode, &&trap,&&trap,&&trap,&&trap,&&trap,&&trap,&&trap,&&trap,&&loadaddress,&&loadaddresshigh,&&loadbyteunsigned,&&loadquadwordunaligned,&&storeword,&&storebyte,&&storequadwordunaligned,&&arithmetic10, &&bitops };
        static void* backuphandlers[] = { &&privcode, &&trap,&&trap,&&trap,&&trap,&&trap,&&trap,&&trap,&&trap,&&loadaddress,&&loadaddresshigh,&&loadbyteunsigned,&&loadquadwordunaligned,&&storeword,&&storebyte,&&storequadwordunaligned,&&arithmetic10, &&bitops };

        instruction inst;
        inst.full = __bswap_32(*mmu.read32(pc));
        unsigned long val = 0;
        startover:
        try {
            dispatch
        trap:
            throw CPUException(ILLEGAL_INSTRUCTION);
        privcode:
        fetch
        dispatch
        loadaddress:
        r[getra] = r[getrb] + sign_extend(getdisp);
        fetch
        dispatch
        loadaddresshigh:
        //disp is reduced to 15 bits
        //this probably means something for this instruction
        r[getra] = r[getrb] + sign_extend(getdisp * 32768);
        fetch
        dispatch
        loadbyteunsigned:
        r[getra]= *mmu.read8(r[getrb] + sign_extend(getdisp));
        fetch
        dispatch
        loadquadwordunaligned:
        r[getra]= *mmu.read64((r[getrb] + sign_extend(getdisp)) & ~7);
        fetch
        dispatch
        loadwordunsigned:
        r[getra] = *mmu.read16wa(r[getrb] + sign_extend(getdisp));
        fetch
        dispatch
        storeword:
        mmu.writewa(r[getrb] + sign_extend(getdisp),2,&r[getra]);
        fetch
        dispatch
        storebyte:
        mmu.writewa(r[getrb] + sign_extend(getdisp),1,&r[getra]);
        fetch
        dispatch
        storequadwordunaligned:
        mmu.write(r[getrb] + sign_extend(getdisp),8,&r[getra]);
        fetch
        dispatch
        arithmetic10:
        val = (std::bitset<32>(inst.full)[19] == 1) ? (getliteral) : r[(getrb)];
        static void *jumplist[64] = {&&addl, &&reserved,&&reserved,&&s4addl,&&reserved,&&reserved,&&subl,&&reserved,&&reserved,&&s4subl,&&reserved,&&reserved,&&s8addl,&&reserved,&&s8subl,&&cmpult,&&reserved,&&cmpbge,&&addq,&&reserved,&&reserved,&&s4addq,&&reserved,&&reserved,&&subq,&&reserved,&&reserved,&&s4subq,&&reserved,&&reserved,&&cmpeq,&&reserved,&&reserved,&&s8addq,&&reserved,&&reserved,&&s8subq,&&reserved,&&reserved,&&cmpule,&&reserved,&&reserved,&&addlv,&&reserved,&&reserved,&&sublv,&&reserved,&&reserved,&&cmplt,&&reserved,&&reserved,&&addqv,&&reserved,&&reserved,&&subqv,&&reserved,&&reserved,&&cmple};
        goto *jumplist[getintegerfunction];
        addl:
        for(int i = 0;i < 32;i++) {
            std::cout << std::bitset<32>(inst.full)[i] << "/" << i << std::endl;
        }
        r[getrc] = sign_extend_32(r[getra] + val);
        fetch
        dispatch
        s4addl:
        r[getrc] = sign_extend_32((r[getra] << 2) + val);
        fetch
        dispatch
        subl:
        r[getrc] = sign_extend_32(r[getra] - val);
        fetch
        dispatch
        s4subl:
        r[getrc] = sign_extend_32((r[getra] << 2) - val);
        fetch
        dispatch
        cmpbge: {
        std::bitset<8> bits;
        for(int i = 0; i < 8;i++) {
            bool compare = ((unsigned char)(r[getra] >> i*8)) >= ((unsigned char)(val >> i*8));
            bits[i] = compare;
        }
        r[getrc] = bits.to_ulong();
        }
        fetch
        dispatch
        s8addl:
        r[getrc] = sign_extend_32((r[getra] << 3) + val);
        fetch
        dispatch
        s8subl:
        r[getrc] = sign_extend_32((r[getra] << 3) - val);
        fetch
        dispatch
        cmpult: {
        r[getrc] = (r[getra] < val);
        }
        fetch
        dispatch
        addq: {
        r[getrc] = r[getra] + val;
        }
        fetch
        dispatch
        s4addq: {
        r[getrc] = (r[getra] << 2) + val;
        }
        fetch
        dispatch
        subq: {
        r[getrc] = r[getra] - val;
        }
        fetch
        dispatch
        s4subq: {
        r[getrc] = (r[getra] << 2) - val;
        }
        fetch
        dispatch
        cmpeq: {
        r[getrc] = (r[getra] == val);
        }
        fetch
        dispatch
        s8addq: {
        r[getrc] = (r[getra] << 3) + val;
        }
        fetch
        dispatch
        s8subq: {
        r[getrc] = (r[getra] << 3) - val;
        }
        fetch
        dispatch
        cmpule:  {
        r[getrc] = (r[getra] <= val);
        }
        fetch
        dispatch
        addlv: {
        r[getrc] = sign_extend_32(r[getra] + val);
        if(!checked_add_32(r[getra],val,NULL))
            throw CPUException(OVERFLOW_EXCEPTION);
        }
        fetch
        dispatch
        sublv: {
        r[getrc] = sign_extend_32(r[getra] - val);
        if(!checked_sub_32(r[getra],val,NULL))
            throw CPUException(OVERFLOW_EXCEPTION);
        }
        fetch
        dispatch
        cmplt: {
        r[getrc] = *(long*)(&r[0] + getra) < *(long*)&val;
        }
        fetch
        dispatch
        addqv: {
        r[getrc] = r[getra] + val;
        if(!checked_add_64(r[getra],val,NULL))
            throw CPUException(OVERFLOW_EXCEPTION);
        }
        fetch
        dispatch
        subqv: {
        r[getrc] = r[getra] - val;
        if(!checked_sub_64(r[getra],val,NULL))
            throw CPUException(OVERFLOW_EXCEPTION);
        }
        fetch
        dispatch
        cmple: {
        r[getrc] = *(long*)(&r[0] + getra) <= *(long*)&val;
        }
        fetch
        dispatch
        bitops:
        val = (std::bitset<32>(inst.full)[19] == 1) ? getliteral : r[getrb];
        static void *handlersl2[64] = {&&andf,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&bic,&&reserved,&&reserved,&&reserved,&&reserved,&&cmovlbs,&&reserved,&&cmovlbc,&&reserved,&&reserved,&&reserved,&&bis,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved,&&reserved};
        goto *handlersl2[getintegerfunction];
        andf:
        r[getrc] = r[getra] & val;
        fetch
        dispatch
        bis:
        r[getrc] = r[getra] | val;
        fetch
        dispatch
        xorf:
        r[getrc] = r[getra] ^ val;
        fetch
        dispatch
        eqv:
        r[getrc] = r[getra] ^ ~val;
        fetch
        dispatch
        ornot:
        r[getrc] = r[getra] | ~val;
        fetch
        dispatch
        bic:
        r[getrc] = r[getra] & ~val;
        fetch
        dispatch
        cmovlbs:
        r[getrc] = ((r[getra] % 2) != 0) ? r[getrb] : r[getrc];
        fetch
        dispatch
        cmovlbc:
        r[getrc] = ((r[getra] % 2) == 0) ? r[getrb] : r[getrc];
        fetch
        dispatch
        cmoveq:
        r[getrc] = (r[getra] == 0) ? r[getrb] : r[getrc];
        fetch
        dispatch
        interrupt:
        //how to handle interrupts(hopefully):
        //realtime signal runs, which copies &&interrupt into all handler slots
        //this allows us to save cycles by not checking for interrupts
        //ever
        //i have no idea if this will work
        dispatch
        reserved:
        //UNPREDICTABLE, doesn't generate exception, but doesn't change operating state
        //this technically allows for implementations that trash registers in the case of a
        //reserved opcode
        //we aren't evil, just continue on as usual
        fetch
        dispatch
        } catch(CPUException &except) {
            std::cout << "Caught CPU Exception, halting... type=" << except.getExceptionType() << std::endl;
            switch(except.getExceptionType()) {
                case ILLEGAL_INSTRUCTION:
                    panic_mode = true;
                    savedpc = pc;
                    break;
            }

            //goto startover;
            //this jump will restart dispatch, and put the cpu back into """normal""" operation
        }
    }
    unsigned char interrupt_vector;
    std::bitset<8> flags;
    RegisterBank<unsigned long, 32> r;
    std::vector<std::function<void()>> function_list;
    private:
    bool panic_mode = false;
    long breakpoint = -1;
    unsigned long n_inst = 0;
    RMMU &mmu;
    int interrupt = false;
    int interrupts_enabled = true;
    unsigned long itableptr = 0;
    unsigned long callstackptr = 0;
    unsigned long pc = 0;
    unsigned long savedpc = 0;
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

    if(arr[2] == 1) {
        std::cout << "alright who's dying first" << std::endl;
    }
    arr[0] = 0b00100000;
    arr[1] = 0b10001111;
    arr[2] = 0b11111000;
    arr[3] = 0b01100010;
    arr[4] = 0b00100010;
    arr[5] = 0b00100001;
    arr[6] = 0b00000000;
    arr[7] = 0b01000010;
    arr[8] = 0b00000010;
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
