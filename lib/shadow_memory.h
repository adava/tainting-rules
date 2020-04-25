#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H

#define MAX_NUM_FLAGS 64
#define TARGET_PAGE_BITS 12
typedef signed char  int8_t;
typedef signed short int16_t;
typedef signed int   int32_t;
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef signed long long   int64_t;
typedef unsigned long long uint64_t;

#define PAGE_SIZE_BITS TARGET_PAGE_BITS
#define NUM_PAGES_BITS (32 - PAGE_SIZE_BITS)
#define PAGE_SIZE (1 << PAGE_SIZE_BITS)
#define OFFSET_MASK  (PAGE_SIZE - 1)
#define PAGE_MASK  ((1 << NUM_PAGES_BITS) - 1)
#define SHD_find_offset(vaddr) (uint32_t)(vaddr & OFFSET_MASK)
#define SHD_PAGE_INDEX(vaddr) (vaddr >> PAGE_SIZE_BITS)
#define SHD_find_page_addr(vaddr) (SHD_PAGE_INDEX(vaddr) & PAGE_MASK)
#define SHD_KEY_CONVERSION(addr) ((gconstpointer)addr)

#define GLOBAL_POOL_SIZE 124 //X86 registers plus a bunch more allocated temps

typedef struct shadow_page_struct {
    uint8_t bitmap[PAGE_SIZE]; /* Contains the bitwise tainting data for the page */
} shadow_page;

//typedef struct shadow_global_pool_struct {
//    uint64_t bitmap[GLOBAL_POOL_SIZE]; /* Contains bitwise tainting data for registers and other globals */
//    struct shadow_global_pool_struct *next;
//} shadow_global;

/* Middle node for holding memory taint information */
typedef struct shadow_memory_struct {
    GHashTable *pages; //it’s a hashmap of shadow_pages
    GPtrArray *global_temps; //initially will have GLOBAL_POOL_SIZE len of uint64_t, and then increases if needed
    uint8_t flags[MAX_NUM_FLAGS]; //according to memcheck, one bit is enough but we don't have memory constraint plus handling bits is complicated
} shadow_memory;

enum shadow_type{
    TEMP,
    GLOBAL,
    MEMORY,
    IMMEDIATE, //used for SHIFT, this type MUST not be passed to the shadow storage
    FLAG
};

typedef enum {
    SHD_SIZE_u8= sizeof(uint8_t),
    SHD_SIZE_u16= sizeof(uint16_t),
    SHD_SIZE_u32= sizeof(uint32_t),
    SHD_SIZE_u64= sizeof(uint64_t),
    SHD_SIZE_MAX
} SHD_SIZE;

typedef struct inquiry{
    union{
        uint64_t vaddr;
        int id;
    }addr;
    enum shadow_type type;
    uint8_t size;
} shad_inq;

typedef int shadow_err;

typedef uint64_t SHD_value;

shadow_memory SHD_Memory;

void SHD_init();

int SHD_map_reg(int reg_code); //returns internal ID assignment for CPU registers; change to be a MACRO

guint SHD_ghash_addr(gconstpointer key);

static uint64_t convert_value(void *value, uint8_t size);

SHD_value SHD_get_shadow(shad_inq inq); // based on type, it would inquiry shadow_memory. The caller would fetch the proper value based on the size
shadow_err SHD_set_shadow(shad_inq *inq, void *value); //id for temps would be set by the callee

#endif