struct __cake_alloc
{
    void *begin;
    size_t size;
    struct __cake_alloc *next;
};

typedef struct __cake_alloc alloc;

#define ALLOC_LIST_HEAD __cake_alloc_list_head
#define ALLOC_LIST_HEAD_SYM "__cake_alloc_list_head"

extern alloc *ALLOC_LIST_HEAD;
extern unsigned long recs_allocated;

/* debugging */
void print_head_alloc(void);
