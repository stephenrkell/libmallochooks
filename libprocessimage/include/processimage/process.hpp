#ifndef LIBCAKE_PROCESS_HPP
#define LIBCAKE_PROCESS_HPP

#include <string>
#include <map>
#include <functional>

#include <sys/types.h>

#include <link.h>

#include <boost/shared_ptr.hpp>

#include <gelf.h>

#include <dwarfpp/spec.hpp>
#include <dwarfpp/attr.hpp>
#include <dwarfpp/lib.hpp>
#include <dwarfpp/adt.hpp>

#include <libunwind.h>
#include <libunwind-ptrace.h>

/* This is a pointer-alike type which uses libunwind's memory accessors
 * rather than accessing memory directly. This allows access to a remote
 * process's address space as if it were local. Of course the remote 
 * process's ABI has to be compatible (wrt the type Target) with the local
 * process's ABI. Also, expressions involving multiple pointer hops (like
 * **foo or blah->bar->baz) won't work: you have to instantiate this class
 * around each intermediate pointer in turn. */
template <typename Target>
class unw_read_ptr
{
    unw_addr_space_t as;
    void *priv;
    Target *ptr;
    mutable Target buf;
public:
    typedef unw_read_ptr<Target> self_type;
    unw_read_ptr(unw_addr_space_t as, void *priv, Target *ptr) : as(as), priv(priv), ptr(ptr) {}
    Target operator*() const 
    { 
        Target tmp; 
        // simplifying assumption: either Target has a word-multiple size,
        // or is less than one word in size
        assert(sizeof (Target) < sizeof (unw_word_t)
        	|| sizeof (Target) % sizeof (unw_word_t) == 0); // simplifying assumption
        // tmp_base is just a pointer to tmp, cast to unw_word_t*
        unw_word_t *tmp_base = reinterpret_cast<unw_word_t*>(&tmp);
        
        // Handle the less-than-one-word case specially, for clarity
        if (sizeof (Target) < sizeof (unw_word_t))
        {
        	//std::cerr << "Read of size " << sizeof (Target) 
            //	<< " from unaligned address " << reinterpret_cast<void*>(ptr)
            //    << std::endl;
                
        	unw_word_t word_read;
            /* We can't trust access_mem not to access a whole word, 
             * so read the whole word and then copy it to tmp. */
            unw_word_t aligned_ptr 
            	= reinterpret_cast<unw_word_t>(ptr) & ~(sizeof (unw_word_t) - 1);
        	unw_get_accessors(as)->access_mem(as, 
	            aligned_ptr, // aligned read
                &word_read,
                0, // 0 means read, 1 means write
                priv);
            ptrdiff_t byte_offset = reinterpret_cast<char*>(ptr)
             - reinterpret_cast<char*>(aligned_ptr);
            //std::cerr << "Byte offset is " << byte_offset << std::endl;
            // now write to tmp directly
            tmp = *reinterpret_cast<Target*>(reinterpret_cast<char*>(&word_read) + byte_offset);
             
            return tmp;
        }
        else
        {
            // Now read memory one word at a time from the target address space
            for (unw_word_t *tmp_tgt = tmp_base;
        	    // termination condition: difference, in words,
                tmp_tgt - tmp_base < sizeof (Target) / sizeof (unw_word_t);
                tmp_tgt++)
            {
                off_t byte_offset // offset from ptr to the word we're currently reading
                 = reinterpret_cast<char*>(tmp_tgt) - reinterpret_cast<char*>(tmp_base);
                unw_get_accessors(as)->access_mem(as, 
                    reinterpret_cast<unw_word_t>(reinterpret_cast<char*>(ptr) + byte_offset), 
                    tmp_tgt,
                    0,
                    priv);
		    }            
            return tmp;
	    }	
    }
    // hmm... does this work? FIXME
    Target *operator->() const { this->buf = this->operator*(); return &this->buf; } 
    self_type& operator++() // prefix
    { ptr++; return *this; }
    self_type  operator++(int) // postfix ++
    { Target *tmp; ptr++; return self_type(as, priv, tmp); }
    self_type& operator--() // prefix
    { ptr++; return *this; }
    self_type  operator--(int) // postfix ++
    { Target *tmp; ptr--; return self_type(as, priv, tmp); }
    
    // we have two flavours of equality comparison: against ourselves,
    // and against unadorned pointers (risky, but useful for NULL testing)
    bool operator==(const self_type arg) { 
    	return this->as == arg.as
        && this->priv == arg.priv
        && this->ptr == arg.ptr; 
    }
    bool operator==(void *arg) { return this->ptr == arg; }
    
    bool operator!=(const self_type arg) { return !(*this == arg); }
    bool operator!=(void *arg) { return !(this->ptr == arg); }

	// default operator= and copy constructor work for us
    // but add another: construct from a raw ptr
    self_type& operator=(Target *ptr) { this->ptr = ptr; return *this; }
    self_type& operator+=(int arg) { this->ptr += arg; return *this; }
    self_type& operator-=(int arg) { this->ptr -= arg; return *this; }

    self_type operator+(int arg)
    { return self_type(as, priv, ptr + arg); }

    self_type operator-(int arg)
    { return self_type(as, priv, ptr - arg); }

    ptrdiff_t operator-(const self_type arg)
    { return this->ptr - arg.ptr; }
    
    operator void*() { return ptr; }
    
    /* Make this pointer-like thing also an iterator. */
    typedef std::random_access_iterator_tag iterator_category;
    typedef Target value_type;
    typedef ptrdiff_t difference_type;
    typedef Target *pointer;
    typedef Target& reference;
    

};

/* Register access implementation using libunwind. Instances may be 
 * passed to dwarf::lib::evaluator. */
class libunwind_regs : public dwarf::lib::regs
{
    unw_cursor_t *c;
public:
    dwarf::lib::Dwarf_Signed get(int i)
    {
        unw_word_t regval;
        switch(i)
        {
// DWARF x86 register numbers pilfered from libunwind/src/x86/unwind_i.h
#define EAX     0
#define ECX     1
#define EDX     2
#define EBX     3
#define ESP     4
#define EBP     5
#define ESI     6
#define EDI     7
#define EIP     8
#define EFLAGS  9
#define TRAPNO  10
#define ST0     11
            case EAX: unw_get_reg(c, UNW_X86_EAX, &regval); break;
			case EDX: unw_get_reg(c, UNW_X86_EDX, &regval); break;
			case ECX: unw_get_reg(c, UNW_X86_ECX, &regval); break;
			case EBX: unw_get_reg(c, UNW_X86_EBX, &regval); break;
			case ESI: unw_get_reg(c, UNW_X86_ESI, &regval); break;
            case EDI: unw_get_reg(c, UNW_X86_EDI, &regval); break;
            case EBP: unw_get_reg(c, UNW_X86_EBP, &regval); 
                std::cerr << "read EBP as 0x" << std::hex << regval << std::endl;
                break;
            case ESP: unw_get_reg(c, UNW_X86_ESP, &regval); 
                std::cerr << "read ESP as 0x" << std::hex << regval << std::endl;                    
                break;
            case EIP: unw_get_reg(c, UNW_X86_EIP, &regval); break;
            case EFLAGS: unw_get_reg(c, UNW_X86_EFLAGS, &regval); break;
            case TRAPNO: unw_get_reg(c, UNW_X86_TRAPNO, &regval); break;
            default:
                throw dwarf::lib::Not_supported("unsupported register number");
        }
        return regval;
    }
    libunwind_regs(unw_cursor_t *c) : c(c) {}
};
#undef EAX 
#undef ECX 
#undef EDX 
#undef EBX 
#undef ESP 
#undef EBP 
#undef ESI 
#undef EDI 
#undef EIP 
#undef EFLAGS 
#undef TRAPNO 
#undef ST0 
        

        
/* Utility function: search multiple diesets for the first 
 * DIE matching a predicate. */
boost::shared_ptr<dwarf::spec::basic_die> resolve_first(
    std::vector<std::string> path,
    std::vector<boost::shared_ptr<dwarf::spec::with_named_children_die> > starting_points,
    bool(*pred)(dwarf::spec::basic_die&) = 0);

struct process_image
{
	/* We maintain a map of loaded objects, so that we can maintain
     * a dieset open on each one. We must keep this map in sync with the
     * actual process map. */
    typedef unw_word_t addr_t;
	typedef std::pair<addr_t, addr_t> entry_key;

    struct entry
    {
        char r, w, x, p;
        int offset;
        int maj, min;
        int inode;
        std::string seg_descr;
    };
    enum memory_kind
    {
	    UNKNOWN,
        STACK,
        HEAP,
        STATIC
    };
	static const char *name_for_memory_kind(/*memory_kind*/ int k); // relaxation for ltrace++
    
    struct file_entry
    {
    	boost::shared_ptr<std::ifstream> p_if;
        boost::shared_ptr<dwarf::lib::file> p_df;
        boost::shared_ptr<dwarf::lib::dieset> p_ds;
    };
    
	std::map<entry_key, entry> objects;
    std::map<entry_key, entry>::iterator objects_iterator;
    std::map<std::string, file_entry> files;
    typedef std::map<std::string, file_entry>::iterator files_iterator;
    
    /* Problem: all addresses could have i_file be the executable;
     * do we want to support i_file being libraries too? Do we want
     * a single vaddr to have multiple section_ and segment_addresses? */
    struct section_address
    { 
    	files_iterator i_file;
        std::string section_name;
        GElf_Off offset; // offset in file? or in vaddr-space defined by ELF file?
    };
    struct segment_address
    { 
    	files_iterator i_file;
        std::string segment_name;
        GElf_Off offset; // offset in file? or in vaddr-space defined by ELF file?
    };

private:
	pid_t m_pid;
    unw_addr_space_t unw_as;
    unw_accessors_t unw_accessors;
    void *unw_priv;
    unw_context_t unw_context;
    r_debug rdbg;
    std::vector<std::string> seen_map_lines;
    files_iterator i_executable; // points to the files entry representing the executable
    Elf *executable_elf;
public:
    process_image(pid_t pid = -1) 
    : m_pid(pid == -1 ? getpid() : pid),
      unw_as(pid == -1 ? 
      	unw_local_addr_space : 
        unw_create_addr_space(&_UPT_accessors/*&unw_accessors*/, 0)),
        executable_elf(0)
    {
    	int retval = unw_getcontext(&unw_context);
        assert(retval == 0);
    	if (pid == -1)
        {
        	unw_accessors = *unw_get_accessors(unw_local_addr_space);
            unw_priv = 0;
        }
        else 
        {
        	unw_accessors = _UPT_accessors;
        	unw_priv = _UPT_create(m_pid);
	    }
    	update();
    }
    void update();
    ~process_image() { if (executable_elf) elf_end(executable_elf); }
    
    std::map<std::string, file_entry>::iterator find_file_by_realpath(const std::string& path);
    memory_kind discover_object_memory_kind(addr_t addr);
    addr_t get_dieset_base(dwarf::lib::abstract_dieset& ds);
    addr_t get_library_base(const std::string& path);

	typedef dwarf::spec::with_runtime_location_die::sym_binding_t sym_binding_t;
    sym_binding_t resolve_symbol(files_iterator file, const std::string& sym);
    
	typedef int (*stack_frame_cb_t)(process_image *image,
    	unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg);
    int walk_stack(void *stack_handle, stack_frame_cb_t handler, void *handler_arg);
    
    boost::shared_ptr<dwarf::spec::basic_die> find_first_matching(
        bool(*pred)(boost::shared_ptr<dwarf::spec::basic_die>, void *pred_arg), void *pred_arg);
    
    files_iterator find_file_for_ip(unw_word_t ip);
    boost::shared_ptr<dwarf::spec::compile_unit_die> find_compile_unit_for_ip(unw_word_t ip);    
    boost::shared_ptr<dwarf::spec::subprogram_die> find_subprogram_for_ip(unw_word_t ip);    
    boost::shared_ptr<dwarf::spec::with_runtime_location_die> find_most_specific_die_for_addr(addr_t addr);        

private:
    addr_t get_library_base_local(const std::string& path);
    addr_t get_library_base_remote(const std::string& path);
    bool rebuild_map();
    void update_rdbg();
    void update_i_executable();
    void update_executable_elf();
public:
	addr_t get_object_from_die(boost::shared_ptr<dwarf::spec::with_runtime_location_die> d,
		dwarf::lib::Dwarf_Addr vaddr);
    boost::shared_ptr<dwarf::spec::basic_die> discover_object_descr(addr_t addr,
    	boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type
         = boost::shared_ptr<dwarf::spec::type_die>(),
        addr_t *out_object_start_addr = 0);
    boost::shared_ptr<dwarf::spec::basic_die> discover_stack_object(addr_t addr,
        addr_t *out_object_start_addr);
    boost::shared_ptr<dwarf::spec::basic_die> discover_stack_object_local(
    	addr_t addr, addr_t *out_object_start_addr);
    boost::shared_ptr<dwarf::spec::basic_die> discover_stack_object_remote(
    	addr_t addr, addr_t *out_object_start_addr);
        
    boost::shared_ptr<dwarf::spec::basic_die> discover_heap_object(addr_t addr,
    	boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type,
        addr_t *out_object_start_addr);
    boost::shared_ptr<dwarf::spec::with_runtime_location_die> discover_object(
    	addr_t addr,
        addr_t *out_object_start_addr);
    std::pair<GElf_Shdr, GElf_Phdr> get_static_memory_elf_headers(addr_t addr);
    // various ELF conveniences
    bool is_linker_code(addr_t addr)
    {	
    	auto kind = get_static_memory_elf_headers(addr);
    	return kind.first.sh_type == SHT_PROGBITS // FIXME: this is WRONG!
         && kind.second.p_type == PT_LOAD
         && (kind.second.p_flags & PF_X);
    }
    std::string nearest_preceding_symbol(addr_t addr); // FIXME: implement this
};
process_image::sym_binding_t resolve_symbol_from_process_image(
	const std::string& sym, /*process_image::files_iterator * */ void *p_file_iterator);
int stack_print_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg);
int stack_object_discovery_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg);
struct stack_object_discovery_handler_arg
{
	// in
	process_image::addr_t addr;
    // out
    boost::shared_ptr<dwarf::spec::basic_die> discovered_die;
    process_image::addr_t object_start_addr;
};        

std::ostream& operator<<(std::ostream& s, const process_image::memory_kind& k);

#endif
