#include "process.hpp"
#include <fstream>
#include <sstream>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fileno.hpp>
//#define _GNU_SOURCE
#include <link.h>
#include <gelf.h>

#ifndef ELF_MAX_SEGMENTS
#define ELF_MAX_SEGMENTS 50
#endif

using namespace dwarf;
/*using namespace dwarf::lib;*/ // omitted to remove Elf ambiguity
using std::string;

void process_image::update()
{
	bool changed = rebuild_map();
	if (changed)
    {
    	update_i_executable();
	    update_executable_elf();
    }
}

bool process_image::rebuild_map()
{
    std::ostringstream filename;
    filename << "/proc/" << m_pid << "/maps";
    std::vector<std::string> map_contents;
    // read the maps file
    string line;
	std::ifstream map_file(filename.str());
    while (map_file)
    {
        std::getline(map_file, line, '\n'); 
        map_contents.push_back(line);
    }
    // has it changed since last update?
    if (map_contents == seen_map_lines) return false;
	// else... do the update
    seen_map_lines = map_contents;
	// open the process map for the file
    char seg_descr[PATH_MAX + 1];
	std::map<entry_key, entry> new_objects; // replacement map
    
    for (auto i = seen_map_lines.begin(); i != seen_map_lines.end(); i++)
    {
		#undef NUM_FIELDS
		#define NUM_FIELDS 11
        entry_key k;
        entry e;
        int fields_read = sscanf(i->c_str(), 
        	"%p-%p %c%c%c%c %8x %2x:%2x %d %s\n",
    	    &k.first, &k.second, &e.r, &e.w, &e.x, &e.p, &e.offset, &e.maj, &e.min, &e.inode, 
            seg_descr);

		// we should only get an empty line at the end
		if (fields_read == EOF) { assert(i+1 == seen_map_lines.end()); }
        else
        {
            if (fields_read < (NUM_FIELDS-1)) throw string("Bad maps data! ") + *i;

            if (fields_read == NUM_FIELDS) e.seg_descr = seg_descr;
            else e.seg_descr = std::string();

            if (objects.find(k) == objects.end() // common case: adding a new object
        	    || string(objects.find(k)->second.seg_descr) != objects[k].seg_descr) 
                 // less common case: same start/end but different libname
            {
        	    if (seg_descr[0] == '/' && files.find(seg_descr) == files.end())
        	    {
            	    files[seg_descr].p_if = boost::make_shared<std::ifstream>(seg_descr);
                    if (*files[seg_descr].p_if)
                    {
	                    int fd = fileno(*files[seg_descr].p_if);
    	                if (fd != -1)
                        {
                    	    try
                            {
                    		    files[seg_descr].p_df = boost::make_shared<lib::file>(fd);
                                files[seg_descr].p_ds = boost::make_shared<lib::dieset>(
                        	        *files[seg_descr].p_df);
                    	    }
                            catch (dwarf::lib::No_entry)
                            {
                        	    files[seg_descr].p_df = boost::shared_ptr<lib::file>();
                                files[seg_descr].p_ds = boost::shared_ptr<lib::dieset>();
                            }
                        }
                        else 
                        {
                    	    files[seg_descr].p_if->close();
                        }
                    }
                }
            }
            // now we can assign the new entry to the map
            new_objects[k] = e;
        }
	}
    objects = new_objects;
    return true;
}

void process_image::update_i_executable()
{
    /* FIXME: if a mapping goes away, we remove its entry but leave its 
     * file open. This does no harm, but would be nice to delete it. */
    	/* We should have the executable open already -- find it. */
    std::ostringstream filename;
    filename << "/proc/" << m_pid << "/exe";
    //char link_target[PATH_MAX];
    //int retval;
    //retval = readlink(filename.str().c_str(), link_target, PATH_MAX);
    //assert(retval != -1);
    char real_exec[PATH_MAX];
    char *retpath;
    retpath = realpath(/*link_target*/filename.str().c_str(), real_exec);
    assert(retpath != NULL);
    i_executable = files.end();
    // HACK: we may have to go round twice, if we're racing
    // with a child about to exec(): we won't find the executable
    // first time, but assuming /proc/.../maps is replaced
    // atomically, we will find it second time.
    for (int j = 0; j < 2; j++)
    {
        for (auto i = files.begin(); i != files.end(); i++)
        {
    	    if (i->first == std::string(real_exec))
            {
			    /* Found the executable */
                i_executable = i;
                return;
		    }
	    }
        if (i_executable == files.end() && j == 0)
        {
    	    rebuild_map();
	    }    
    }
    assert(false);
}

void process_image::update_executable_elf()
{
    assert(i_executable != files.end());
    int fd = fileno(*i_executable->second.p_if);
    assert(fd != -1);
    if (elf_version(EV_CURRENT) == EV_NONE)
	{
		/* library out of date */
		/* recover from error */
        assert(0);
	}
	this->executable_elf = elf_begin(fd, ELF_C_READ, NULL);
		
}

/* Utility function: search multiple diesets for the first 
 * DIE matching a predicate. */
boost::shared_ptr<spec::basic_die> resolve_first(
    std::vector<string> path,
    std::vector<boost::shared_ptr<spec::with_named_children_die > > starting_points,
    bool(*pred)(spec::basic_die&) /*=0*/)
{
	for (auto i_start = starting_points.begin(); i_start != starting_points.end(); i_start++)
    {
    	std::vector<boost::shared_ptr<spec::basic_die> > results;
        (*i_start)->scoped_resolve_all(path.begin(), path.end(), results);
        for (auto i_result = results.begin(); i_result != results.end(); i_result++)
        {
        	assert(*i_result); // result should not be null ptr
        	if (!pred || pred(**i_result)) return *i_result;
		}
    }
}

boost::shared_ptr<dwarf::spec::basic_die> 
process_image::find_first_matching(
        bool(*pred)(boost::shared_ptr<dwarf::spec::basic_die>, void *pred_arg),
        void *pred_arg)
{
	for (auto i_file = files.begin(); i_file != files.end(); i_file++)
    {
    	if (i_file->second.p_ds)
        {
        	for (auto i_die = i_file->second.p_ds->begin(); i_die != i_file->second.p_ds->end(); i_die++)
            {
            	auto die_ptr = (*i_file->second.p_ds)[i_die.base().off];
            	if (pred(die_ptr, pred_arg))
                {
                	return die_ptr;
                }
            }
        }
	}
}

process_image::addr_t process_image::get_dieset_base(dwarf::lib::abstract_dieset& ds)
{
    int retval;
    /* First get the filename of the dieset, by searching through
     * the files map. */
    files_iterator found = files.end();
    for (auto i = files.begin(); i != files.end(); i++)
    {
    	if (i->second.p_ds.get() == &ds) { found = i; break; }
    }
    if (found == files.end()) 
    {
		std::cerr << "Warning: failed to find library for some dieset..." << std::endl;
    	return 0; // give up
    }

	return get_library_base(found->first.c_str());
}

struct callback_in_out
{
	const char *name_in;
    void *load_addr_out;
};
static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	const char *name_sought = ((callback_in_out *)data)->name_in;
    size_t sought_namelen = strlen(name_sought);
    size_t cur_obj_namelen = strlen(info->dlpi_name);
    // search for a *suffix match*
    // FIXME: fix s.t. prefix must end in '/'
	if (strncmp(info->dlpi_name + (cur_obj_namelen - sought_namelen),
    	name_sought, sought_namelen) == 0)
    {
    	((callback_in_out *)data)->load_addr_out = (void*) info->dlpi_addr;
    	return 1;
    }
    else return 0; // 0 means "carry on searching"
}
process_image::addr_t process_image::get_library_base(const std::string& path)
{
	char real_path[PATH_MAX]; 
    int retval;
    char *retpath = realpath(path.c_str(), real_path);
    assert(retpath != NULL);
    if (m_pid == getpid())
    {
    	/* use the local version */
        return get_library_base_local(std::string(real_path));
    }
    else
    {
    	/* use the remote version */
        return get_library_base_remote(std::string(real_path));
    }
}

process_image::addr_t process_image::get_library_base_local(const std::string& path)
{
    callback_in_out obj = { path.c_str()/*"libcake.so"*/, 0 };
    /* dl_iterate_phdr doesn't include the executable in its
     * list, so if we're looking for that, short-cut. */
    if (path == i_executable->first)
    {
    	return 0;
    }
    int retval = dl_iterate_phdr(phdr_callback, &obj);
    if (retval)
    {
    	// result -- we found the library
        addr_t library_base = reinterpret_cast<addr_t>(obj.load_addr_out);
        return library_base;
    }
    else
    {
    	// not a result: didn't find the library
		std::cerr << "Warning: failed to find library for some DIE..." << std::endl;
    	return 0;
	}
}

void process_image::update_rdbg()
{
	void *dyn_addr = 0;
	GElf_Ehdr ehdr;
	if (this->executable_elf != NULL 
        && elf_kind(executable_elf) == ELF_K_ELF 
        && gelf_getehdr(executable_elf, &ehdr))
    {
	    for (int i = 1; i < ehdr.e_shnum; ++i) 
        {
		    Elf_Scn *scn;
		    GElf_Shdr shdr;
		    const char *name;

		    scn = elf_getscn(executable_elf, i);
		    if (scn != NULL && gelf_getshdr(scn, &shdr))
            {
			    name = elf_strptr(executable_elf, ehdr.e_shstrndx, shdr.sh_name);
                switch(shdr.sh_type)
                {
                    case SHT_DYNAMIC:
                    {
                    	dyn_addr = (void*)(unsigned) shdr.sh_addr;
                        break;
                    }
                    default: continue;
                }
            }
        }
    }
    assert(dyn_addr != 0);
    /* Search the dynamic section for the DT_DEBUG tag. */
    int done = 0, i = 0;
	ElfW(Dyn) entry;
    
	unw_read_ptr<ElfW(Dyn)> search_ptr(
    	this->unw_as, this->unw_priv, 
        static_cast<ElfW(Dyn)*>(dyn_addr));
	
    void *dbg_addr;
    do
    {
     	entry = *search_ptr;
		if (entry.d_tag == DT_DEBUG) {
			done = 1;
			dbg_addr = reinterpret_cast<void*>(entry.d_un.d_val);
		}
        search_ptr++; // += sizeof (entry);
    } while (!done && entry.d_tag != DT_NULL && 
                ++i < ELF_MAX_SEGMENTS); // HACK: tolerate .dynamic sections not terminated by DT_NULL
    
    unw_read_ptr<r_debug> dbg_ptr(this->unw_as, this->unw_priv, 
    	static_cast<r_debug*>(dbg_addr));
    rdbg = *dbg_ptr;
	/* If we don't have a r_debug, this might segfault! */
    /*fprintf(stderr, "Found r_debug structure at %p\n", dbg_addr);*/
}

process_image::addr_t process_image::get_library_base_remote(const std::string& path)
{
	update_rdbg();
    /* Now crawl the link map. */
    struct link_map rlm;
    typedef unw_read_ptr<link_map> lm_ptr_t;
    typedef unw_read_ptr<char> remote_char_ptr_t;
	for(lm_ptr_t p_lm(this->unw_as, this->unw_priv, rdbg.r_map);
    	p_lm != 0; p_lm = p_lm->l_next)
    {
    	if (p_lm->l_name == NULL)
        {
			//fprintf(stderr, "Invalid library name referenced in dynamic linker map\n");
			return 0;
		}

		if (*remote_char_ptr_t(this->unw_as, this->unw_priv, p_lm->l_name) == '\0') {
			//fprintf(stderr, "Library name is an empty string\n");
			continue;
		}
        
        remote_char_ptr_t beginning_of_string(this->unw_as, this->unw_priv, p_lm->l_name);
        remote_char_ptr_t end_of_string(this->unw_as, this->unw_priv, p_lm->l_name);
        // advance remote pointer to end of string
        while (*++end_of_string != '\0');
        std::string name(beginning_of_string, end_of_string);

		//fprintf(stderr,
        //	"Library %s is loaded at 0x%x\n", name.c_str(), p_lm->l_addr);
        if (path == name) return p_lm->l_addr;
	}
    return 0;
}

process_image::sym_binding_t resolve_symbol_from_process_image(
	const std::string& sym, /*process_image::files_iterator * */ void *p_file_iterator_void)
{
	Elf *elf;
    process_image::files_iterator *p_file_iterator
     = reinterpret_cast<process_image::files_iterator *>(p_file_iterator_void);
	(*p_file_iterator)->second.p_df->get_elf(&elf);
    // code gratefully stolen from Sun libelf docs
    Elf_Scn* scn = 0;
    int number = 0;
    while ((scn = elf_nextscn(elf, scn)) != 0) 
    {
        char *name = 0;
        GElf_Shdr *shdr;
        if ((shdr = gelf_getshdr (scn, shdr)) != 0) 
        {
            if (shdr->sh_type == SHT_DYNSYM) 
            {
                Elf_Data *data;
                char *name;
                char *stringName;
                data = 0;
                int number = 0;
                if ((data = elf_getdata(scn, data)) == 0 || data->d_size == 0)
                {
                    throw dwarf::lib::No_entry(); // FIXME: better choice of exception
                }
                /*now print the symbols*/
                GElf_Sym *esym = (GElf_Sym*) data->d_buf;
                GElf_Sym *lastsym = (GElf_Sym*) ((char*) data->d_buf + data->d_size);
                /* now loop through the symbol table and print it*/
                for (; esym < lastsym; esym++)
                {
                    if ((esym->st_value == 0) ||
                        (GELF_ST_BIND(esym->st_info)== STB_WEAK) ||
                        (GELF_ST_BIND(esym->st_info)== STB_NUM) ||
                        (
                        	(GELF_ST_TYPE(esym->st_info)!= STT_FUNC)
                         && (GELF_ST_TYPE(esym->st_info)!= STT_OBJECT)
                         && (GELF_ST_TYPE(esym->st_info)!= STT_COMMON) // FIXME: support TLS
                        )
                        ) 
                        continue;
                    name = elf_strptr(elf,shdr->sh_link , (size_t)esym->st_name);
                    if(!name)
                    {
                    	// null symbol name
                        
                        //fprintf(stderr,"%sn",elf_errmsg(elf_errno()));
                        //exit(-1);
                        throw dwarf::lib::No_entry(); // FIXME: better choice of exception
                    }
                    else if (sym == std::string(name))
                    {
                    	process_image::sym_binding_t binding;
                        binding.file_relative_start_addr = esym->st_value;
                        binding.size = esym->st_size;
                        return binding;
                    }
                	//printf("%d: %sn",number++, name);
                }
            }
        }
    }
    /* no symtab */
    throw dwarf::lib::No_entry();
}

process_image::addr_t 
process_image::get_object_from_die(
  boost::shared_ptr<spec::with_runtime_location_die> p_d, 
  lib::Dwarf_Addr vaddr)
{
	/* From a DIE, return the address of the object it denotes. 
     * This only works for DIEs describing objects existing at
     * runtime. */

	unsigned char *base = reinterpret_cast<unsigned char *>(get_dieset_base(p_d->get_ds()));
    assert(p_d->get_runtime_location().size() == 1);
    auto loc_expr = p_d->get_runtime_location();
    lib::Dwarf_Unsigned result = dwarf::lib::evaluator(
        loc_expr,
        vaddr,
        p_d->get_spec()
        ).tos();
    unsigned char *retval = base + static_cast<size_t>(result);
    return reinterpret_cast<addr_t>(retval);
}

process_image::memory_kind process_image::discover_object_memory_kind(addr_t addr)
{
	memory_kind ret = UNKNOWN;
	// for each range in the map...
	for (auto i_obj = objects.begin(); i_obj != objects.end(); i_obj++)
    {
    	addr_t begin = i_obj->first.first;
        addr_t end = i_obj->first.second;
        // see whether addr matches this range
        if (addr >= begin && addr < end)
        {
        	const char *seg_descr = i_obj->second.seg_descr.c_str();
            // what sort of line is this?
            switch(seg_descr[0])
            {
                case '[':
                    if (strcmp(seg_descr, "[stack]") == 0)
                    {
                        ret = STACK; break;
				    }
                    else if (strcmp(seg_descr, "[heap]") == 0)
                    {
                        ret = HEAP; break;
                    }
                    else if (strcmp(seg_descr, "[anon]") == 0)
                    {
                        // hmm... anon segments might be alloc'd specially...
                        // ... but it's probably "closest" to report them as heap
                        ret = HEAP; break;
				    }
                    else { ret = UNKNOWN; break; }
                    //break;
                case '/': ret = STATIC; break;
                    //break;
                case '\0': ret = HEAP; break; // treat nameless segments as heap too
                    //break;
                default: ret = UNKNOWN; break;
                    //break;
            }
        }
    }
	return ret;
}    

/* Clearly one of these will delegate to the other. 
 * Which way round do they go? Clearly, discover_object_descr must first
 * delegate to discover_object, in case the object has its own variable DIE,
 * which might have a customised DWARF type. If that fails, we use the
 * generic object discovery stuff based on memory kind. */
 
/* Discover a DWARF type for an arbitrary object in the program address space. */
boost::shared_ptr<spec::basic_die> 
process_image::discover_object_descr(addr_t addr, 
	boost::shared_ptr<spec::type_die> imprecise_static_type /* = null ptr */,
	addr_t *out_object_start_addr /* = 0 */)
{
	auto discovered_obj = discover_object(addr, out_object_start_addr);
    if (discovered_obj)
    {
    	if (discovered_obj->get_tag() == DW_TAG_variable)
	    	return *boost::dynamic_pointer_cast<
    	    	dwarf::spec::variable_die>(discovered_obj)->get_type();
    	else return discovered_obj; // HACK: return subprograms as their own descriptions
    }
    else
    {
    	switch(discover_object_memory_kind(addr))
        {
        	case STATIC:
            	std::cerr << 
                	"Warning: static object DIE search failed for static object at 0x" 
                    << addr << std::endl;
            case STACK:
            	return discover_stack_object(addr, out_object_start_addr);
            case HEAP:
            	return discover_heap_object(addr, imprecise_static_type, out_object_start_addr);
            default:
            case UNKNOWN:
            	std::cerr << "Warning: unknown kind of memory at 0x" << addr << std::endl;
            	return boost::shared_ptr<spec::basic_die>();
        }
    }
}

/* Discover a DWARF variable or subprogram for an arbitrary object in
 * the program. These will usually be static-alloc'd objects, but in
 * DwarfPython they could be heap-alloc'd objects that have been
 * specialised in their layout. Could they be stack-alloc'd? I guess so,
 * although you'd better hope that the C code which allocated them won't
 * be accessing them any more. */
boost::shared_ptr<spec::with_runtime_location_die> 
process_image::discover_object(addr_t addr, addr_t *out_object_start_addr)
{
	boost::shared_ptr<dwarf::spec::basic_die> most_specific
     = boost::dynamic_pointer_cast<dwarf::spec::basic_die>(
     	this->find_most_specific_die_for_addr(addr));

	// if not failed already...
    if (most_specific)
    {
        // we want either a variable or a subprogram
        while (!(
    		    most_specific->get_tag() == DW_TAG_subprogram
    		    || (most_specific->get_tag() == DW_TAG_variable &&
            	    boost::dynamic_pointer_cast<dwarf::spec::variable_die>(most_specific)
                	    ->has_static_storage())))
        {
    	    most_specific = most_specific->get_parent();
            if (most_specific->get_tag() == 0 || most_specific->get_offset() == 0UL)
            {
        	    // failed!
                return boost::shared_ptr<spec::with_runtime_location_die>();
            }
        }
	}
	return boost::dynamic_pointer_cast<dwarf::spec::with_runtime_location_die>(most_specific);
}

boost::shared_ptr<dwarf::spec::basic_die> 
process_image::discover_heap_object(addr_t addr,
    boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type,
    addr_t *out_object_start_addr)
{
	assert(false);
	return boost::shared_ptr<dwarf::spec::basic_die>();
}

//void *
boost::shared_ptr<dwarf::spec::basic_die>
process_image::discover_stack_object(addr_t addr, addr_t *out_object_start_addr/*,
	unw_word_t top_frame_sp, unw_word_t top_frame_ip, unw_word_t top_frame_retaddr,
    const char *top_frame_fn_name*/)
{
    if (m_pid == getpid())
    {
    	/* use the local version */
        return discover_stack_object_local(addr, out_object_start_addr);
    }
    else
    {
    	/* use the remote version */
        return discover_stack_object_remote(addr, out_object_start_addr);
    }
}

boost::shared_ptr<dwarf::spec::basic_die>
process_image::discover_stack_object_local(addr_t addr, addr_t *out_object_start_addr)
{
	stack_object_discovery_handler_arg arg
     = {addr, boost::shared_ptr<dwarf::spec::basic_die>(), 0};
	walk_stack(NULL, stack_object_discovery_handler, &arg);
    // forward output argument
    if (out_object_start_addr) *out_object_start_addr = arg.object_start_addr;
    // extract and return return value
    return arg.discovered_die;
}

int stack_print_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg)
{
    std::cerr << "Found a frame, ip=0x" << std::hex << frame_ip
        << ", sp=0x" << std::hex << frame_sp 
        << ", bp=0x" << std::hex << frame_caller_sp  << std::dec
        //<< ", return_addr=0x" << std::hex << prevframe_ip
        << ", name: " << frame_proc_name << std::endl;
	return 0; // should we stop? no, carry on
}

int stack_object_discovery_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg)
{
	// DEBUG: print the frame
	stack_print_handler(image, frame_sp, frame_ip, frame_proc_name, 
    	frame_caller_sp, frame_callee_ip, 
        frame_cursor, frame_callee_cursor,
        0);
    
    // unpack our argument object 
    struct stack_object_discovery_handler_arg *arg_obj 
     = reinterpret_cast<stack_object_discovery_handler_arg *>(arg);
    process_image::addr_t addr = arg_obj->addr;
        
    // now do the stuff
    if (addr <= (frame_caller_sp - sizeof (int))
        && addr >= frame_sp)
    {
        std::cerr << "Variable at 0x" << std::hex << addr << std::dec
        	<< " appears to be in frame " << frame_proc_name << std::endl;
    }
	else return 0; // keep going

    /* If a variable "appears to be" in a frame X, it might actually
     * be an actual parameter of the current *callee* of X, rather than
     * a local of X.
     * Actual parameters appear to be in the caller's frame, because they
     * come before the break pointer (i.e. higher up in memory). To fix this, 
     * get the debug info for the current ip, and test against the formal
     * parameters. */
    if (frame_callee_ip != 0)
    {
        auto callee_subp = image->find_subprogram_for_ip(frame_callee_ip);
        if(!callee_subp)
		{
			std::cerr << "Warning: no debug info at bp=0x"           // HACK: we don't get 
				<< std::hex << frame_sp << std::dec           // the callee sp, so quote
				<< "; object discovery may miss argument objects."   // current sp as callee bp
				<< std::endl;
			// skip the rest of this test
		}
		else
		{
        	process_image::addr_t dieset_base = image->get_dieset_base(callee_subp->get_ds());
        	unw_word_t dieset_relative_ip = frame_callee_ip - dieset_base;
        	//unw_word_t dieset_relative_addr = reinterpret_cast<unw_word_t>(addr)
        	// - reinterpret_cast<unw_word_t>(dieset_base);
        	libunwind_regs my_regs(&frame_callee_cursor); 
        	dwarf::lib::Dwarf_Signed frame_base;
        	// warn about variadic omission
        	if (callee_subp->is_variadic())
        	{
				std::cerr << "Warning: unwinding varargs frame at bp=0x" // HACK: we don't get 
					<< std::hex << frame_sp << std::dec                  // the callee sp, so quote
					<< "; object discovery may miss objects in this frame."   // current sp as callee bp
					<< std::endl;
        	}
        	auto ret = callee_subp->contains_addr_as_frame_local_or_argument(
        		addr,
            	static_cast<dwarf::lib::Dwarf_Off>(dieset_relative_ip), 
            	&frame_base,
            	&my_regs);
        	if (ret) 
        	{
        		arg_obj->discovered_die = ret->second;
            	// ret.first is the number of bytes that addr was offset into the pointed-to local/arg
            	arg_obj->object_start_addr = addr - ret->first;
        		return 1; // 1 means "can stop now"
        	}
		}
    }
    // if we got here, look for a local of the current frame
    auto frame_subp = image->find_subprogram_for_ip(frame_ip);
    if (!frame_subp)
	{
		std::cerr << "Warning: no debug info at bp=0x"           // HACK: we don't get 
			<< std::hex << frame_caller_sp << std::dec           // the callee sp, so quote
			<< "; object discovery may miss argument objects."   // current sp as callee bp
			<< std::endl;
		return 0;
	}
    process_image::addr_t dieset_base = image->get_dieset_base(frame_subp->get_ds());
    unw_word_t dieset_relative_ip = frame_ip - dieset_base;
    //unw_word_t dieset_relative_addr = reinterpret_cast<unw_word_t>(addr)
    // - reinterpret_cast<unw_word_t>(dieset_base);
    libunwind_regs my_regs(&frame_cursor); 
    dwarf::lib::Dwarf_Signed frame_base;
    auto ret = frame_subp->contains_addr_as_frame_local_or_argument(
        addr,
        static_cast<dwarf::lib::Dwarf_Off>(dieset_relative_ip), 
        &frame_base, 
        &my_regs);
    if (ret) 
    {
        arg_obj->discovered_die = ret->second;
        // ret.first is the number of bytes that addr was offset into the pointed-to local/arg
        arg_obj->object_start_addr = addr - ret->first;
        return 1; // 1 means "can stop now"
    }
    return 0;
            
//         /* To calculate the "frame base" (stack pointer) for the location in
//          * the subprogram, first calculate the offset from the CU base. */
//         //auto containing_cu = callee_subp->enclosing_compile_unit();
//         //assert(containing_cu);
//         process_image::files_iterator subprogram_file = find_file_for_ip(frame_callee_ip);
//         assert(subprogram_file != this->files.end());
//         //// get a CU-relative IP, using contains_addr
//         //auto contains_addr_result = containing_cu->contains_addr(dieset_relative_ip,
//         //    resolve_symbol_from_process_image, &subprogram_file);
//         //assert(contains_addr_result);
//         //unw_word_t cu_relative_ip = *contains_addr_result;
//         //assert(cu_relative_ip >= 0);
//         
//         // now calculate the frame base of the callee
// 
//         auto frame_base_addr = dwarf::lib::evaluator(
//             *callee_subp->get_frame_base(),
//             dieset_relative_ip, // this is the vaddr which selects a loclist element
//             callee_subp->get_ds().get_spec(),
//             &my_regs).tos();
// 
//         try
//         {
//             for (auto fp = callee_subp->get_first_child(); fp; fp = fp->get_next_sibling())
//             {
// 
// 
//                 auto param = boost::dynamic_pointer_cast<dwarf::spec::formal_parameter_die>(fp);
//                 assert(param->get_type());
// 
//                 /* NOTE: addr is process-relative, not file-relative... 
//                  * and so is frame_base (since it was pulled out of registers). */
//                 if (param->contains_addr(reinterpret_cast<dwarf::lib::Dwarf_Addr>(addr), 
//                     frame_base_addr, dieset_relative_ip, &my_regs))
//                 {
//  				    std::cerr << "Variable at " << addr << " is an actual parameter " 
//                         << *param
//                         << " of subprogram " << *callee_subp;
//                 }
//             } // end for each parameter
//         } // end try
//         catch (dwarf::lib::No_entry) {} // terminates loop
//     } // end if callee_ip != 0
// 
// 	/* If we got here, we're looking for locals */
// 
}
        
int process_image::walk_stack(void *stack_handle, stack_frame_cb_t handler, void *handler_arg)
{
	// FIXME: make cross-process-capable, and support multiple stacks
	unw_cursor_t cursor, saved_cursor, prev_saved_cursor;
    int unw_ret;
    unw_ret = unw_getcontext(&this->unw_context);
    unw_init_local(&cursor, /*this->unw_as,*/ &this->unw_context);
    
	unw_word_t prevframe_sp = 0, sp/*, prevframe_ip = 0*/, callee_ip;
    
	// sanity check
    unw_word_t check_prevframe_sp;
    __asm__ ("movl %%esp, %0\n" :"=r"(check_prevframe_sp));
    unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &prevframe_sp);
    assert(check_prevframe_sp == prevframe_sp);
    std::cerr << "Initial sp=0x" << std::hex << prevframe_sp << std::endl;
    
    unw_word_t ip = 0;
	int step_ret;
    char name[100];
    
    int ret; // value returned by handler

#define BEGINNING_OF_STACK 0xbfffffff
    do
    {
        callee_ip = ip;
        prev_saved_cursor = saved_cursor;	// prev_saved_cursor is the cursor into the callee's frame 
        									// FIXME: will be garbage if callee_ip == 0
        saved_cursor = cursor; // saved_cursor is the *current* frame's cursor
        	// and cursor, later, becomes the *next* (i.e. caller) frame's cursor
        
    	/* First get the ip, sp and symname of the current stack frame. */
        unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(unw_ret == 0);
        unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(unw_ret == 0); // sp = prevframe_sp
        unw_ret = unw_get_proc_name(&cursor, name, 100, NULL); 
        if (unw_ret != 0) strncpy(name, "(no name)", 100);
        /* Now get the sp of the previous stack frame, 
         * i.e. the bp of the current frame. N
         
         * NOTE: we're still
         * processing the stack frame ending at sp, but we
         * hoist the unw_step call to here so that we can get
         * the bp of the previous frame (without demanding that
         * libunwind provides bp, e.g. for code compiled with
         * -fomit-frame-pointer -- FIXME: does this work?). 
         * This means "cursor" is no longer current -- use 
         * saved_cursor for the remainder of this iteration!
         * saved_cursor points to the deeper stack frame. */
        int step_ret = unw_step(&cursor);
        if (step_ret > 0)
        {
        	unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &prevframe_sp); assert(unw_ret == 0);
        	//unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &prevframe_ip); assert(unw_ret == 0);
        }
        else if (step_ret == 0)
        {
        	prevframe_sp = BEGINNING_OF_STACK;
            //prevframe_ip = 0x0;
        }
        else
        {
        	assert(false); // what does a retval < 0 mean?
        }
        
        ret = handler(this, sp, ip, name, prevframe_sp, callee_ip, 
        	saved_cursor, prev_saved_cursor, handler_arg); 
        if (ret == 1) break;
       
        assert(step_ret > 0 || prevframe_sp == BEGINNING_OF_STACK);
    } while (ret == 0 && prevframe_sp != BEGINNING_OF_STACK);
    return ret; //boost::shared_ptr<dwarf::spec::basic_die>();
#undef BEGINNING_OF_STACK
}

// struct find_subprogram_pred_arg
// {
// 	unw_word_t ip;
// };
// 
// static
// bool find_subprogram_pred(boost::shared_ptr<spec::basic_die> p_d, void *pred_arg)
// {
// 	return
//     	p_d->get_tag() == DW_TAG_subprogram
//     &&	boost::dynamic_pointer_cast<spec::subprogram_die>(p_d)->get_low_pc()
//     &&  boost::dynamic_pointer_cast<spec::subprogram_die>(p_d)->get_high_pc()
// }

process_image::files_iterator 
process_image::find_file_for_ip(unw_word_t ip)
{
	process_image::files_iterator i_file;
    assert(files.size() > 0);
    
// 	/* HACK: if address is in the PLT or some other runtime artifact,
//      * patch that up here. */
//     if (this->is_linker_code((void*)ip))
//     {
// 		/* use libunwind to get the name of the procedure */
//         char fn_name[4096];
//         int unw_ret;
//         unw_ret = _UPT_get_proc_name(unw_as, ip, fn_name, sizeof fn_name, NULL, unw_priv);
// 		assert(unw_ret == 0);
//         std::cerr << "libunwind thinks ip 0x" << std::hex << ip << std::dec
//         	<< " is under symbol: " << fn_name << std::endl;
// 	}

    for (auto i_entry = this->objects.begin(); i_entry != this->objects.end(); i_entry++)
    {
    	/* Test whether this IP is within this library's mapped regions. */
        if (ip >= i_entry->first.first
            && ip < i_entry->first.second)
        {
            auto found = this->files.find(i_entry->second.seg_descr);
            assert(found != this->files.end());
        	std::cerr << "Found that address 0x" << std::hex << ip
            	<< " is in image of file " << found->first << std::endl;
            return found;
        }
    }
    
// 	for (process_image::files_iterator i_file = this->files.begin(); 
//     	i_file != this->files.end(); i_file++)
//     {
//     	if (i_file->second.p_ds)
//         {
// 
//         }
//     }
    return files.end();
}


static boost::shared_ptr<dwarf::spec::with_runtime_location_die> 
find_more_specific_die_for_addr(dwarf::lib::abstract_dieset::iterator under_here,
    unw_word_t addr);
static boost::shared_ptr<dwarf::spec::with_runtime_location_die> 
find_more_specific_die_for_addr(dwarf::lib::abstract_dieset::iterator under_here,
    unw_word_t addr)
{
// 	std::cerr << "*** looking for a more specific match for addr 0x" 
//     	<< std::hex << addr << std::hex
//     	<< " than DIE at offset 0x" 
//     	<< std::hex << (*under_here)->get_offset() << std::dec << std::endl;
	unsigned initial_depth = under_here.base().path_from_root.size();
    dwarf::spec::abstract_dieset& ds = (*under_here)->get_ds();
    dwarf::spec::abstract_dieset::bfs_policy bfs_state;
	for (dwarf::spec::abstract_dieset::iterator i(++under_here, bfs_state); 
    	i != ds.end() && i.base().path_from_root.size() > initial_depth; 
        i++)
    {
    	auto p_has_location = boost::dynamic_pointer_cast<spec::with_runtime_location_die>(*i);
        if (p_has_location && p_has_location->contains_addr(addr))
        {
// 	        std::cerr << "*** found a more specific match for addr 0x" 
//     	        << std::hex << addr << std::hex
//     	        << " than DIE at offset 0x" 
//     	        << std::hex << (*under_here)->get_offset() << std::dec 
//                 << ": " << *p_has_location << std::endl;
        	return p_has_location;
        }
    }
// 	std::cerr << "*** failed to find a more specific match for addr 0x" 
//     	<< std::hex << addr << std::hex
//     	<< std::endl;
	return boost::shared_ptr<dwarf::spec::subprogram_die> ();
}

boost::shared_ptr<dwarf::spec::compile_unit_die> 
process_image::find_compile_unit_for_ip(unw_word_t ip)
{
	process_image::files_iterator found_file = find_file_for_ip(ip);
    if (found_file != this->files.end())
    {
    	unsigned ip_offset_within_dieset = ip -get_dieset_base(*found_file->second.p_ds);
        boost::shared_ptr<spec::basic_die> found_deeper = found_file->second.p_ds->toplevel();
        while (found_deeper)
        {
        	if (found_deeper->get_tag() == DW_TAG_compile_unit)
            {
            	return boost::dynamic_pointer_cast<spec::compile_unit_die>(found_deeper);
            }
            else
            {
	        	found_deeper = find_more_specific_die_for_addr(
    		       	dwarf::spec::abstract_dieset::iterator(*found_file->second.p_ds, 
                    found_deeper->get_offset(),
                    found_file->second.p_ds->path_from_root(found_deeper->get_offset())), 
                    	ip_offset_within_dieset);
            }
        }
    }
    return boost::shared_ptr<dwarf::spec::compile_unit_die>();
        
        
//         // now search through compile units in the dieset
//         try
//         {
//         	for (boost::shared_ptr<spec::compile_unit_die> p_cu 
//             	= boost::dynamic_pointer_cast<spec::compile_unit_die>(
//                 	found->second.p_ds->toplevel()->get_first_child());
//                 p_cu; // actually terminated by exception
//                 p_cu = boost::dynamic_pointer_cast<spec::compile_unit_die>(p_cu->get_next_sibling()))
//             {
//                 /*if (!(p_cu->get_high_pc() && p_cu->get_low_pc())) // HACK: will do for now
//                 {
//                 	std::cerr << "Warning: not considering CU " << *p_cu
//                     	<< " as it lacks high and/or low-PC attributes." << std::endl;
//                     continue;
//                 }*/
//                 std::cerr << "considering CU: " << *p_cu << std::endl;
//                 /*if (ip_offset_within_dieset >= *p_cu->get_low_pc()
//                  && ip_offset_within_dieset < *p_cu->get_high_pc())
//                 {
//                 	return p_cu;
//                 }*/
//                 if (p_cu->contains_addr(ip_offset_within_dieset)) return p_cu;
//             }
//                 
//         }
//         catch (dwarf::lib::No_entry) {}
//     }
//    return boost::shared_ptr<dwarf::spec::compile_unit_die>();
}

boost::shared_ptr<dwarf::spec::subprogram_die> 
process_image::find_subprogram_for_ip(unw_word_t ip)
{
// 	auto found = find_compile_unit_for_ip(ip);
//     if (found)
//     {
//     	/* PC values in compile unit DIEs are file-relative. */
// 	    unsigned dieset_base = reinterpret_cast<unsigned>(this->get_dieset_base(found->get_ds()));
//     	unsigned ip_offset_within_dieset = ip -
//         	reinterpret_cast<unsigned>(this->get_dieset_base(found->get_ds()));
//         for (dwarf::lib::abstract_dieset::iterator i_die(found->get_ds(), found->get_offset());
//         	i_die != found->get_ds().end();
//             i_die++)
//         {
//         	auto p_with_runtime_location
//         }    
//     }
//     return boost::shared_ptr<dwarf::spec::subprogram_die>();


	process_image::files_iterator found_file = find_file_for_ip(ip);
    if (found_file != this->files.end())
    {
    	unsigned ip_offset_within_dieset = ip - get_dieset_base(*found_file->second.p_ds);
        boost::shared_ptr<spec::basic_die> found_deeper = found_file->second.p_ds->toplevel();
        while (found_deeper)
        {
        	if (found_deeper->get_tag() == DW_TAG_subprogram)
            {
            	return boost::dynamic_pointer_cast<spec::subprogram_die>(found_deeper);
            }
            else
            {
	        	found_deeper = find_more_specific_die_for_addr(
    		       	dwarf::spec::abstract_dieset::iterator(
                    *found_file->second.p_ds, 
                    found_deeper->get_offset(),
                    found_file->second.p_ds->path_from_root(found_deeper->get_offset())), 
                    	ip_offset_within_dieset);
            }
        }
    }
    return boost::shared_ptr<dwarf::spec::subprogram_die>();
 
}

boost::shared_ptr<dwarf::spec::with_runtime_location_die> 
process_image::find_most_specific_die_for_addr(unw_word_t addr)
{
	/* Recursive approach: 
     * - walk depthfirst until we find a with_runtime_location_die 
     * which contains the object. 
     * - on success, try again. */

	process_image::files_iterator found_file = find_file_for_ip(addr);
    if (found_file != this->files.end())
    {
    	unsigned addr_offset_within_dieset = addr - get_dieset_base(*found_file->second.p_ds);
        boost::shared_ptr<spec::basic_die> found_deeper = found_file->second.p_ds->toplevel();
        boost::shared_ptr<spec::basic_die> found_last;
        while (found_deeper)
        {
            found_last = found_deeper;
	        found_deeper = find_more_specific_die_for_addr(
    		    dwarf::spec::abstract_dieset::iterator(*found_file->second.p_ds, 
            	found_deeper->get_offset(),
                found_file->second.p_ds->path_from_root(found_deeper->get_offset())),
                	addr_offset_within_dieset);
        }
        return boost::dynamic_pointer_cast<spec::with_runtime_location_die>(found_last);
    }
    return boost::shared_ptr<dwarf::spec::with_runtime_location_die>();
}

// 	do {
//     	// test our location against the current frame
//         if (stack_loc < reinterpret_cast<void*>(prevframe_sp) 
//         	&& stack_loc >= reinterpret_cast<void*>(sp))
//         {
// 	        fprintf(options.output, "I think the object at %p resides in a %s stack frame with sp=%p, prevframe_sp=%p\n", 
//             	stack_loc, fn_name, sp, prevframe_sp);
//             /* We have found the frame, so we exit the loop. But note that we have
//              * already advanced the cursor to the previous frame, in order to read
//              * prevframe_sp! Later we will need the cursor pointing at *this* frame,
//              * so we use prev_cursor. */
//             break;
// 		}
//         else
//         {
//         	//fprintf(options.output, "I think the object at %p does NOT reside in a %s stack frame with sp=%p, prevframe_sp=%p\n", 
//             //	stack_loc, fn_name, sp, prevframe_sp);
//         }   
//         unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); if (unw_ret != 0) break;
//         unw_ret = unw_get_proc_name(&cursor, fn_name, 100, NULL); if (unw_ret != 0) break;
//         
//         // we've already got the ip, sp and fn_name for this frame, so
//         // advance to the next frame for the prevframe_sp
// 		sp = prevframe_sp;
//         if (sp == BEGINNING_OF_STACK) break;
//         
//         prev_cursor = cursor;
//         prev_cursor_init = true;
//         step_ret = unw_step(&cursor);
// 		if (step_ret > 0) unw_get_reg(&cursor, UNW_REG_SP, &prevframe_sp);
//         else prevframe_sp = BEGINNING_OF_STACK; /* beginning of stack */
//     } while  (1);
//     assert(prev_cursor_init); cursor = prev_cursor;
// #undef BEGINNING_OF_STACK
//     if (strlen(fn_name) == 0) return 0;
//     
//     /* Now use the instruction pointer to find the DIE for the 
//      * function which allocated the stack frame. */
//     boost::optional<dwarf::encap::Die_encap_subprogram&> found;
//     void **dbg_files = (void**) malloc(sizeof (void*) * library_num + 1);
// 	int i;
//     for (i = 0; i < library_num; i++)
//     {
//     	dbg_files[i] = library_dbg_info[i];
//     }
//     dbg_files[i] = exec_dbg_info;
//     
//     for (int j = 0; j <= library_num; j++)
//     {
//     	dwarf::encap::file *p_file 
//          = static_cast<dwarf::encap::file *>(dbg_files[j]);
//         if (!p_file) continue;
//         
//         if (!(p_file->get_ds().map_size() > 1)) break; // we have no info
//          
//         for (auto i_subp = p_file->get_ds().all_compile_units().subprograms_begin();
//         	i_subp != p_file->get_ds().all_compile_units().subprograms_end();
//             i_subp++)
//         {
//             if ((*i_subp)->get_name() && (*i_subp)->get_low_pc() && (*i_subp)->get_high_pc())
//             { 
//             	if (strcmp(fn_name, (*(*i_subp)->get_name()).c_str()) == 0)
//                 {
//             	    fprintf(options.output, "subprogram %s, low %p, high %p\n", 
//                 	    (*(*i_subp)->get_name()).c_str(), 
//                         (void*) *((*i_subp)->get_low_pc()), (void*) *((*i_subp)->get_high_pc()));
//                     std::cerr << **i_subp;
// 	            }
//             	if (ip >= *((*i_subp)->get_low_pc()) && ip < *((*i_subp)->get_high_pc()))
//                 {
//             	    found = **i_subp;
//             	    assert(strcmp(fn_name, (*(*i_subp)->get_name()).c_str()) == 0);
//                     break;
//                 }
// 	        }
//         }
//     }
//     free(dbg_files);
//     if (found)
//     {
//     	dwarf::encap::Die_encap_subprogram& subprogram = *found;
//     	fprintf(options.output, "Successfully tracked down subprogram: %s\n", 
//         	(*subprogram.get_name()).c_str());
//             
//         /* Calculate the "frame base" (stack pointer) for the location in
//          * the subprogram. First calculate the offset from the CU base. */
//         dwarf::lib::Dwarf_Off cu_offset = ip - *subprogram.enclosing_compile_unit().get_low_pc();
//         assert(cu_offset >= 0);
//         std::cerr << "Detected that current PC 0x"
//         	<< std::hex << ip
//            << " has CU offset 0x" << std::hex << cu_offset << std::endl;
//         /* Now select the DWARF expression (in the location list) which
//          * matches the CU offset. */
// 		class libunwind_regs : public dwarf::lib::regs
//         {
//         	unw_cursor_t *c;
//         public:
//             dwarf::lib::Dwarf_Signed get(int i)
//             {
//             	unw_word_t regval;
//             	switch(i)
//                 {
// // from libunwind-x86.h
// #define EAX     0
// #define ECX     1
// #define EDX     2
// #define EBX     3
// #define ESP     4
// #define EBP     5
// #define ESI     6
// #define EDI     7
// #define EIP     8
// #define EFLAGS  9
// #define TRAPNO  10
// #define ST0     11
//                 	case EAX: unw_get_reg(c, UNW_X86_EAX, &regval); break;
// 					case EDX: unw_get_reg(c, UNW_X86_EDX, &regval); break;
// 					case ECX: unw_get_reg(c, UNW_X86_ECX, &regval); break;
// 					case EBX: unw_get_reg(c, UNW_X86_EBX, &regval); break;
// 					case ESI: unw_get_reg(c, UNW_X86_ESI, &regval); break;
//                     case EDI: unw_get_reg(c, UNW_X86_EDI, &regval); break;
//                     case EBP: unw_get_reg(c, UNW_X86_EBP, &regval); 
//                     	std::cerr << "read EBP as 0x" << std::hex << regval << std::endl;
//                         break;
//                     case ESP: unw_get_reg(c, UNW_X86_ESP, &regval); 
//                     	std::cerr << "read ESP as 0x" << std::hex << regval << std::endl;                    
//                     	break;
//                     case EIP: unw_get_reg(c, UNW_X86_EIP, &regval); break;
//                     case EFLAGS: unw_get_reg(c, UNW_X86_EFLAGS, &regval); break;
//                     case TRAPNO: unw_get_reg(c, UNW_X86_TRAPNO, &regval); break;
//                     default:
//                     	throw dwarf::lib::Not_supported("unsupported register number");
//                 }
//                 return regval;
//             }
//         	libunwind_regs(unw_cursor_t *c) : c(c) {}
//         } my_regs(&cursor);
//         boost::optional<dwarf::encap::loc_expr> found;
//         for (auto i_loc_expr = subprogram.get_frame_base()->begin();
//         		i_loc_expr != subprogram.get_frame_base()->end();
//                 i_loc_expr++)
//         {
//           	std::cerr << "Testing whether CU offset 0x" 
//             	<< std::hex << cu_offset << " falls within loc_expr " << *i_loc_expr
//                 	<< std::endl;
// 
//         	if (cu_offset >= i_loc_expr->lopc 
//             	&& cu_offset < i_loc_expr->hipc)
//             {
//             	std::cerr << "Success" << std::endl;
//             	found = *i_loc_expr;
//                 break;
//             }
//         }
//         assert(found);
//         // now evaluate that expression to get the frame_base
//         dwarf::lib::Dwarf_Signed frame_base = dwarf::lib::evaluator(
//         		(*found).m_expr, 
//                 subprogram.get_ds().get_spec(),
//                 my_regs,
//                 0).tos();
//         std::cerr << "Calculated DWARF frame base: 0x" << std::hex << frame_base << std::endl;
//         
//         /* Now for the coup de grace: find the extents of the object 
//          * (local or formal parameter) that spans the pointed-to address.
//          * For robustness, we do this by iterating over all formal 
//          * parameters and locals, and matching their extents. */
//         for (auto i_fp = subprogram.formal_parameters_begin();
//         		i_fp != subprogram.formal_parameters_end();
//                 i_fp++)
//         {        	
//         	unsigned param_begin_addr = dwarf::lib::evaluator(
//         		(*i_fp)->get_location()->at(0).m_expr, 
//                 subprogram.get_ds().get_spec(),
//                 frame_base).tos();
//             assert((*i_fp)->get_type());
//             assert((*i_fp)->get_name());            
//             unsigned param_end_addr
//              = param_begin_addr + 
//              	dwarf::encap::Die_encap_is_type::calculate_byte_size(
//              		*(*i_fp)->get_type());
//             fprintf(options.output,
//             	"Parameter %s spans addresses [%p, %p)\n", 
//             	(*i_fp)->get_name()->c_str(),
//                 param_begin_addr,
//                 (void*)(int) param_end_addr);
//             if (stack_loc >= (void*)(int) param_begin_addr && stack_loc < (void*)(int) param_end_addr)
//             {
//             	if (out_object_start_addr != 0) *out_object_start_addr = (void*)(int) param_begin_addr;
//                 assert((*i_fp)->get_type());
//                 return &*(*i_fp)->get_type();
// 			}            
//         }
//         //for (auto i_var = subprogram.variables_begin();
//         //		i_var != subprogram.variables_end();
//         //        i_var++)
//         for (auto i_dfs = subprogram.depthfirst_begin();
//         		i_dfs != subprogram.depthfirst_end();
//                 i_dfs++)
//         {
//         	/* Here we explore child DIEs looking for DW_TAG_variables.
//              * We only want those defined in a lexical block that is
//              * currently active, so use nearest_enclosing. */
//             if (i_dfs->get_tag() != DW_TAG_variable) continue;
//             
//             /* Find the nearest enclosing lexical block (if any). */
//             auto opt_block = dynamic_cast<dwarf::abstract::Die_abstract_base<dwarf::encap::die>&>(*i_dfs).
//             					nearest_enclosing<DW_TAG_lexical_block>();
//             if (!opt_block || (
//             		ip < *opt_block->get_high_pc() 
//                     && ip >= *opt_block->get_low_pc()))
//             {
//                 dwarf::encap::Die_encap_variable& variable
//                  = dynamic_cast<dwarf::encap::Die_encap_variable&>(*i_dfs);
//         	    unsigned var_begin_addr = dwarf::lib::evaluator(
//         		    variable.get_location()->at(0).m_expr, 
//                     subprogram.get_ds().get_spec(),
//                     my_regs,
//                     frame_base).tos();
//                 assert(variable.get_type());
//                 assert(variable.get_name());            
//                 unsigned var_end_addr
//                  = var_begin_addr + 
//              	    dwarf::encap::Die_encap_is_type::calculate_byte_size(
//              		    *variable.get_type());
//                 fprintf(options.output,
//             	    "Local %s spans addresses [%p, %p)\n", 
//             	    variable.get_name()->c_str(),
//                     var_begin_addr,
//                     (void*)(int) var_end_addr);
//                 if (stack_loc >= (void*)(int) var_begin_addr && stack_loc < (void*)(int) var_end_addr)
//                 {
//             	    if (out_object_start_addr != 0) *out_object_start_addr = (void*)(int) var_begin_addr;
//                     assert(variable.get_type());
//                     return &*variable.get_type();
// 			    }            
//             }
//         }
//         fprintf(options.output, "Failed to find a local or actual parameter for %p\n", stack_loc);
//     }
//     else
//     {
//     	fprintf(options.output, "Failed to track down subprogram for PC %p\n", ip);
//         /* We could get the frame by falling back on symtab.
//          * This isn't much good though. */
//     }
//     
boost::shared_ptr<dwarf::spec::basic_die>
process_image::discover_stack_object_remote(addr_t addr, addr_t *out_object_start_addr)
{
	return boost::shared_ptr<dwarf::spec::basic_die>();
}


const char *process_image::name_for_memory_kind(int k) // relaxation for ltrace++
{
	switch(k)
    {
        case STACK: return "stack";
        case STATIC: return "static";
        case HEAP: return "heap";
    	case UNKNOWN: 
        default: return "unknown";
	}    
}
std::ostream& operator<<(std::ostream& s, const process_image::memory_kind& k)
{
	s << process_image::name_for_memory_kind(k);
    return s;
}

struct realpath_file_entry_cmp 
: public std::unary_function<std::pair<std::string, process_image::file_entry>, bool>
{
	char path_real[PATH_MAX];
	realpath_file_entry_cmp(const char *path) 
    { char *retval = realpath(path, path_real); assert(retval != NULL); }
	bool operator()(const std::pair<std::string, process_image::file_entry>& arg) const
    {
    	char arg_real[PATH_MAX];
        realpath(arg.first.c_str(), arg_real);
        return strcmp(arg_real, path_real) == 0;
    }
};
std::map<std::string, process_image::file_entry>::iterator 
process_image::find_file_by_realpath(const std::string& path)
{
	return std::find_if(this->files.begin(), this->files.end(), 
    	realpath_file_entry_cmp(path.c_str()));
}

std::pair<GElf_Shdr, GElf_Phdr> process_image::get_static_memory_elf_headers(addr_t addr)
{
	assert(this->executable_elf != NULL 
        && elf_kind(executable_elf) == ELF_K_ELF);
	std::pair<GElf_Shdr, GElf_Phdr> retval; //= std::make_pair(SHT_NULL, PT_NULL);
    retval.first.sh_type = SHT_NULL;
    retval.second.p_type = PT_NULL;
            
    GElf_Ehdr ehdr;
    if (gelf_getehdr(executable_elf, &ehdr))
    {
	    for (int i = 1; i < ehdr.e_shnum; ++i) 
        {
		    Elf_Scn *scn;
		    GElf_Shdr shdr;

		    scn = elf_getscn(executable_elf, i);
		    if (scn != NULL && gelf_getshdr(scn, &shdr))
            {
                addr_t section_begin_addr = shdr.sh_addr;
                addr_t section_end_addr = shdr.sh_addr + shdr.sh_size;
                if (addr >= section_begin_addr && addr < section_end_addr)
                {
                    /* Found it! */
                    retval.first = shdr/*.sh_type*/;
                }
            }
        }
    } 
    else assert(false); // we assume gelf_getehdr won't fail

	GElf_Phdr phdr;
    if (gelf_getphdr(executable_elf, 0, &phdr))
    {
        // we got the first phdr
        assert(phdr.p_type == PT_PHDR);
        unsigned num_entries = phdr.p_memsz / sizeof (ElfW(Phdr));
        for (int i = 1; i < num_entries; i++)
        {
        	GElf_Phdr *success = gelf_getphdr(executable_elf, i, &phdr);
            if (success)
            {
				addr_t segment_begin_vaddr = phdr.p_vaddr;
                addr_t segment_end_vaddr = segment_begin_vaddr + phdr.p_memsz;
            	if (addr >= segment_begin_vaddr && addr < segment_end_vaddr)
                {
                	retval.second = phdr/*.p_type*/;
                }
			}
            else
            {
            	fprintf(stderr, "Error getting program header at index %d.\n", i);
            }
        }
    }

    // every static addr should be accounted for by shdrs
    if (retval.first.sh_type != SHT_NULL && retval.second.p_type != PT_NULL) return retval; 
    assert(this->discover_object_memory_kind(addr) != STATIC);
    // call didn't respect precondition
    assert(false);
}
