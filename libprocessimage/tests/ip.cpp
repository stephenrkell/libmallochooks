#include <cstdio>
#include <iostream>

#include <processimage/process.hpp>

process_image me(-1); 

static void print_dies(unw_word_t ip)
{
    process_image::files_iterator i_file = me.find_file_for_ip(ip);
    
    boost::shared_ptr<dwarf::spec::compile_unit_die> p_cu 
     = me.find_compile_unit_for_ip(ip);
    if (p_cu) std::cout << "Found compile unit: " << *p_cu << std::endl;
    else std::cout << "Didn't find a compile unit." << std::endl;
     
    boost::shared_ptr<dwarf::spec::subprogram_die> p_subp
     = me.find_subprogram_for_ip(ip);    
    if (p_subp) std::cout << "Found a subprogram: " << *p_subp << std::endl;
    else std::cout << "Didn't find a subprogram." << std::endl;
     
    boost::shared_ptr<dwarf::spec::with_runtime_location_die> p_most
     = me.find_most_specific_die_for_addr(ip);
    if (p_most) std::cout << "Found a most specific: " << *p_most << std::endl;
    else std::cout << "Didn't find a most specific." << std::endl;
}

int main(int argc, char **argv)
{
	fprintf(stderr, "Finding DIEs for function main...\n");
    unw_word_t main_ip = reinterpret_cast<unw_word_t>(main);
    print_dies(main_ip);
    
	fprintf(stderr, "Finding DIEs for function fprintf...\n");
    unw_word_t fprintf_ip = reinterpret_cast<unw_word_t>(
    	dlsym(RTLD_NEXT, "fprintf"));
    print_dies(fprintf_ip);

    {
    my_label:
		fprintf(stderr, "Finding DIEs for label my_label...\n");
	    unw_word_t my_label_ip = reinterpret_cast<unw_word_t>(&&my_label);
    	print_dies(my_label_ip);
	}
    
    return 0;
}
