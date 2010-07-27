#include <iostream>

#include <processimage/process.hpp>

process_image me(-1); 

struct foo 
{
	int x;
    double y;
} global;

static int a(foo arg1, int arg2);
static int b(int arg1);
static int c(void *arg);
static int a(foo arg1, int arg2)
{
	struct
    {
    	int xyzzy;
        int plugh;
    } myvar;
    b(arg2);
	return 20;
}

static int b(int arg1)
{
	foo it = {1, 2.0};
    c(&it);
    c(&arg1);
}

static int c(void *arg)
{
	process_image::addr_t out = 0;
    std::cout << "Address of local variable in c() is " << &out << std::endl;
	std::cout << "Discovering object at " << arg << std::endl;// " to have typeinfo at " << 
	auto discovered = me.discover_stack_object(reinterpret_cast<process_image::addr_t>(arg), &out);
    assert(discovered);
    std::cout << *discovered << std::endl;
    
    return 0;
}

int main(int argc, char **argv);
int main(int argc, char **argv)
{
	a(global /* copied */, 42);
    return 0;
}
