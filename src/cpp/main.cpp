#include "packet_reader.hpp"
#include "callback.hpp"

int main(int argc, const char** argv)
{
    Packman packman{ };
    packman.create_pcapd();
#if 0
    {
        packman.set_filter_rule(argv[2]);
        packman.start_loop(atoi(argv[1]), callback, nullptr);
    }
#else
    {
        packman.set_filter_rule("tcp");
        packman.start_loop(0, callback, nullptr);
    }
#endif

    return 0;
}

