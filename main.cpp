#include "packet_reader.hpp"
#include "callback.hpp"

int main(int argc, const char** argv)
{
    Packman packman{ };
    packman.create_pcapd();
    packman.set_filter_rule(argv[2]);
    packman.start_loop(atoi(argv[1]), callback, nullptr);
}

