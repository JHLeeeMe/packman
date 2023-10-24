#include "packet_reader.hpp"
#include "callback.hpp"

void help()
{
    std::cout << "Usage: program [<LOOP_COUNT> <FILTER_RULE>]\n"
              << "\n"
              << "Arguments:\n"
              << "  LOOP_COUNT    The number of loops to run (default: INF).\n"
              << "  FILTER_RULE   The pcap filter rule (default: \"\").\n"
              << "e.g. CXX_Packman 0 tcp\n"
    << std::endl;
}

int main(int argc, const char** argv)
{
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help")
        {
            help();
            return 0;
        }
    }

    Packman packman{ };
    packman.create_pcapd();

    int loop_cnt = 0;
    if (argc > 2)
    {
        packman.set_filter_rule(argv[2]);
        loop_cnt = atoi(argv[1]);
    }
    else
    {
        packman.set_filter_rule("");
    }

    packman.start_loop(loop_cnt, callback, nullptr);

    return 0;
}

