#include "analyzer.h"

void Analyzer::printHelpMenu(char **argv)
{
    std::cout
        << "[+] Usage: " << argv[0] << " [OPTION]... FILE\n"
        << "[+] Analyze and manipulate Mach-O binary files.\n\n"
        << "Options:\n"
        << "  -h, --header       Extract and display Mach-O headers, load commands, and entry points.\n"
        << "  -s, --segment      Analyze memory layout, permissions, and unusual flags.\n"
        << "  -y, --symbol       Detect hidden functions, obfuscated strings, or stripped symbols.\n"
        << "  -d, --disassembly  Extract and analyze executable sections.\n"
        << "  -o, --obfuscation  Identify common obfuscation patterns or suspicious modifications.\n"
        << "  -x, --hex          Provide a formatted hex dump with string extraction.\n"
        << "  -c, --compare      Compare two Mach-O binaries for integrity checks.\n"
        << "  -h, --help         Display this help menu and exit.\n\n"
        << "Examples:\n"
        << "  " << argv[0] << " -h file.macho\n"
        << "  " << argv[0] << " -c file1.macho file2.macho\n\n"
        << "Author:\n"
        << "  https://github.com/wilfrantz ©2025\n";
}

void Analyzer::processCLArguments(int argc, char **argv)
{
    if (argc < 3 || argc > 4)   
    {
        printHelpMenu(argv);
        EXIT_FAILURE;
    }

    for (int argIndex = 1; argIndex < argc; argIndex += 2)
    {
        if (argv[argIndex][0] != '-')
        {
            std::cerr << "[-] Bad option: \"-\" (Error Code: 2)" << std::endl;
            EXIT_FAILURE;
        }

        std::string filename = argv[argc - 1];

        if (filename.empty())
        {
            std::cerr << "[-] Error: No file specified.\n";
            EXIT_FAILURE;
        }

        AnalysisType analysisType;
        switch (argc)
        {
        case 3:
            break;
        case 4:
            // Compare two Mach-O binaries;
            break;

        default:
            printHelpMenu(argv);
            break;
        }
    }
}

void Analyzer::compareMachOBinaries(std::string file1, std::string file2)
{
    std::ifstream file1Stream(file1, std::ios::binary);
    std::ifstream file2Stream(file2, std::ios::binary);

    if (!file1Stream.is_open() || !file2Stream.is_open())
    {
        std::cerr << "[-] Error: Unable to open file(s).\n";
        EXIT_FAILURE;
    }

    // TODO: Compare the two files.
    // ...

    file1Stream.close();
    file2Stream.close();
}