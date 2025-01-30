#include "analyzer.h"

namespace machXplorer
{

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
            << "  --help         Display this help menu and exit.\n\n"
            << "Examples:\n"
            << "  " << argv[0] << " -h file.macho\n"
            << "  " << argv[0] << " -c file1.macho file2.macho\n\n"
            << "Author:\n"
            << "  https://github.com/wilfrantz ©2025\n";
    }

    void Analyzer::processCLArguments(int argc, char **argv)
    {
        // Ensure enough arguments are provided
        if (argc < 3)
        {
            std::cerr << "[-] Error: Insufficient arguments provided.\n";
            printHelpMenu(argv);
            exit(EXIT_FAILURE);
        }

        // Process the file based on the analysis type
        AnalysisType type = setAnalysisType(argv);

        if (type == AnalysisType::INVALID)
        {
            std::cerr << "[-] Error: Invalid option provided.\n";
            printHelpMenu(argv);
            exit(EXIT_FAILURE);
        }
        else if (type == AnalysisType::HELP)
        {
            printHelpMenu(argv);
            exit(EXIT_SUCCESS);
        }
        else if (type == AnalysisType::COMPARE)
        {
            if (argc < 4)
            {
                std::cerr << "[-] Error: Insufficient arguments provided for comparison.\n";
                printHelpMenu(argv);
                exit(EXIT_FAILURE);
            }
            const std::string &file = argv[2];
            const std::string &file2 = argv[3];
            analyzeMachOBinary(file, file2, type);
        }
        else
        {
            const std::string &file = argv[2];
            analyzeMachOBinary(file, "", type);
        }
    }

    Analyzer::AnalysisType Analyzer::setAnalysisType(char **argv)
    {
        if (!argv[1]) // Defensive check in case argv[1] is null
        {
            return AnalysisType::INVALID;
        }

        std::string option(argv[1]);

        if (option == "-h" || option == "--header")
            return AnalysisType::HEADER;
        if (option == "-s" || option == "--segment")
            return AnalysisType::SEGMENT;
        if (option == "-y" || option == "--symbol")
            return AnalysisType::SYMBOL;
        if (option == "-d" || option == "--disassembly")
            return AnalysisType::DISASSEMBLY;
        if (option == "-o" || option == "--obfuscation")
            return AnalysisType::OBFUSCATION;
        if (option == "-x" || option == "--hex")
            return AnalysisType::HEX;
        if (option == "-c" || option == "--compare")
            return AnalysisType::COMPARE;
        if (option == "--help")
            return AnalysisType::HELP;

        return AnalysisType::INVALID; // Avoid immediate exit here
    }

    void Analyzer::analyzeMachOBinary(const std::string &file,
                                      const std::string &file2,
                                      const AnalysisType type)
    {
        switch (type)
        {
        case AnalysisType::HEADER:
            analyzeHeader(file);
            break;
        case AnalysisType::SEGMENT:
            analyzeSegment(file);
            break;
        case AnalysisType::SYMBOL:
            analyzeSymbol(file);
            break;
        case AnalysisType::DISASSEMBLY:
            analyzeDisassembly(file);
            break;
        case AnalysisType::OBFUSCATION:
            analyzeObfuscation(file);
            break;
        case AnalysisType::HEX:
            analyzeHexDump(file);
            break;
        case AnalysisType::COMPARE:
            compareMachOBinaries(file, file2);
            break;
        case AnalysisType::HELP:
            // NOTE: No need to implement help menu here.
            break;
        case AnalysisType::INVALID:
            std::cerr << "[-] Error: Invalid option provided.\n";
            break;
        }
    }

    void Analyzer::compareMachOBinaries(const std::string &file1, const std::string &file2)
    {

        if (file1.empty() || file2.empty())
        {
            std::cerr << "[-] Error: Missing file(s).\n";
            EXIT_FAILURE;
        }

        std::ifstream file1Stream(file1, std::ios::binary);
        std::ifstream file2Stream(file2, std::ios::binary);

        if (!file1Stream.is_open() || !file2Stream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file(s).\n";
            EXIT_FAILURE;
        }

        // TODO: Compare the two files.
        // ...
        std::printf("[+] Comparing %s and %s\n", file1.c_str(), file2.c_str());

        file1Stream.close();
        file2Stream.close();
    }

    /***
     * Analyze the header of a Mach-O binary file.
     * This function extracts and displays the Mach-O headers,
     * load commands, and entry points.
     * @param file The Mach-O binary file to analyze.
     * @return void
     ***/
    void Analyzer::analyzeHeader(const std::string &file)
    {
        std::cout << "[+] Analyzing header of file: " << file << std::endl;
        std::ifstream fileStream(file, std::ios::binary);

        if (!fileStream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            exit(EXIT_FAILURE);
        }

        // Read the Mach-O header
        mach_header_64 header64;
        fileStream.read(reinterpret_cast<char *>(&header64), sizeof(header64));

        if (!fileStream)
        {
            std::cerr << "[-] Error: Unable to read Mach-O header.\n";
            fileStream.close();
            exit(EXIT_FAILURE);
        }

        // Print header information
        printHeaderInfo(&header64);

        fileStream.close();
    }

    void Analyzer::printHeaderInfo(const mach_header_64 *header)
    {
        std::cout << "[+] Mach-O Header Information:\n";
        std::cout << "  Magic: " << std::hex << header->magic << std::dec << "\n";
        std::cout << "  CPU Type: " << header->cputype << "\n";
        std::cout << "  CPU Subtype: " << header->cpusubtype << "\n";
        std::cout << "  File Type: " << header->filetype << "\n";
        std::cout << "  Number of Load Commands: " << header->ncmds << "\n";
        std::cout << "  Size of Load Commands: " << header->sizeofcmds << "\n";
        std::cout << "  Flags: " << header->flags << "\n";
    }

    void Analyzer::analyzeSegment(const std::string &file) {}
    void Analyzer::analyzeSymbol(const std::string &file) {}
    void Analyzer::analyzeDisassembly(const std::string &file) {}
    void Analyzer::analyzeObfuscation(const std::string &file) {}
    void Analyzer::analyzeHexDump(const std::string &file) {}

} // namespace machXplorer
