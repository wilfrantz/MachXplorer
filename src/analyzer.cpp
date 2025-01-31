
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

    void Analyzer::analyzeSegment(const std::string &file)
    {
        std::ifstream fileStream(file, std::ios::binary);
        if (!fileStream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            exit(EXIT_FAILURE);
        }

        segment_command_64 segment64;
        fileStream.read(reinterpret_cast<char *>(&segment64), sizeof(segment64));

        printSegmentInfo(&segment64);

        fileStream.close();
    }

    void Analyzer::printSegmentInfo(const segment_command_64 *segment64)
    {
        std::cout << "[+] Segment Information:\n";
        std::cout << "  Segment Name: " << segment64->segname << "\n";
        std::cout << "  VM Address: " << segment64->vmaddr << "\n";
        std::cout << "  VM Size: " << segment64->vmsize << "\n";
        std::cout << "  File Offset: " << segment64->fileoff << "\n";
        std::cout << "  File Size: " << segment64->filesize << "\n";
        std::cout << "  Max VM Protection: " << segment64->maxprot << "\n";
        std::cout << "  Initial VM Protection: " << segment64->initprot << "\n";
        std::cout << "  Number of Sections: " << segment64->nsects << "\n";
        std::cout << "  Flags: " << segment64->flags << "\n";
    }

    void Analyzer::analyzeSection(const std::string &file)
    {
        std::ifstream fileStream(file, std::ios::binary);
        if (!fileStream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            exit(EXIT_FAILURE);
        }

        section_64 *section64;
        fileStream.read(reinterpret_cast<char *>(&section64), sizeof(section64));

        printSectionInfo(section64);

        fileStream.close();
    }

    void Analyzer::printSectionInfo(const section_64 *section64)
    {
        std::cout << "[+] Section Information:\n";
        std::cout << "  Section Name: " << section64->sectname << "\n";
        std::cout << "  Segment Name: " << section64->segname << "\n";
        std::cout << "  Address: " << section64->addr << "\n";
        std::cout << "  Size: " << section64->size << "\n";
        std::cout << "  Offset: " << section64->offset << "\n";
        std::cout << "  Alignment: " << section64->align << "\n";
        std::cout << "  Number of Relocation Entries: " << section64->nreloc << "\n";
        std::cout << "  Flags: " << section64->flags << "\n";
    }
    void Analyzer::analyzeSymbol(const std::string &file)
    {
        std::ifstream filestream(file, std::ios::binary);
        if (!filestream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            exit(EXIT_FAILURE);
        }

        symtab_command symtab;
        filestream.read(reinterpret_cast<char *>(&symtab), sizeof(symtab));

        printSymbolInfo(symtab);
        filestream.close();
    }

    void Analyzer::printSymbolInfo(const symtab_command &symtab64)
    {
        std::cout << "[+] Symbol Information:\n";
        std::cout << "  Symbol Table Offset: " << symtab64.symoff << "\n";
        std::cout << "  Number of Symbols: " << symtab64.nsyms << "\n";
        std::cout << "  String Table Offset: " << symtab64.stroff << "\n";
        std::cout << "  String Table Size: " << symtab64.strsize << "\n";
    }

    void Analyzer::analyzeDisassembly(const std::string &file)
    {
        std::ifstream fileStream(file, std::ios::binary);
        if (!fileStream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            exit(EXIT_FAILURE);
        }

        dysymtab_command dysymtab;
        fileStream.read(reinterpret_cast<char *>(&dysymtab), sizeof(dysymtab));
        printDisassemblyInfo(dysymtab);

        fileStream.close();
    }

    void Analyzer::printDisassemblyInfo(const dysymtab_command &dysymtab)
    {
        std::cout << "[+] Disassembly Information:\n";
        std::cout << "  Command: " << dysymtab.cmd << "\n";
        std::cout << "  Command Size: " << dysymtab.cmdsize << "\n";
        std::cout << " Index of local symbols: " << dysymtab.ilocalsym << "\n";
        std::cout << " Number of local symbols: " << dysymtab.nlocalsym << "\n";
        std::cout << " Index of external symbols: " << dysymtab.iextdefsym << "\n";
        std::cout << " Number of external symbols: " << dysymtab.nextdefsym << "\n";
        std::cout << " Index of undefined symbols: " << dysymtab.iundefsym << "\n";
        std::cout << " Number of undefined symbols: " << dysymtab.nundefsym << "\n";
        std::cout << " File offset to table of contents: " << dysymtab.tocoff << "\n";
        std::cout << " Number of entries in table of contents: " << dysymtab.ntoc << "\n";
        std::cout << " File offset to module table: " << dysymtab.modtaboff << "\n";
        std::cout << " Number of module table entries: " << dysymtab.nmodtab << "\n";
        std::cout << " File offset to reference symbol table: " << dysymtab.extrefsymoff << "\n";
        std::cout << " Number of entries in reference symbol table: " << dysymtab.nextrefsyms << "\n";
        std::cout << " File offset to indirect symbol table: " << dysymtab.indirectsymoff << "\n";
        std::cout << " Number of entries in indirect symbol table: " << dysymtab.nindirectsyms << "\n";
        std::cout << " File offset to external relocation entries: " << dysymtab.extreloff << "\n";
        std::cout << " Number of external relocation entries: " << dysymtab.nextrel << "\n";
        std::cout << " File offset to local relocation entries: " << dysymtab.locreloff << "\n";
        std::cout << " Number of local relocation entries: " << dysymtab.nlocrel << "\n";
    }

    void Analyzer::analyzeObfuscation(const std::string &file)
    {
        std::ifstream fileStream(file, std::ios::binary);
        if (!fileStream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            exit(EXIT_FAILURE);
        }

        // NOTE: Step 1 Check for Stripped Symbols
        auto symbols = extractSymbolTable(file);
        if (symbols.empty())
            std::cout << "[!] Warning: Symbols are stripped, possible obfuscation detected.\n";

        // NOTE Step 2 Detect Mangled or Obfuscated Symbols
        std::regex mangledPattern("_Z[0-9A-Za-z_]+$");
        for (const auto &symbol : symbols)
        {
            if (std::regex_match(symbol, mangledPattern))
            {
                std::cout << "[!] Obfuscated symbol detected: " << symbol << "\n";
            }
        }

        // NOTE: Step 3 Detect Hidden Functions
        std::vector<std::string> disassembly = {/* TODO: Call a disassembly function */};
        for (const auto &instruction : disassembly)
        {
            if (isIndirectCall(instruction))
            {
                std::cout << "[!] Potential obfuscation: Indirect call detected at " << instruction << "\n";
            }
        }

        // NOTE: Step 4 Detect Excessive Jump Instructions
        int jumpCount = countJumpInstructions(disassembly);
        if (jumpCount > 50)
        {
            std::cout << "[!] Warning: Unusual number of jump instructions detected.\n";
        }

        // Step 5: Identify Packed or Encrypted Sections
        std::vector<std::string> segments = {/* Extract segment information */};
        for (const auto &segment : segments)
        {
            if (isSuspiciousSegment(segment))
            {
                std::cout << "[!] Potential packing or encryption detected in segment: " << segment << "\n";
            }
        }

        // Step 6: Scan for Dynamic API Resolution
        std::vector<std::string> dylibFunctions = extractDylibFunctions(file);
        for (const auto &function : dylibFunctions)
        {
            if (function == "dlopen" || function == "dlsym" || function == "objc_msgSend")
            {
                std::cout << "[!] Suspicious dynamic API resolution detected: " << function << "\n";
            }
        }

        // Step 7: Analyze String Table for Encrypted Strings
        std::vector<std::string> strings = extractStrings(file);
        if (missingCommonStrings(strings))
        {
            std::cout << "[!] Potential encrypted strings detected.\n";
        }

        std::cout << "[+] Obfuscation analysis completed.\n";
    }

    std::vector<std::string> Analyzer::extractSymbolTable(const std::string &file)
    {
        std::ifstream fileStream(file, std::ios::binary);
        if (fileStream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            exit(EXIT_FAILURE);
        }
        symtab_command symtab;
        fileStream.read(reinterpret_cast<char *>(&symtab), sizeof(symtab));

        std::vector<std::string> symbols;
        for (int i = 0; i < symtab.nsyms; i++)
        {
            nlist_64 symbol;
            fileStream.read(reinterpret_cast<char *>(&symbol), sizeof(symbol));
            symbols.push_back(std::to_string(symbol.n_un.n_strx));
        }
        return symbols;
    }

    void Analyzer::analyzeHexDump(const std::string &file) {}
    bool Analyzer::isIndirectCall(const std::string &instruction) {}
    int Analyzer::countJumpInstructions(const std::vector<std::string> &disassembly) {}
    bool Analyzer::isSuspiciousSegment(const std::string &segment) {}
    std::vector<std::string> Analyzer::extractDylibFunctions(const std::string &file) {}
    std::vector<std::string> Analyzer::extractStrings(const std::string &file) {}
    bool Analyzer::missingCommonStrings(const std::vector<std::string> &strings) {}

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

} // namespace machXplorer
