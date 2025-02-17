#include "analyzer.h"

namespace machXplorer
{
    std::ifstream Analyzer::openFileStream(const std::string &file)
    {
        std::ifstream fileStream(file, std::ios::binary);
        if (!fileStream.is_open())
        {
            std::cerr << "[-] Error: Unable to open file.\n";
            throw std::runtime_error("Error: Unable to open file.");
        }
        return fileStream;
    } // !Analyzer::openFileStream

    void Analyzer::printHelpMenu(char **argv)
    {
        static const std::vector<std::pair<std::string, std::string>> helpOptions = {
            {"-h, --header", "Analyze Mach-O header"},
            {"-s, --segment", "Analyze Mach-O segments"},
            {"-y, --symbol", "Analyze Mach-O symbols"},
            {"-d, --disassembly", "Analyze Mach-O disassembly"},
            {"-o, --obfuscation", "Analyze Mach-O obfuscation"},
            {"-x, --hex", "Analyze Mach-O hex dump"},
            {"-c, --compare", "Compare two Mach-O binaries"},
            {"--help", "Display this help menu"}};

        std::cout << "Usage: " << argv[0] << " <option> <file> [additional file for comparison]\n";
        std::cout << "Options:\n";

        for (const auto &option : helpOptions)
        {
            std::cout << "  " << option.first << "   " << option.second << "\n";
        }
    } // !Analyzer::printHelpMenu

    void Analyzer::processCLArguments(int argc, char **argv)
    {
        if (argc < 3) // Ensure enough arguments are provided
        {
            if (argc == 2 && std::string(argv[1]) == "--help")
            {
                printHelpMenu(argv);
                exit(EXIT_SUCCESS);
            }
            std::cerr << "\n[-] Error: Insufficient arguments provided.\n\n";
            printHelpMenu(argv);
            exit(EXIT_FAILURE);
        }

        // Get the analysis type from arguments
        AnalysisType type = setAnalysisType(argv);

        if (type == AnalysisType::INVALID)
        {
            std::cerr << "[-] Error: Invalid option provided.\n";
            printHelpMenu(argv);
            exit(EXIT_FAILURE);
        }

        // Define a lookup table for required argument counts
        static const std::unordered_map<AnalysisType, int> requiredArgs = {
            {AnalysisType::COMPARE, 4}, // Compare requires 2 files
            {AnalysisType::HELP, 2},    // Help needs just the command
            {AnalysisType::HEADER, 3},
            {AnalysisType::SEGMENT, 3},
            {AnalysisType::SYMBOL, 3},
            {AnalysisType::DISASSEMBLY, 3},
            {AnalysisType::OBFUSCATION, 3},
            {AnalysisType::HEX, 3}};

        // Validate argument count dynamically
        if (argc < requiredArgs.at(type))
        {
            std::cerr << "[-] Error: Insufficient arguments for " << argv[1] << ".\n";
            printHelpMenu(argv);
            exit(EXIT_FAILURE);
        }

        // Handle different operations
        std::string file1 = argv[2];
        std::string file2 = (type == AnalysisType::COMPARE) ? argv[3] : "";

        if (type == AnalysisType::HELP)
        {
            printHelpMenu(argv);
            exit(EXIT_SUCCESS);
        }

        analyzeMachOBinary(file1, file2, type);
    }

    Analyzer::AnalysisType Analyzer::setAnalysisType(char **argv)
    {
        // NOTE: If argv[1] is nullptr, it’s fine.
        // But if argv[1] is an empty string (""),
        // std::string(argv[1]) will be empty and still pass the check.
        if (!argv[1] || std::strlen(argv[1]) == 0)
            return AnalysisType::INVALID;

        static const std::unordered_map<std::string, AnalysisType> optionMap = {
            {"-h", AnalysisType::HEADER},
            {"--header", AnalysisType::HEADER},
            {"-s", AnalysisType::SEGMENT},
            {"--segment", AnalysisType::SEGMENT},
            {"-y", AnalysisType::SYMBOL},
            {"--symbol", AnalysisType::SYMBOL},
            {"-d", AnalysisType::DISASSEMBLY},
            {"--disassembly", AnalysisType::DISASSEMBLY},
            {"-o", AnalysisType::OBFUSCATION},
            {"--obfuscation", AnalysisType::OBFUSCATION},
            {"-x", AnalysisType::HEX},
            {"--hex", AnalysisType::HEX},
            {"-c", AnalysisType::COMPARE},
            {"--compare", AnalysisType::COMPARE},
            {"--help", AnalysisType::HELP}};

        const std::string option(argv[1]);
        auto it = optionMap.find(option);
        return (it != optionMap.end()) ? it->second : AnalysisType::INVALID;
    } // !Analyzer::setAnalysisType

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
            // NOTE: printHelpMenu() already called!
            // keep here to turn off Compiler warning
            break;
        case AnalysisType::INVALID:
            std::cerr << "[-] Error: Invalid option provided.\n";
            break;
        }
    } // !Analyzer::analyzeMachOBinary

    /***
     * Analyze the header of a Mach-O binary file.
     * This function extracts and displays the Mach-O headers,
     * load commands, and entry points.
     * @param file The Mach-O binary file to analyze.
     * @return void
     ***/
    void Analyzer::analyzeHeader(const std::string &file)
    {
        if (!isMachO(file))
        {
            std::cerr << "[-] Error: Invalid Mach-O file provided.\n";
            throw std::runtime_error("Error: Invalid Mach-O file provided.");
        }

        auto fileStream = openFileStream(file);

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
    } // !Analyzer::analyzeHeader

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
    } // !Analyzer::printHeaderInfo

    void Analyzer::analyzeSegment(const std::string &file)
    {
        if (!isMachO(file))
        {
            std::cerr << "[-] Error: Invalid Mach-O file provided.\n";
            throw std::runtime_error("Error: Invalid Mach-O file provided.");
        }

        auto fileStream = openFileStream(file);

        mach_header_64 header;
        fileStream.read(reinterpret_cast<char *>(&header), sizeof(header));

        for (uint32_t i = 0; i < header.ncmds; i++)
        {
            load_command loadCmd;
            fileStream.read(reinterpret_cast<char *>(&loadCmd), sizeof(loadCmd));

            if (loadCmd.cmd == LC_SEGMENT_64)
            {
                segment_command_64 segment;
                fileStream.read(reinterpret_cast<char *>(&segment), sizeof(segment));
                printSegmentInfo(&segment);
            }
            else
            {
                // Skip unknown load commands
                fileStream.seekg(loadCmd.cmdsize - sizeof(loadCmd), std::ios::cur);
            }
        }

        fileStream.close();
    } // !Analyzer::analyzeSegment

    void Analyzer::printSegmentInfo(const segment_command_64 *segment64)
    {
        if (!segment64)
        {
            std::cerr << "[-] Error: Invalid segment pointer.\n";
            return;
        }

        // **Debug: Print the load command type**
        std::cout << "[DEBUG] Load Command Type: 0x" << std::hex << segment64->cmd << std::dec << "\n";

        // **Fix segment name extraction**
        char segname[17] = {0};                       // Allocate 16 bytes + null terminator
        std::memcpy(segname, segment64->segname, 16); // Copy raw bytes safely

        // **Ensure segment name is printable**
        for (int i = 0; i < 16; i++)
        {
            if (!isprint(segname[i]) && segname[i] != '\0')
            {
                std::cerr << "[-] Error: Segment name contains non-printable characters.\n";
                return;
            }
        }

        std::cout << "[+] Segment Information:\n";
        std::cout << "  Segment Name:        " << segname << "\n";
        std::cout << "  VM Address:          0x" << std::hex << segment64->vmaddr << std::dec << "\n";
        std::cout << "  VM Size:             " << segment64->vmsize << " bytes\n";
        std::cout << "  File Offset:         0x" << std::hex << segment64->fileoff << std::dec << "\n";
        std::cout << "  File Size:           " << segment64->filesize << " bytes\n";
        std::cout << "  Max VM Protection:   " << formatProtectionFlags(segment64->maxprot) << "\n";
        std::cout << "  Init VM Protection:  " << formatProtectionFlags(segment64->initprot) << "\n";
        std::cout << "  Number of Sections:  " << segment64->nsects << "\n";
        std::cout << "  Flags:               " << std::bitset<32>(segment64->flags) << " (binary)\n";
    } // !Analyzer::printSegmentInfo

    // Helper function to format VM protection flags
    std::string Analyzer::formatProtectionFlags(int prot)
    {
        std::string result;
        if (prot & VM_PROT_READ)
            result += "READ ";
        if (prot & VM_PROT_WRITE)
            result += "WRITE ";
        if (prot & VM_PROT_EXECUTE)
            result += "EXECUTE ";
        return result.empty() ? "NONE" : result;
    }

    void Analyzer::analyzeSection(const std::string &file)
    {
        if (!isMachO(file))
        {
            std::cerr << "[-] Error: Invalid Mach-O file provided.\n";
            throw std::runtime_error("Error: Invalid Mach-O file provided.");
        }
        auto fileStream = openFileStream(file);

        section_64 *section64;
        fileStream.read(reinterpret_cast<char *>(&section64), sizeof(section64));

        printSectionInfo(section64);

        fileStream.close();
    } // !Analyzer::analyzeSection

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
    } // !Analyzer::printSectionInfo

    void Analyzer::analyzeSymbol(const std::string &file)
    {
        if (!isMachO(file))
        {
            std::cerr << "[-] Error: Invalid Mach-O file provided.\n";
            throw std::runtime_error("Error: Invalid Mach-O file provided.");
        }

        auto fileStream = openFileStream(file);

        symtab_command symtab;
        fileStream.read(reinterpret_cast<char *>(&symtab), sizeof(symtab));

        printSymbolInfo(symtab);
        fileStream.close();
    } // !Analyzer::analyzeSymbol

    void Analyzer::printSymbolInfo(const symtab_command &symtab64)
    {
        std::cout << "[+] Symbol Information:\n";
        std::cout << "  Symbol Table Offset: " << symtab64.symoff << "\n";
        std::cout << "  Number of Symbols: " << symtab64.nsyms << "\n";
        std::cout << "  String Table Offset: " << symtab64.stroff << "\n";
        std::cout << "  String Table Size: " << symtab64.strsize << "\n";
    } // !Analyzer::printSymbolInfo

    void Analyzer::analyzeDisassembly(const std::string &file)
    {
        if (!isMachO(file))
        {
            std::cerr << "[-] Error: Invalid Mach-O file provided.\n";
            throw std::runtime_error("Error: Invalid Mach-O file provided.");
        }
        auto fileStream = openFileStream(file);

        dysymtab_command dysymtab;
        fileStream.read(reinterpret_cast<char *>(&dysymtab), sizeof(dysymtab));
        printDisassemblyInfo(dysymtab);

        fileStream.close();
    } // !Analyzer::analyzeDisassembly

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
    } // !Analyzer::printDisassemblyInfo

    void Analyzer::analyzeObfuscation(const std::string &file)
    {
        if (!isMachO(file))
        {
            std::cerr << "[-] Error: Invalid Mach-O file provided.\n";
            throw std::runtime_error("Error: Invalid Mach-O file provided.");
        }

        auto fileStream = openFileStream(file);
        std::cout << "[+] Starting obfuscation analysis...\n";

        // **Step 1: Run all obfuscation checks**
        std::vector<std::pair<std::string, bool>> checks = {
            {"Symbols are stripped", checkStrippedSymbols(file)},
            {"Mangled symbols detected", checkMangledSymbols(file)},
            {"Excessive indirect calls", checkIndirectCalls(file)},
            {"Unusual number of jump instructions", checkJumpInstructions(file)},
            {"High-entropy sections (possible packing/encryption)", checkPackedSections(file)},
            {"Suspicious dynamic API resolution", checkDynamicAPIUsage(file)},
            {"High-entropy strings detected (possible string obfuscation)", checkObfuscatedStrings(file)}};

        // **Step 2: Print Results**
        bool detected = false;
        for (const auto &[description, found] : checks)
        {
            if (found)
            {
                std::cout << "[!] " << description << "\n";
                detected = true;
            }
        }

        if (!detected)
            std::cout << "[+] No significant obfuscation detected.\n";

        std::cout << "[+] Obfuscation analysis completed.\n";
    } // !Analyzer::analyzeObfuscation

    bool Analyzer::checkStrippedSymbols(const std::string &file)
    {
        auto symbols = extractSymbolTable(file);
        return symbols.empty();
    } // !Analyzer::checkStrippedSymbols

    bool Analyzer::checkMangledSymbols(const std::string &file)
    {
        auto symbols = extractSymbolTable(file);
        std::regex mangledPattern("_Z[0-9A-Za-z_]+$"); // C++ Itanium ABI Mangled Names
        int count = 0;

        for (const auto &symbol : symbols)
        {
            if (std::regex_match(symbol, mangledPattern))
                count++;
        }

        return count > 5; // Threshold to avoid false positives
    } // !Analyzer::checkMangledSymbols

    bool Analyzer::checkIndirectCalls(const std::string &file)
    {
        auto disassembly = disassembleMachOFile(file);
        int count = 0;

        for (const auto &instruction : disassembly)
        {
            if (isIndirectCall(instruction))
                count++;
        }

        return count > 10; // Threshold for suspicious activity
    } // !Analyzer::checkIndirectCalls

    bool Analyzer::checkJumpInstructions(const std::string &file)
    {
        auto disassembly = disassembleMachOFile(file);
        int jumpCount = countJumpInstructions(disassembly);
        return jumpCount > 100; // Threshold to detect junk code
    } // !Analyzer::checkJumpInstructions

    bool Analyzer::checkPackedSections(const std::string &file)
    {
        auto segments = extractSegmentInfo(file);

        for (const auto &segment : segments)
        {
            if (calculateEntropy(segment.data) > 7.5) // High entropy threshold
                return true;
        }

        return false;
    } // !Analyzer::checkPackedSections

    bool Analyzer::checkDynamicAPIUsage(const std::string &file)
    {
        std::vector<std::string> dylibFunctions = extractDylibFunctions(file);

        static const std::unordered_set<std::string> suspiciousFunctions = {
            "dlopen", "dlsym", "objc_msgSend"};

        for (const auto &function : dylibFunctions)
        {
            if (suspiciousFunctions.count(function))
                return true;
        }

        return false;
    } // !Analyzer::checkDynamicAPIUsage

    bool Analyzer::checkObfuscatedStrings(const std::string &file)
    {
        auto strings = extractStrings(file);
        int highEntropyStrings = 0;

        for (const auto &str : strings)
        {
            if (calculateEntropy(std::vector<uint8_t>(str.begin(), str.end())) > 7.0)
                highEntropyStrings++;
        }

        return highEntropyStrings > 10; // Threshold for detecting obfuscated strings
    } // !Analyzer::checkObfuscatedStrings

    std::vector<std::string> Analyzer::extractSymbolTable(const std::string &file)
    {
        auto fileStream = openFileStream(file);

        mach_header_64 header;
        fileStream.read(reinterpret_cast<char *>(&header), sizeof(header));

        std::vector<std::string> symbols;
        uint32_t strOffset = 0;

        for (uint32_t i = 0; i < header.ncmds; i++)
        {
            load_command loadCmd;
            fileStream.read(reinterpret_cast<char *>(&loadCmd), sizeof(loadCmd));

            if (loadCmd.cmd == LC_SYMTAB)
            {
                symtab_command symtab;
                fileStream.read(reinterpret_cast<char *>(&symtab), sizeof(symtab));

                strOffset = symtab.stroff;
                fileStream.seekg(symtab.symoff, std::ios::beg);

                for (uint32_t j = 0; j < symtab.nsyms; j++)
                {
                    nlist_64 symbol;
                    fileStream.read(reinterpret_cast<char *>(&symbol), sizeof(symbol));

                    fileStream.seekg(strOffset + symbol.n_un.n_strx, std::ios::beg);
                    std::string symbolName;
                    std::getline(fileStream, symbolName, '\0');
                    symbols.push_back(symbolName);
                }
            }
        }

        return symbols;
    } // !Analyzer::extractSymbolTable

    bool Analyzer::isIndirectCall(const std::string &instruction)
    {
        return instruction.find("call") != std::string::npos && instruction.find("[") != std::string::npos;
    } // !Analyzer::isIndirectCall

    std::vector<std::string> Analyzer::disassembleMachOFile(const std::string &file)
    {
        if (!isMachO(file))
        {
            std::cerr << "[-] Error: Invalid Mach-O file provided.\n";
            throw std::runtime_error("Error: Invalid Mach-O file provided.");
        }

        std::cout << "[+] Disassembling Mach-O file: " << file << std::endl;
        auto fileStream = openFileStream(file);

        // NOTE: Read the Mach-O header
        mach_header_64 header64;
        fileStream.read(reinterpret_cast<char *>(&header64), sizeof(header64));

        auto loadCommands = header64.ncmds;
        std::vector<std::string> instructions{};

        for (int i = 0; i < loadCommands; i++)
        {
            load_command command;
            fileStream.read(reinterpret_cast<char *>(&command), sizeof(command)); // Read the load command

            if (command.cmd == LC_SEGMENT_64)
            {
                // NOTE: Read the Mach-O __TEXT Segment
                segment_command_64 segment64;
                fileStream.read(reinterpret_cast<char *>(&segment64), sizeof(segment64));

                for (uint32_t i = 0; i < header64.ncmds; i++)
                {
                    load_command loadCmd;
                    fileStream.read(reinterpret_cast<char *>(&loadCmd), sizeof(loadCmd));

                    if (loadCmd.cmd == LC_SEGMENT_64)
                    {
                        segment_command_64 segment;
                        fileStream.read(reinterpret_cast<char *>(&segment), sizeof(segment));

                        for (uint32_t j = 0; j < segment.nsects; j++)
                        {
                            section_64 section;
                            fileStream.read(reinterpret_cast<char *>(&section), sizeof(section));

                            if (section.flags & S_ATTR_PURE_INSTRUCTIONS)
                            {
                                auto disassembledInstructions = disassembleSection(file, section.offset, section.size, header64.cputype);
                                instructions.insert(instructions.end(), disassembledInstructions.begin(), disassembledInstructions.end());
                            }
                        }
                    }
                    else
                    {
                        // Skip unknown load commands
                        fileStream.seekg(loadCmd.cmdsize - sizeof(loadCmd), std::ios::cur);
                    }
                }
            }
        }

        fileStream.close();

        std::cout << "[+] Disassembled Instructions:" << std::endl;
        for (const auto &instruction : instructions)
        {
            std::cout << instruction << std::endl;
        }

        EXIT_SUCCESS;
        return instructions;
    } // !Analyzer::disassembleMachOFile

    int Analyzer::countJumpInstructions(const std::vector<std::string> &disassembly)
    {
        int count = 0;
        for (const auto &instruction : disassembly)
        {
            if (instruction.find("jmp") != std::string::npos)
                count++;
        }
        return count;
    } // !Analyzer::countJumpInstructions

    std::vector<Analyzer::SegmentInfo> Analyzer::extractSegmentInfo(const std::string &file)
    {
        // NOTE: Dummy implementation: Simulated segments
        return {{"__TEXT", {0x55, 0x48, 0x89, 0xe5}}, {"__DATA", {0xff, 0xff, 0xaa, 0xaa}}};
    }

    double Analyzer::calculateEntropy(const std::vector<uint8_t> &data)
    {
        std::unordered_map<uint8_t, int> freq;
        for (uint8_t byte : data)
        {
            freq[byte]++;
        }

        double entropy = 0.0;
        for (const auto &[byte, count] : freq)
        {
            double p = static_cast<double>(count) / data.size();
            entropy -= p * std::log2(p);
        }
        return entropy;
    } // !Analyzer::calculateEntropy

    bool Analyzer::isSuspiciousSegment(const SegmentInfo &segment)
    {
        return calculateEntropy(segment.data) > 7.5;
    } // !Analyzer::isSuspiciousSegment

    // Dynamic API Resolution Detection**
    std::vector<std::string> Analyzer::extractDylibFunctions(const std::string &file)
    {
        // NOTE: Dummy implementation
        return {"dlopen", "dlsym", "objc_msgSend"};
    } // !Analyzer::extractDylibFunctions

    std::vector<std::string> Analyzer::extractStrings(const std::string &file)
    {
        // NOTE: Dummy implementation: Simulated extracted strings
        return {"Hello", "Password123", "\x89\xAB\xCD\xEF"};
    } // !Analyzer::extractStrings

    bool Analyzer::missingCommonStrings(const std::vector<std::string> &strings)
    {
        std::unordered_set<std::string> commonStrings = {"main", "printf", "exit", "malloc"};
        for (const auto &str : strings)
        {
            if (commonStrings.find(str) != commonStrings.end())
            {
                return false; // Found at least one common string
            }
        }
        return true;
    } // !Analyzer::missingCommonStrings

    // Logging & Reporting**
    void Analyzer::printWarning(const std::string &message)
    {
        std::cout << "[!] " << message << std::endl;
    } // !Analyzer::printWarning

    std::vector<std::string> Analyzer ::disassembleSection(const std::string &file,
                                                           uint64_t offset, uint64_t size, cpu_type_t cpuType)
    {
        std::ifstream binary(file, std::ios::binary);

        // Read the __TEXT.__text section bytes
        binary.seekg(offset, std::ios::beg);
        std::vector<uint8_t> code(size);
        binary.read(reinterpret_cast<char *>(code.data()), size);
        binary.close();

        // Initialize Capstone disassembler
        csh handle;
        cs_insn *insn;
        size_t count;

        cs_arch arch;
        cs_mode mode;

        // Detect architecture type
        if (cpuType == CPU_TYPE_ARM64)
        {
            arch = CS_ARCH_ARM64;
            mode = CS_MODE_LITTLE_ENDIAN;
        }
        else if (cpuType == CPU_TYPE_X86_64)
        {
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
        }
        else
        {
            std::cerr << "[-] Error: Unsupported architecture." << std::endl;
            return {};
        }

        if (cs_open(arch, mode, &handle) != CS_ERR_OK)
        {
            std::cerr << "[-] Error: Failed to initialize Capstone." << std::endl;
            return {};
        }

        std::vector<std::string> disassembledInstructions;
        count = cs_disasm(handle, code.data(), code.size(), offset, 0, &insn);
        if (count > 0)
        {
            for (size_t i = 0; i < count; i++)
            {
                std::ostringstream oss;
                oss << "0x" << std::hex << insn[i].address << ": " << insn[i].mnemonic << " " << insn[i].op_str;
                disassembledInstructions.push_back(oss.str());
            }
            cs_free(insn, count);
        }
        else
        {
            std::cerr << "[-] Error: Failed to disassemble the section." << std::endl;
        }

        cs_close(&handle);
        return disassembledInstructions;
    } // !Analyzer::disassembleSection

    void Analyzer::analyzeHexDump(const std::string &file)
    {
        // TODO: Implementation for hex dump analysis
    } // !Analyzer::analyzeHexDump

    void Analyzer::compareMachOBinaries(const std::string &file1, const std::string &file2)
    {
        if (!(isMachO(file1) && isMachO(file2)))
        {
            std::cerr << "[-] Error: Invalid file(s) provided.\n";
            throw std::runtime_error("Error: Invalid file(s) provided.");
        }

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
    } // !Analyzer::compareMachOBinaries

    bool Analyzer::isMachO(const std::string &filePath)
    {
        std::ifstream fileStream = openFileStream(filePath);

        uint32_t magic;
        fileStream.read(reinterpret_cast<char *>(&magic), sizeof(magic));

        fileStream.close();

        // Handle byte order correctly
        uint32_t swappedMagic = __builtin_bswap32(magic);
        return magic == MH_MAGIC || magic == MH_MAGIC_64 ||
               swappedMagic == FAT_MAGIC || swappedMagic == FAT_MAGIC_64;
    } // !Analyzer::isMachO

} // !namespace machXplorer
