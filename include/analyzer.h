#pragma once

#include <iostream>
#include <fstream>
#include <mach-o/loader.h>

namespace machXplorer
{

    class Analyzer
    {
    public:
        enum class AnalysisType
        {
            HEADER,
            SEGMENT,
            SYMBOL,
            DISASSEMBLY,
            OBFUSCATION,
            HEX,
            COMPARE,
            HELP,
            INVALID
        };
        void printHelpMenu(char **argv);
        AnalysisType setAnalysisType(char **argv);
        void processCLArguments(int argc, char **argv);
        void compareMachOBinaries(const std::string &file1,
                                  const std::string &file2);
        void analyzeMachOBinary(const std::string &file,
                                const std::string &file2 = "",
                                const AnalysisType type = AnalysisType::INVALID);

    private:
        void analyzeHeader(const std::string &file);
        void analyzeSegment(const std::string &file);
        void analyzeSection(const std::string &file);
        void analyzeSymbol(const std::string &file);
        void analyzeDisassembly(const std::string &file);
        void analyzeObfuscation(const std::string &file);
        void analyzeHexDump(const std::string &file);

        // Functions to print the Mach-O header information
        void printSectionInfo(const section_64 *section64);
        void printHeaderInfo(const mach_header_64 *header64);
        void printSegmentInfo(const segment_command_64 *segment64);
        void printSymbolInfo(const symtab_command &symtab64);
        void printDisassemblyInfo(const dysymtab_command &dysymtab);
    };

} // namespace machXplorer