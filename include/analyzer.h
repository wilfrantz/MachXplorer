#pragma once

#include <iostream>
#include <regex>
#include <string>
#include <cstdlib>
#include <vector>
#include <fstream>
#include <mach-o/nlist.h>
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

        // Helper functions
        std::ifstream openFileStream(const std::string &file);
        std::vector<std::string> disassembleMachOFile(const std::string &file);
        std::vector<std::string> extractSymbolTable(const std::string &file);
        bool isIndirectCall(const std::string &instruction);
        int countJumpInstructions(const std::vector<std::string> &disassembly);
        bool isSuspiciousSegment(const std::string &segment);
        std::vector<std::string> extractDylibFunctions(const std::string &file);
        std::vector<std::string> extractStrings(const std::string &file);
        bool missingCommonStrings(const std::vector<std::string> &strings);


        // Functions to print the Mach-O header information
        void printSectionInfo(const section_64 *section64);
        void printHeaderInfo(const mach_header_64 *header64);
        void printSegmentInfo(const segment_command_64 *segment64);
        void printSymbolInfo(const symtab_command &symtab64);
        void printDisassemblyInfo(const dysymtab_command &dysymtab);
    };

} // namespace machXplorer