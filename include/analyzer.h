#pragma once

#include <iostream>
#include <fstream>
#include <mach-o/loader.h>

enum class AnalysisType
{
    HEADER,
    SEGMENT,
    SYMBOL,
    DISASSEMBLY,
    OBFUSCATION,
    HEX,
    COMPARE,
    HELP
};

class Analyzer
{
public:
    void printHelpMenu(char **argv);
    void processCLArguments(int argc, char **argv);
    void compareMachOBinaries(std::string file1, std::string file2);    
};