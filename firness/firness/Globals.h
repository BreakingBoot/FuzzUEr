#pragma once

#include <iostream>
#include <fstream>
#include <algorithm>
#include <set>
#include <string>
#include <regex>
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ParentMap.h>
#include "clang/AST/ParentMapContext.h"
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include <clang/Basic/SourceManager.h>
#include <sstream>
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/AST/TypeLoc.h"
#include "clang/Lex/Preprocessor.h"
#include <clang/Basic/Diagnostic.h>
#include <clang/Lex/PPCallbacks.h>
#include "clang/Lex/Lexer.h"


using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;


enum class ParameterDirection {
    IN,
    OUT,
    IN_OUT,
    UNKNOWN,
    DIRECT,
    INDIRECT,
    IN_DIRECT
};

struct Argument {
    std::string data_type;
    std::string variable;
    std::string assignment;
    std::vector<std::string> potential_outputs;
    std::string usage;
    std::string arg_dir;
    std::string arg_type;

    Argument() = default;

    // Function to clear the Argument object
    void clear() {
        data_type.clear();
        variable.clear();
        assignment.clear();
        usage.clear();
        arg_dir.clear();
        arg_type.clear();
        potential_outputs.clear();
    }
};

struct Argument_AST {
    Expr* Arg;
    Expr* Assignment;
    int ArgNum;
    ParameterDirection direction;

    Argument_AST() = default;

    void clear() {
        Arg = nullptr;
        Assignment = nullptr;
        ArgNum = 0;
        direction = ParameterDirection::UNKNOWN; 
    }
};

struct FieldInfo {
    std::string Name;
    std::string Type;
    FieldDecl* FieldType;

    FieldInfo() = default;
};

struct TypeData {
    std::string TypeName;
    TypedefDecl* TypeDec = nullptr;
    RecordDecl* record = nullptr;
    std::vector<FieldInfo> Fields;
    std::string File;

    TypeData() = default;
    TypeData(const std::string& typeName, TypedefDecl* typeDec, RecordDecl* rec)
        : TypeName(typeName), TypeDec(typeDec), record(rec) {}
};

struct Call {
    std::string Function;
    std::string Service;
    std::string return_type;
    std::map<std::string, Argument> Arguments;
    std::set<std::string> includes;

    Call() = default;

    // Function to clear the Call object
    void clear() {
        Function.clear();
        Service.clear();
        for (auto& pair : Arguments) {
            pair.second.clear();
        }
        Arguments.clear();
        includes.clear();
        return_type.clear();
    }
};

struct EnumDef {
    std::set<std::string> Constants;
    std::string File;

    EnumDef() = default;
};

struct Function {
    std::string FunctionName;
    std::string alias;
    std::string return_type;
    std::map<std::string, Argument> Parameters;
    std::string File;
    std::set<std::string> includes;

    Function() = default;

    // Function to clear the Call object
    void clear() {
        FunctionName.clear();
        for (auto& pair : Parameters) {
            pair.second.clear();
        }
        Parameters.clear();
        includes.clear();
        File.clear();
        return_type.clear();
    }
};

struct MacroDef {
    std::string Name;
    std::string Value;
    std::string File;

    MacroDef() = default;
};

struct GraphNodeInfo {
    std::string FileName;
    std::string FunctionName;
    unsigned int StartLine;
    unsigned int EndLine;

    GraphNodeInfo() = default;

    bool operator<(const GraphNodeInfo& other) const {
        // if (FileName != other.FileName) {
        //     return FileName < other.FileName;
        // }
        // if (FunctionName != other.FunctionName) {
        //     return FunctionName < other.FunctionName;
        // }
        // if (StartLine != other.StartLine) {
        //     return StartLine < other.StartLine;
        // }
        // return EndLine < other.EndLine;
        return std::tie(FileName, FunctionName, StartLine, EndLine) <
         std::tie(other.FileName, other.FunctionName, other.StartLine, other.EndLine);
    }
};


typedef std::pair<Expr*, ParameterDirection> Assignment;
typedef std::map<VarDecl*, std::vector<Argument_AST>> VarMap;


extern std::map<TypedefDecl*, TypeData> varTypeInfo;
extern std::map<RecordDecl*, TypeData> varRecordInfo;

extern std::set<std::string> FunctionNames;
extern std::set<std::string> FunctionDeclNames;
extern std::set<std::string> GeneratorDeclNames;
extern std::set<std::pair<std::string, std::string>> HarnessFunctions;
extern std::set<std::pair<std::string, std::string>> FunctionAliases;
extern std::set<std::pair<std::string, std::string>> SingleTypedefs;
extern std::map<VarDecl*, std::stack<Assignment>> VarAssignments;
extern std::map<MemberExpr*, std::stack<Assignment>> MemAssignments;
extern std::set<std::string> FunctionTypes;

extern std::map<std::string, std::set<std::string>> TotalDebugMap;
extern std::map<std::string, std::set<std::string>> CallGraphMap;
extern std::set<GraphNodeInfo> FunctionLineMap;

extern std::map<std::string, std::string> DebugMap;
extern std::map<std::string, std::set<std::string>> Aliases;

extern std::map<std::string, TypeData> FinalTypes;
extern std::map<CallExpr*, VarMap> CallExprMap;
extern std::map<CallExpr*, std::map<Expr*, ParameterDirection>> CallArgMap;
extern std::vector<Call> CallMap;
extern std::map<std::string, MacroDef> PreDefinedConstants;
extern std::set<std::string> IncludeDirectives;
extern std::vector<std::string> EnumConstants;
extern std::map<std::string, EnumDef> EnumMap;
extern std::map<CallExpr*, VarMap> GeneratorFunctionsMap;
extern std::vector<Call> GeneratorMap;
extern std::set<std::string> GeneratorTypes;
extern std::vector<Function> FunctionDeclMap;
extern std::vector<Function> GeneratorDeclMap;
extern std::map<std::string, std::set<std::string>> CastMap;
extern std::map<std::string, std::set<std::string>> IncludesDependencyGraph;
