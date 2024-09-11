#ifndef __FUNCTIONDECLANALYSIS_H__
#define __FUNCTIONDECLANALYSIS_H__

#include "PassHelpers.h"
#include "clang/AST/DeclBase.h"

class FunctionDeclAnalysis : public RecursiveASTVisitor<FunctionDeclAnalysis> {
public:
    explicit FunctionDeclAnalysis(ASTContext *Context)
        : Context(Context) {}

    // Don't add repeat function decl of the same number of args
    bool ContainsFunction(FunctionDecl *FD) {
        for (auto &Func : FunctionDeclMap) {
            if ((Func.FunctionName == FD->getNameAsString()) && Func.Parameters.size() == FD->getNumParams()) {
                return true;
            }
            // check the FunctionAliases map to see if the function is an alias
            for(auto it = FunctionAliases.begin(); it != FunctionAliases.end(); ++it)
            {
                if(it->first == FD->getNameAsString())
                {
                    if(it->second == Func.FunctionName)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    std::string getFunctionName(FunctionDecl *FD) {
        std::string name = FD->getNameAsString();
        for(auto it = FunctionAliases.begin(); it != FunctionAliases.end(); ++it)
        {
            if(it->first == name)
            {
                return it->second;
            }
        }
        return name;
    }

    std::string DetermineDirection(int Param, std::string FuncText) {
        std::vector<std::string> parameters;
        size_t pos = 0;
        size_t found;
        while ((found = FuncText.find(",", pos)) != std::string::npos) {
            parameters.push_back(FuncText.substr(pos, found - pos));
            pos = found + 1;
        }
        // Add the last parameter (no trailing comma)
        parameters.push_back(FuncText.substr(pos));

        if (Param < parameters.size()) {
            std::string param = parameters[Param];
            

            // Now you can analyze 'param' to determine the direction
            // use regular expressions to find "IN" and "OUT" qualifiers in 'param'.
            std::regex paramRegex(R"(\b(IN\s*OUT|OUT\s*IN|IN|OUT)\b\s+[\w_]+\s*\**\s*[\w_]+)");
            if(std::regex_search(param, paramRegex)) {
                std::smatch match;
                std::regex_search(param, match, paramRegex);
                std::string qualifier = match[1].str();
                // Check the matched string
                if (qualifier == "IN"){
                    return "IN";
                }else if (qualifier == "IN OUT" || qualifier == "OUT IN") {
                    return "IN_OUT";
                }else if (qualifier == "OUT") {
                    return "OUT";
                }
            }

        }
        // If nth parameter doesn't exist, return false by default
        return "UNKNOWN";
    }

    bool isProtocol(std::string function_name) {
        if(FunctionInfo.Parameters.empty())
        {
            return false;
        }
        std::string type = FunctionInfo.Parameters.begin()->second.arg_type;
        if(type.empty())
        {
            return false;
        }
        // if(FunctionInfo.Service == "protocol")
        // {
        //     FunctionInfo.Arguments.begin()->second.variable = "__PROTOCOL__";
        //     llvm::outs() << "Protocol: " << function_name << "\n";
        //     return true;
        // }
        // std::string guid;
        // for(auto it = HarnessFunctions.begin(); it != HarnessFunctions.end(); ++it)
        // {
        //     if(it->first == function_name)
        //     {
        //         if(!it->second.empty())
        //         {
        //             guid = it->second;
        //         }
        //     }
        // }
        // if(guid.empty())
        // {
        //     return false;
        // }
        // drop the g and Guid from the string guid
        // guid = guid.substr(1, guid.length() - 5);

        // make sure its all lowercase
        // std::transform(guid.begin(), guid.end(), guid.begin(), ::tolower);
        // guid.erase(std::remove(guid.begin(), guid.end(), '_'), guid.end());

        // remove the all underscores from the data type string
        // type.erase(std::remove(type.begin(), type.end(), '_'), type.end());

        // make sure its all lowercase
        std::transform(type.begin(), type.end(), type.begin(), ::tolower);

        // check if the type contains the guid
        if (type.find('protocol') != std::string::npos) {
            FunctionInfo.Parameters.begin()->second.variable = "__PROTOCOL__";
            return true;
        }

        return false;
    }

    bool isNonProtocol(std::string function_name)
    {
        for(auto it = HarnessFunctions.begin(); it != HarnessFunctions.end(); ++it)
        {
            if(it->first == function_name)
            {
                if(it->second.empty())
                {
                    return true;
                }
            }
        }
        return false;
    }

    void verifyFunctionInfo()
    {
        if(isNonProtocol(FunctionInfo.FunctionName) || isProtocol(FunctionInfo.FunctionName))
        {
            FunctionDeclMap.push_back(FunctionInfo);
        }
    }

    void getFunctionHeaderFile(FunctionDecl *FD, ASTContext &Context) {
        // Get the source range of the function declaration
        SourceRange range = FD->getSourceRange();

        // Get the file path of the header file
        SourceLocation loc = range.getBegin();
        FileID fileID = Context.getSourceManager().getFileID(loc);
        const FileEntry *fileEntry = Context.getSourceManager().getFileEntryForID(fileID);
        if (fileEntry) {
            FunctionInfo.includes.insert(fileEntry->getName().str());
            FunctionInfo.File = fileEntry->getName().str();
        }
    }

    bool VisitFunctionDecl(FunctionDecl *Func) {
        if (FunctionDeclNames.count(Func->getNameAsString()) && !ContainsFunction(Func)) {
            // save the function name if there is no alias, otherwise save the alias
            FunctionInfo.FunctionName = getFunctionName(Func);
            std::string arg_ID = "Arg_";
            for (unsigned i = 0; i < Func->getNumParams(); ++i) {
                Argument arg;
                ParmVarDecl *Param = Func->getParamDecl(i);
                
                SourceManager &SM = Context->getSourceManager();
                const LangOptions &LangOpts = Context->getLangOpts();
                CharSourceRange Range = CharSourceRange::getTokenRange(Func->getSourceRange());
                std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

                arg.arg_type = Param->getType().getAsString();
                arg.variable = Param->getNameAsString();
                // capture the other qualifiers for the argument
                // Need to do it via the lexer
                arg.arg_dir = DetermineDirection(i, ExprText);
                FunctionInfo.Parameters[arg_ID+std::to_string(i)] = arg;
            }
            //return type
            FunctionInfo.return_type = Func->getReturnType().getAsString();
            getFunctionHeaderFile(Func, *Context);
            // FunctionInfo.includes = "protocol";
            verifyFunctionInfo();
            FunctionDeclMap.push_back(FunctionInfo);
            FunctionInfo.clear();
        }
        return true;
    }

private:
    ASTContext *Context;
    Function FunctionInfo;
};

#endif