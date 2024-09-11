#ifndef __FCP_ACTION_H__
#define __FCP_ACTION_H__

#include "FCPConsumer.h"
#include "FCPCallbacks.h"

class FCPAction : public clang::ASTFrontendAction {
public:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile) override {
        
        IncludeDirectives.clear();

        // Suppress the error related to 'AutoGen.h' file
        Compiler.getDiagnostics().setSuppressAllDiagnostics(true);

        Compiler.getPreprocessor().addPPCallbacks(std::make_unique<FCPCallbacks>(Compiler.getSourceManager(), &Compiler.getASTContext()));

        return std::unique_ptr<clang::ASTConsumer>(
            new FCPConsumer(&Compiler.getASTContext()));
    }
};

#endif