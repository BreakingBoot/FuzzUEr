#ifndef __FCP_CONSUMER_H__
#define __FCP_CONSUMER_H__

#include "VariableFlow.h"
#include "GeneratorAnalysis.h"
#include "CallSiteAnalysis.h"
#include "FileOperationHelpers.h"
#include "FunctionDeclAnalysis.h"
#include "GeneratorDeclAnalysis.h"
#include "CallGraph.h"

class FCPConsumer : public clang::ASTConsumer {
public:
    explicit FCPConsumer(ASTContext *Context)
        : VariableVisitor(Context), FunctionVisitor(Context), GeneratorVisitor(Context), CallVisitor(Context), CallGraphVisitor(Context), GeneratorDeclVisitor(Context) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        // add another pass specific to getting all of the protocol functions from just the protocol type
        VariableVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        FunctionVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        GeneratorVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        GeneratorDeclVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        CallVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        CallGraphVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        CallArgMap.clear();
    }
private:
    VariableFlow VariableVisitor;
    CallSiteAnalysis CallVisitor;
    CallGraph CallGraphVisitor;
    GeneratorAnalysis GeneratorVisitor;
    FunctionDeclAnalysis FunctionVisitor;
    GeneratorDeclAnalysis GeneratorDeclVisitor;
};

#endif 