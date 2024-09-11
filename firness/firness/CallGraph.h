#ifndef __CALLGRAPH_H__
#define __CALLGRAPH_H__

#include "PassHelpers.h"

using namespace PassHelpers;

class CallGraph : public RecursiveASTVisitor<CallGraph> {
public:
    explicit CallGraph(ASTContext *Context)
        : Context(Context) {}

    // Function to calculate the similarity between two strings
    double similarity(const std::string& s1, const std::string& s2) {
        size_t len1 = s1.size(), len2 = s2.size();
        // Check if s2 ends with the pattern '__attribute__((ms_abi))'
        std::string pattern = "__attribute__((ms_abi))";
        if (s2.size() >= pattern.size()) {
            // Ignore the pattern by reducing the length of s2
            if(s2.substr(s2.size() - pattern.size()) == pattern)
                len2 -= pattern.size();
        }
        if (s1.size() >= pattern.size()) {
            // Ignore the pattern by reducing the length of s2
            if(s1.substr(s1.size() - pattern.size()) == pattern)
                len1 -= pattern.size();
        }

        const size_t maxlen = std::max(len1, len2);
        size_t common_chars = 0;

        for (size_t i = 0, j = 0; i < len1 && j < len2; ++i, ++j) {
            if (std::tolower(s1[i]) == std::tolower(s2[j])) {
                ++common_chars;
            }
        }

        return static_cast<double>(common_chars) / maxlen;
    }

    // Function to check if two strings are 80% similar
    bool fuzzyMatch(const std::string& s1, const std::string& s2) {
        return similarity(s1, s2) >= 0.8;
    }
    bool matchType(const std::string& type) {
        for(auto& functionType : TotalDebugMap) {
            if(fuzzyMatch(type, functionType.first)) {
                return true;
            }
        }
        return false;
    }

    std::string getFuzzyMatch(std::string type) {
        // go through the DebugMap and find the key that is 80% similar
        for(auto& function : TotalDebugMap) {
            if(fuzzyMatch(type, function.first)) {
                return function.first;
            }
        }
        return type;
    }

    std::set<std::string> getFuzzySet(std::string type) {
        // go through the DebugMap and find the key that is 80% similar
        for(auto& function : TotalDebugMap) {
            if(fuzzyMatch(type, function.first)) {
                return function.second;
            }
        }
        return {};
    }

    // bool VisitInitListExpr(InitListExpr *ILE)
    // {
    //     for (auto Expr : ILE->inits()) {
    //         // get the initializer only if it is a FunctionToPointerDecay
    //         if(auto *ICE = dyn_cast<ImplicitCastExpr>(Expr))
    //         {
    //             if(ICE->getCastKind() == CK_FunctionToPointerDecay)
    //             {
    //                 if(DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Expr->IgnoreImpCasts()))
    //                 {  
    //                     if(matchType(DRE->getType().getAsString()))
    //                     {
    //                         TotalDebugMap[getFuzzyMatch(DRE->getType().getAsString())].insert(DRE->getNameInfo().getAsString());
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     return true;
    // }

    // /*

    // */
    // bool VisitRecordDecl(RecordDecl *RD) {
    //     for (auto field : RD->fields()) {
    //         if(field->getType()->isFunctionPointerType())
    //         {
    //             QualType QT = field->getType();
    //             if (QT->isPointerType()) {
    //                 QT = QT->getPointeeType();
    //             }
    //             while (auto *TDT = dyn_cast<TypedefType>(QT)) {
    //                 QT = TDT->getDecl()->getUnderlyingType();
    //             }

    //             TotalDebugMap[QT.getAsString()].insert(field->getNameAsString());
    //         }
    //     }
    //     return true;
    // }

    std::set<std::string> TranslateIndirectCall(Expr *E) {
        std::set<std::string> CallStr;
        if(CallExpr *Call = dyn_cast<CallExpr>(E))
        {
            if (Call->getDirectCallee()) {
                CallStr.insert(Call->getDirectCallee()->getNameInfo().getAsString());
            } else if(Expr *Callee = Call->getCallee())
            {
                // Match the CallExpr type against the TotalDebugMap
                if(ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(Callee))
                {
                    QualType QT = ICE->getType();
                    if (QT->isPointerType()) {
                        QT = QT->getPointeeType();
                    }
                    while (auto *TDT = dyn_cast<TypedefType>(QT)) {
                        QT = TDT->getDecl()->getUnderlyingType();
                    }
                    CallStr = getFuzzySet(QT.getAsString());
                }
                else if(MemberExpr* ME = dyn_cast<MemberExpr>(Callee->IgnoreImpCasts()))
                {
                    QualType QT = ICE->getType();
                    if (QT->isPointerType()) {
                        QT = QT->getPointeeType();
                    }
                    while (auto *TDT = dyn_cast<TypedefType>(QT)) {
                        QT = TDT->getDecl()->getUnderlyingType();
                    }
                    CallStr = getFuzzySet(QT.getAsString());
                }
                else
                {
                    CallStr = {};
                }
            }
        }
        
        return CallStr;
    }

        //
    // Get all of the direct assignments for different variables
    //
    // bool VisitBinaryOperator(BinaryOperator *BO) {
    //     if (BO->isAssignmentOp()) {
    //         Expr *LHS = BO->getLHS();
    //         if(ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(LHS))
    //         {
    //             if(MemberExpr* ME = dyn_cast<MemberExpr>(LHS->IgnoreImpCasts())){
    //                 clang::DeclarationNameInfo nameInfo = ME->getMemberNameInfo();
    //                 llvm::outs() << "ICE Type: " << ICE->getType().getAsString() << "\n";
    //                 exit(0);
    //                 // llvm::outs() << "DRE Type: " << DRE->getType().getAsString() << "\n";
    //                 // 
    //             }
    //         }
    //     }
    //     return true;
    // }

    // bool VisitBinaryOperator(BinaryOperator *BO) {
    //     if (BO->isAssignmentOp()) {
    //         Expr *LHS = BO->getLHS()->IgnoreImpCasts();
    //         if(MemberExpr* ME = dyn_cast<MemberExpr>(LHS)){
    //             clang::DeclarationNameInfo nameInfo = ME->getMemberNameInfo();
    //             if(auto *ICE = dyn_cast<ImplicitCastExpr>(BO->getRHS()))
    //             {
    //                 if(ICE->getCastKind() == CK_FunctionToPointerDecay)
    //                 {
    //                     if(DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreImpCasts()))
    //                     {  
    //                         TotalDebugMap[getFuzzyMatch(DRE->getType().getAsString())].insert(nameInfo.getAsString());
    //                     }
    //                 }
    //             }
    //         }
    //     }
    //     return true;
    // }
        
    bool printName(Expr *E, ASTContext &Ctx) {
        if (!E) return false;
        bool found = false;

        // Check for direct function calls
        if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(E)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                llvm::outs() << FD->getNameAsString();
                return true;
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(E)) {
            // If the Function Pointer Called matches the one we are looking for
            llvm::outs() << MemExpr->getMemberNameInfo().getName().getAsString();
            return true;
        }

        for (Stmt *child : E->children()) {
            if (Expr *childExpr = dyn_cast<Expr>(child)) {
                if(printName(childExpr, Ctx))
                {
                    found = true;
                    break;
                }
            }
        }
        return found;
    }

    unsigned int getLine(SourceLocation Loc) {
        SourceManager &SM = Context->getSourceManager();
        if (Loc.isValid()) {
            return SM.getExpansionLineNumber(Loc);
        }
        return 0;
    }

    /*
        Visit Every Function Decl and add all CallExpr inside of it to its CallGraph map
    */
    bool VisitFunctionDecl(FunctionDecl *Func) {
        std::string FuncName = Func->getNameInfo().getAsString();
        QualType QT = Func->getType();
        if (QT->isPointerType()) {
            QT = QT->getPointeeType();
        }
        while (auto *TDT = dyn_cast<TypedefType>(QT)) {
            QT = TDT->getDecl()->getUnderlyingType();
        }
        TotalDebugMap[QT.getAsString()].insert(FuncName);
        GraphNodeInfo NodeInfo;
        SourceManager &SM = Context->getSourceManager();
        NodeInfo.FileName = Func->getLocation().printToString(SM);
        size_t pos = NodeInfo.FileName.find(":"); // Find the position of the first colon
        if (pos != std::string::npos) {
            NodeInfo.FileName.erase(pos); // Erase everything after the colon (including the colon)
        }
        NodeInfo.FunctionName = FuncName;
        NodeInfo.StartLine = getLine(Func->getBeginLoc());
        if(Func->getBody() == nullptr)
        {
            return true;
        }
        for(Stmt *S : Func->getBody()->children())
        {
            NodeInfo.EndLine = getLine(S->getEndLoc());
        }
        if(NodeInfo.StartLine > NodeInfo.EndLine)
        {
            return true;
        }
        
        FunctionLineMap.insert(NodeInfo);
        return true;
    }

    std::string getFunctionName(CallExpr *Call) {
        SourceManager &SM = Context->getSourceManager();
        std::string CallFileName = SM.getFileEntryForID(SM.getMainFileID())->getName().str();
        unsigned int CallLine = getLine(Call->getBeginLoc());
        for(const auto& NodeInfo : FunctionLineMap) {

            if(CallFileName == NodeInfo.FileName)
            {
                if(CallLine >= NodeInfo.StartLine && CallLine <= NodeInfo.EndLine)
                {
                    return NodeInfo.FunctionName;
                }
            }
        }
        // llvm::outs() << "Failed to find matching function to Call: " << printName(Call, *Context) << "\n";
        return "Unknown";
    }

    bool VisitCallExpr(CallExpr* Call)
    {
        std::string FuncName = getFunctionName(Call);
        if(FuncName == "Unknown")
        {
            return true;
        }
        std::set<std::string> callees = TranslateIndirectCall(Call);
        CallGraphMap[FuncName].insert(callees.begin(), callees.end());
        
        return true;
    }




private:
    ASTContext *Context;
};

#endif