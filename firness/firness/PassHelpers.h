#ifndef __PASS_HELPERS_H__
#define __PASS_HELPERS_H__

#include "Globals.h"

namespace PassHelpers {

    class OperatorCheckVisitor : public clang::RecursiveASTVisitor<OperatorCheckVisitor> {
    public:
        bool containsMulOrAdd = false;

        bool VisitBinaryOperator(clang::BinaryOperator* binaryOp) {
            if (binaryOp->getOpcode() == clang::BO_Mul || binaryOp->getOpcode() == clang::BO_Add) {
                containsMulOrAdd = true;
            }
            return true;
        }
    };

    bool checkForMulOrAdd(Stmt *stmt) {
        OperatorCheckVisitor visitor;
        visitor.TraverseStmt(stmt);
        return visitor.containsMulOrAdd;
    }

    /*
        Get the source code level string of the given Expr
    */
    std::string getSourceCode(Expr *E, ASTContext &Context)
    {
        if (!E) return "";
        SourceManager &SM = Context.getSourceManager();
        const LangOptions &LangOpts = Context.getLangOpts();
        CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
        std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

        return ExprText;
    }

    /*
        Responsible for checking if the argument is all well-defined data
    */
    bool checkOperand(Expr *operand, ASTContext &Ctx, const std::map<std::string, std::string> &DefinesList, 
            const std::vector<std::string> &EnumList) {
        std::string literalString = getSourceCode(operand, Ctx); 

        // Check if any string in PreDefinedConstants is a substring of literalString
        for (const auto& predefined : DefinesList) {
            if (literalString.find(predefined.first) != std::string::npos) {
                return true;
            }
        }

        for (const std::string& enums_defs : EnumList) {
            if (literalString.find(enums_defs) != std::string::npos) {
                return true;
            }
        }

        if(auto *BO = dyn_cast<BinaryOperator>(operand)){
            // Recursively check both the left-hand and right-hand operands
            return checkOperand(BO->getLHS(), Ctx, DefinesList, EnumList) && 
                checkOperand(BO->getRHS(), Ctx, DefinesList, EnumList);
        }
        
        return false;
    }

    /*
        Print out the given expression to stdout
    */
    void PrintExpr(Expr *E, ASTContext &Context)
    {
        llvm::outs() << E->getStmtClassName() << ": " << getSourceCode(E, Context) << "\n";
    }

    /*
        Gets the Line number of a given Expr
    */
    unsigned getLineNumber(Expr *E, ASTContext &Context) {
        SourceManager &SM = Context.getSourceManager();
        SourceLocation Loc = E->getExprLoc();
        if (Loc.isValid()) {
            return SM.getExpansionLineNumber(Loc);
        }
        return 0;
    }

    std::string removeTrailingPointer(const std::string& input) {
        std::string result = input;

        // Remove trailing spaces
        result.erase(std::remove_if(result.rbegin(), result.rend(), ::isspace).base(), result.end());

        // Find the last occurrence of '*'
        size_t lastStarPos = result.find_last_of('*');

        // Check if '*' is found and it is at the end of the string
        if (lastStarPos != std::string::npos && lastStarPos == result.length() - 1) {
            // Erase the trailing '*'
            result.erase(lastStarPos);
        }

        return result;
    }

    /*
        Eliminates the extra whitespace for new lines//extra spaces
        in a given string
    */
    std::string reduceWhitespace(const std::string& str) {
        std::string result = std::regex_replace(str, std::regex("\\s+"), " ");

        // Trim leading and trailing spaces if desired
        if (!result.empty() && result[0] == ' ') {
            result.erase(result.begin());
        }
        if (!result.empty() && result[result.size() - 1] == ' ') {
            result.erase(result.end() - 1);
        }

        return result;
    }

}; // PassHelpers namespace

#endif