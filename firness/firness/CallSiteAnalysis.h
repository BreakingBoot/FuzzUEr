#ifndef __CALLSITEANALYSIS_H__
#define __CALLSITEANALYSIS_H__

#include "PassHelpers.h"

class CallSiteAnalysis : public RecursiveASTVisitor<CallSiteAnalysis> {
public:
    explicit CallSiteAnalysis(ASTContext *Context)
        : Context(Context) {}

    // Assume ParameterDirection is an enum with values INPUT and OUTPUT
    Expr* getMostRelevantAssignment(VarDecl* var, MemberExpr* ME, int exprLineNumber, ASTContext &Ctx) {
        std::stack<std::pair<clang::Expr *, ParameterDirection>> assignmentsStack = (var == nullptr) ? MemAssignments[ME] : VarAssignments[var];

        // This loop checks the assignments from the most recent (top of the stack) to the earliest.
        while (!assignmentsStack.empty() && assignmentsStack.top().first != nullptr) {
            std::pair<clang::Expr *, ParameterDirection> assignmentInfo = assignmentsStack.top();

            Expr* assignmentExpr = assignmentInfo.first;
            ParameterDirection direction = assignmentInfo.second;

            // Retrieve the line number of the assignmentExpr.
            int assignmentLineNumber = getLineNumber(assignmentExpr, Ctx);

            // If the direction indicates it's an assignment and it's before our expression of interest
            if ((direction == ParameterDirection::OUT || direction == ParameterDirection::IN_OUT || direction == ParameterDirection::DIRECT)&& assignmentLineNumber < exprLineNumber) {
                return assignmentExpr;
            }

            // Move to the next (earlier) assignment in the stack
            assignmentsStack.pop();
        }

        // Handle the case where no assignment is found, if necessary.
        return nullptr;
    }

    void HandleMatchingExpr(CallExpr* CE, ASTContext &Ctx) {
        for (unsigned i = 0; i < CE->getNumArgs(); i++) {
            ParseArg(CE->getArg(i)->IgnoreCasts(), Ctx, CE, CE->getArg(i), i);
        }
    }

    ParameterDirection HandleParameterDirection(ParameterDirection VariableDirection, CallExpr* CE, Expr* Arg)
    {
        // if((VariableDirection == ParameterDirection::DIRECT) && (CallArgMap[CE][Arg] == ParameterDirection::IN))
        // {
        //     return ParameterDirection::IN_DIRECT;
        // }
        return CallArgMap[CE][Arg];
    }

    void ParseArg(Stmt *S, ASTContext &Ctx, Expr* CurrentExpr, Expr* CallArg, int ParamNum) {
        if (!S) return;

        if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
            if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                // If the top Expr in the stack of VarAssignments[VD]
                // is the same as the current CallExpr then get the second one
                while (!VarAssignments[VD].empty() && VarAssignments[VD].top().first == CurrentExpr) {
                    VarAssignments[VD].pop();
                }
                    
                // If stack is empty after popping, you might want to handle it here
                if (VarAssignments[VD].empty()) {
                    return;  // or some other default action
                }
                // print out the vardecl type
                clang::QualType type = VD->getType();
                // Fetch the most relevant assignment for this variable usage
                Expr* mostRelevantAssignment = getMostRelevantAssignment(VD, nullptr, PassHelpers::getLineNumber(CurrentExpr, Ctx), Ctx);
                if (type->isEnumeralType()) {
                    VarDecl *Var = createPlaceholderVarDecl(Ctx, DRE);  // Assuming this function creates a placeholder VarDecl for the enum value
                    Argument_AST Arg;
                    Arg.Assignment = DRE;
                    Arg.Arg = CallArg;
                    Arg.ArgNum = ParamNum;
                    Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                    VarDeclMap[Var].push_back(Arg);
                    return;
                }
                else if (mostRelevantAssignment) {
                    Argument_AST Arg;
                    Arg.Assignment = mostRelevantAssignment;
                    Arg.Arg = CallArg;
                    Arg.ArgNum = ParamNum;
                    Arg.direction = HandleParameterDirection(VarAssignments[VD].top().second, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                    VarDeclMap[VD].push_back(Arg);
                }
                else
                {
                    Argument_AST Arg;
                    Arg.Assignment = nullptr;
                    Arg.Arg = CallArg;
                    Arg.ArgNum = ParamNum;
                    Arg.direction = HandleParameterDirection(VarAssignments[VD].top().second, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                    VarDeclMap[VD].push_back(Arg);
                }
                return;
            }
            else if (FunctionDecl *FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                // New handling code for FunctionDecl...
                VarDecl *Var = createPlaceholderVarDecl(Ctx, DRE); 
                Argument_AST Arg;
                Arg.Assignment = DRE;
                Arg.Arg = CallArg;
                Arg.ArgNum = ParamNum;
                Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                VarDeclMap[Var].push_back(Arg);
                return;
            }
            else if (EnumConstantDecl *ECD = dyn_cast<EnumConstantDecl>(DRE->getDecl())) {
                VarDecl *Var = createPlaceholderVarDecl(Ctx, DRE);  // Assuming this function creates a placeholder VarDecl for the enum value
                Argument_AST Arg;
                Arg.Assignment = DRE;
                Arg.Arg = CallArg;
                Arg.ArgNum = ParamNum;
                Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                VarDeclMap[Var].push_back(Arg);
                return;
            }
        }
        else if(BinaryOperator *BO = dyn_cast<BinaryOperator>(S))
        {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, BO);
            Argument_AST Arg;
            Arg.Assignment = BO;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);
            return;
        }
        else if (StringLiteral *SL = dyn_cast<StringLiteral>(S)) {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, SL);
            Argument_AST Arg;
            Arg.Assignment = SL;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);
            return;
        } 
        else if (IntegerLiteral *IL = dyn_cast<IntegerLiteral>(S)) {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, IL); 
            Argument_AST Arg;
            Arg.Assignment = IL;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);     
            return;       
        }
        else if (UnaryExprOrTypeTraitExpr *UETTE = dyn_cast<UnaryExprOrTypeTraitExpr>(S)) {
            if (UETTE->getKind() == UETT_SizeOf) {
                // It's a sizeof expression.
                // Handle or further process the operand of the sizeof operation.
                VarDecl *Var = createPlaceholderVarDecl(Ctx, UETTE); 
                Argument_AST Arg;
                Arg.Assignment = UETTE;
                Arg.Arg = CallArg;
                Arg.ArgNum = ParamNum;
                Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                VarDeclMap[Var].push_back(Arg);  
                return;
            }
        } 
        else if (CallExpr* CE = dyn_cast<CallExpr>(S)) {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, CE); 
            Argument_AST Arg;
            Arg.Assignment = CE;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::INDIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);  
            return;
        }
        else if (MemberExpr* ME = dyn_cast<MemberExpr>(S))
        {
            Expr* mostRelevantAssignment = getMostRelevantAssignment(nullptr, ME, PassHelpers::getLineNumber(CurrentExpr, Ctx), Ctx);
            VarDecl *Var = isa<VarDecl>(ME->getMemberDecl()) ? dyn_cast<VarDecl>(ME->getMemberDecl()) : createPlaceholderVarDecl(Ctx, ME); 
            Argument_AST Arg;
            Arg.Assignment = ME;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::INDIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);  
            return;
        }
        for (Stmt *child : S->children()) {
            ParseArg(child, Ctx, CurrentExpr, CallArg, ParamNum);
        }
        return;
    }

    /*
        This is responible for creating the placeholder variable
        name when the CallExpr argument is directly passed in via
        a literal (i.e. constant)
    */
    VarDecl* createPlaceholderVarDecl(ASTContext &Ctx, Stmt *literal) {
        // Get a unique name for the placeholder VarDecl
        std::string name = "__CONSTANT_";
        QualType type;

        if (isa<StringLiteral>(literal)) {
            name += "STRING__";
            type = Ctx.getPointerType(Ctx.getWCharType());
        } else if (UnaryExprOrTypeTraitExpr *sizeofExpr = dyn_cast<UnaryExprOrTypeTraitExpr>(literal)){
            if (sizeofExpr->getKind() == UETT_SizeOf) {
                name += "SIZEOF__";
                // Get the type of the expression argument if it's a type
                if (sizeofExpr->isArgumentType()) {
                    type = sizeofExpr->getArgumentType();
                } else {
                    // If the argument is an expression, get its type
                    type = sizeofExpr->getArgumentExpr()->getType();
                }
            }
            else
            {
                name += "UNKNOWN__";
                type = sizeofExpr->getType();
            }
        } else if(auto *BO = dyn_cast<BinaryOperator>(literal)){
            if(BO->getOpcode() == BO_Or)
            {
                name += "INT__";
                type = Ctx.IntTy;
            }
            else
            {
                name += "UNKNOWN__";
                type = BO->getType();
            }
            /*else
            {
                bool isSubstring = checkOperand(BO, Ctx, PreDefinedConstants, EnumConstants);
                
                if (isSubstring) {
                    name += "INT__";
                }
            }*/
            
        } else if (isa<IntegerLiteral>(literal)) {
            // Get the string representation of the literal
            std::string literalString = getSourceCode(dyn_cast<IntegerLiteral>(literal), Ctx); 

            // Check if any string in PreDefinedConstants is a substring of literalString
            bool isSubstring = false;
            for (const std::string& enums_defs : EnumConstants) {
                if (literalString.find(enums_defs) != std::string::npos) {
                    isSubstring = true;
                    break;
                }
            }

            if (isSubstring) {
                name += "INT__";
            }
            else
            {
                for (const auto& predefined : PreDefinedConstants) {
                    if (literalString.find(predefined.first) != std::string::npos) {
                        IncludeDirectives.insert(predefined.second.File);
                        isSubstring = true;
                        break;
                    }
                }

                if (isSubstring) {
                    name += "MAYBE_INT__";
                }
                else
                {
                    name += "UNKNOWN__";
                }
            }
            type = Ctx.IntTy;
        } else if (CallExpr *CE = dyn_cast<CallExpr>(literal)) {
            name = "__INDIRECT_CALL__";
            type = CE->getCallReturnType(Ctx);
        } else if (auto *DRE = dyn_cast<DeclRefExpr>(literal)){
            if(auto *FD = dyn_cast<FunctionDecl>(DRE->getDecl()))
            {
                name = "__FUNCTION_PTR__";
                type = FD->getReturnType();
            }
            else if(EnumConstantDecl *ECD = dyn_cast<EnumConstantDecl>(DRE->getDecl()))
            {
                name = "__ENUM_ARG__";
                type = ECD->getType();
            }
            else if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl()))
            {
                clang::QualType vartype = VD->getType();
                if(vartype->isEnumeralType())
                {
                    name = "__ENUM_ARG__";
                    type = vartype;
                }
                else
                {
                    name = "__UNKNOWN__";
                    type = DRE->getType();
                }
            }
            else
            {
                name = "__UNKNOWN__";
                type = DRE->getType();
            }
        }
        else if (auto *ME = dyn_cast<MemberExpr>(literal)){
            name = ME->getMemberNameInfo().getAsString();
            type = ME->getType();
        }
        else
        {
            name += "UNKNOWN__";
            type = Ctx.IntTy;
        }

        // Create the VarDecl with the computed name and type
        return VarDecl::Create(Ctx, Ctx.getTranslationUnitDecl(), 
                            SourceLocation(), SourceLocation(), 
                            &Ctx.Idents.get(name), type, 
                            Ctx.getTrivialTypeSourceInfo(type), 
                            SC_None);
    }

    /*
        Checks if a given function call matches a function
        from the FunctionNames set
    */
    bool doesCallMatch(Expr *E, ASTContext &Ctx) {
        if (!E) return false;
        bool found = false;

        // Check for direct function calls
        if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(E)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                if (FunctionNames.count(FD->getNameAsString())) {
                    // llvm::outs() << "Found Match: " << FD->getNameAsString() << "\n";
                    return true;
                }
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(E)) {
            // If the Function Pointer Called matches the one we are looking for
            if (FunctionNames.count(MemExpr->getMemberNameInfo().getName().getAsString())) {
                // llvm::outs() << "Found Match: " << MemExpr->getMemberNameInfo().getName().getAsString() << "\n";
                return true;
            }
        }

        for (Stmt *child : E->children()) {
            if (Expr *childExpr = dyn_cast<Expr>(child)) {
                if(doesCallMatch(childExpr, Ctx))
                {
                    found = true;
                    break;
                }
            }
        }
        return found;
    }


    /*
        Convert the direction flow of data to string
    */
    std::string GetAssignmentType(ParameterDirection dir)
    {
        switch(dir)
        {
            case ParameterDirection::DIRECT:
                return "DIRECT";
            case ParameterDirection::UNKNOWN:
                return "UNKNOWN";
            case ParameterDirection::IN:
                return "IN";
            case ParameterDirection::OUT:
                return "OUT";
            case ParameterDirection::IN_OUT:
                return "IN_OUT";
            case ParameterDirection::INDIRECT:
                return "INDIRECT";
            case ParameterDirection::IN_DIRECT:
                return "IN_DIRECT";
            default:
                return "UNKNOWN";
        }
    }

    /*
        Converts the Clang AST map to a string map for output/further analysis
    */
    std::map<std::string, Argument> GetVarDeclMap(VarMap OriginalMap)
    {
        std::map<std::string, Argument> ConvertedMap;
        std::string arg_ID = "Arg_";
        for(auto& pair : OriginalMap)
        {
            VarDecl* VD = pair.first;
            GetVarStruct(VD);
            for(Argument_AST Clang_Arg : pair.second)
            {
                Argument String_Arg;
                String_Arg.data_type = VD->getType().getAsString();
                if(Clang_Arg.ArgNum == 0 && CallInfo.Service == "protocol")
                {
                    String_Arg.variable = "__PROTOCOL__";
                }
                else
                {
                    String_Arg.variable = VD->getNameAsString();
                }
                // String_Arg.variable = VD->getNameAsString();
                std::vector<std::string> potentialOutputs = GetPotentialOutputs(Clang_Arg.Arg);
                if(potentialOutputs.size() > 1)
                {
                    String_Arg.potential_outputs = potentialOutputs;
                    String_Arg.usage = PassHelpers::reduceWhitespace(PassHelpers::getSourceCode(Clang_Arg.Arg, *this->Context));
                }
                else if(potentialOutputs.size() == 1)
                {
                    String_Arg.usage = PassHelpers::reduceWhitespace(potentialOutputs[0]);
                }
                else
                {
                    String_Arg.usage = PassHelpers::reduceWhitespace(PassHelpers::getSourceCode(Clang_Arg.Arg, *this->Context));
                }

                String_Arg.assignment = PassHelpers::reduceWhitespace(PassHelpers::getSourceCode(Clang_Arg.Assignment, *this->Context));
                String_Arg.arg_dir = GetAssignmentType(Clang_Arg.direction);
                String_Arg.arg_type = Clang_Arg.Arg->getType().getAsString();
                if(String_Arg.arg_dir == "OUT" || String_Arg.arg_dir == "IN_OUT")
                {
                    GeneratorTypes.insert(removeTrailingPointer(String_Arg.arg_type));
                    for(auto cast : CastMap)
                    {
                        if(cast.first == removeTrailingPointer(String_Arg.arg_type))
                        {
                            for(auto cast_type : cast.second)
                            {
                                GeneratorTypes.insert(cast_type);
                            }
                            break;
                        }
                    
                    }
                }
                
                
                ConvertedMap[arg_ID+std::to_string(Clang_Arg.ArgNum)] = String_Arg;
            }
        }
        return ConvertedMap;
    }

    void PrintPotentialOutputs(const std::vector<std::string>& potentialOutputs) {
        for (const std::string& output : potentialOutputs) {
            llvm::outs() << "Potential Output: " << output << "\n";
        }
    }


    bool isWhitespace(const std::string& str) {
        for (char c : str) {
            if (!std::isspace(static_cast<unsigned char>(c))) {
                return false; 
            }
        }
        return true;
    }

    // std::vector<std::string> GetPotentialOutputs(Expr *E) {
    //     std::vector<std::string> potentialOutputs;

    //     if (auto *BO = dyn_cast<BinaryOperator>(E->IgnoreCasts())) {
    //         if (BO->isBitwiseOp()) {
    //             Expr *lhs = BO->getLHS();
    //             Expr *rhs = BO->getRHS();

    //             // Recursively check left-hand side and right-hand side
    //             auto leftOutputs = GetPotentialOutputs(lhs->IgnoreCasts()->IgnoreParens());
    //             auto rightOutputs = GetPotentialOutputs(rhs->IgnoreCasts()->IgnoreParens());

    //             if (leftOutputs.empty() && rightOutputs.empty()) {
    //                 return potentialOutputs;
    //             } else if (leftOutputs.empty()) {
    //                 return rightOutputs;
    //             } else if (rightOutputs.empty()) {
    //                 return leftOutputs;
    //             }

    //             // Combine the potential outputs from both sides
    //             for (const std::string &left : leftOutputs) {
    //                 for (const std::string &right : rightOutputs) {
    //                     if (BO->getOpcode() == BO_Or)
    //                         potentialOutputs.push_back(left + " | " + right);
    //                     else if (BO->getOpcode() == BO_And)
    //                         potentialOutputs.push_back(left + " & " + right);
    //                 }
    //             }
    //         }
    //     } else if (ConditionalOperator *condOp = dyn_cast<ConditionalOperator>(E->IgnoreCasts())) {
    //         // Process true and false expressions
    //         auto trueOutputs = GetPotentialOutputs(condOp->getTrueExpr());
    //         auto falseOutputs = GetPotentialOutputs(condOp->getFalseExpr());

    //         // Add the potential outputs from both branches
    //         potentialOutputs.insert(potentialOutputs.end(), trueOutputs.begin(), trueOutputs.end());
    //         potentialOutputs.insert(potentialOutputs.end(), falseOutputs.begin(), falseOutputs.end());
    //     } else {
    //         // This is a leaf node or non-conditional expression, add it to potential outputs
    //         //if (isa<StringLiteral>(E->IgnoreCasts()) || isa<IntegerLiteral>(E->IgnoreCasts()) || isa<CharacterLiteral>(E->IgnoreCasts())) {
    //         potentialOutputs.push_back(getSourceCode(E, *this->Context));
    //         //}
    //     }

    //     return potentialOutputs;
    // }

    std::vector<std::string> GetPotentialOutputs(Expr *E) {
        std::vector<std::string> potentialOutputs;

        if (auto *BO = dyn_cast<BinaryOperator>(E->IgnoreCasts())) {
            if (BO->getOpcode() == BO_Or) {
                Expr *lhs = BO->getLHS();
                Expr *rhs = BO->getRHS();

                // Recursively check left-hand side and right-hand side
                auto leftOutputs = GetPotentialOutputs(lhs->IgnoreCasts()->IgnoreParens());
                auto rightOutputs = GetPotentialOutputs(rhs->IgnoreCasts()->IgnoreParens());

                // Combine the potential outputs from both sides
                for(const std::string &left : leftOutputs)
                {
                    for (const std::string &right : rightOutputs) {
                        if(reduceWhitespace(right) == "0")
                            potentialOutputs.push_back(left);
                        else
                            potentialOutputs.push_back(left + " | " + right);
                    }
                }
            }
        } else if (ConditionalOperator *condOp = dyn_cast<ConditionalOperator>(E->IgnoreCasts())) {
            // Process true and false expressions
            auto trueOutputs = GetPotentialOutputs(condOp->getTrueExpr());
            auto falseOutputs = GetPotentialOutputs(condOp->getFalseExpr());

            // Add the potential outputs from both branches
            potentialOutputs.insert(potentialOutputs.end(), trueOutputs.begin(), trueOutputs.end());
            potentialOutputs.insert(potentialOutputs.end(), falseOutputs.begin(), falseOutputs.end());
        } else {
            // This is a leaf node or non-conditional expression, add it to potential outputs
            potentialOutputs.push_back(getSourceCode(E, *this->Context));
        }

        return potentialOutputs;
    }

    /*
        This is the recursion to handle grabbing the sub types
        It also makes sure the sub types are only added once to the map
    */
    void processRecord(RecordDecl *RD) {
        if (!RD || (varRecordInfo.find(RD) == varRecordInfo.end()) || (FinalTypes.find(varRecordInfo[RD].TypeName) != FinalTypes.end())) {
            return;
        }
        // Copy the Info from the list generated during variable analysis
        if((FinalTypes.find(varRecordInfo[RD].TypeName) == FinalTypes.end())) {
            FinalTypes.insert(std::make_pair(varRecordInfo[RD].TypeName, varRecordInfo[RD]));
        }
        // Analyze the sub types of the struct and determine if they also need to be
        //      considered
        for (auto field : RD->fields()) {
            QualType fieldQT = field->getType();
            while (fieldQT->isAnyPointerType() || fieldQT->isReferenceType()) {
                fieldQT = fieldQT->getPointeeType();
            }
            fieldQT = fieldQT.getCanonicalType();

            if (const RecordType *fieldRT = dyn_cast<RecordType>(fieldQT)) {
                processRecord(fieldRT->getDecl());
            } /*else if (const TypedefType *fieldTDT = dyn_cast<TypedefType>(fieldQT)) {
                TypedefNameDecl *fieldTND = fieldTDT->getDecl();
                This isn't needed for edk2 use case
            }*/
        }
    }

    /*
        For each Variable Type that is used in generating the calls
        I grab those types structures and any sub types that may also be structures
    */
    void GetVarStruct(VarDecl *VD) {
        if (!VD) {
            return;
        }
        QualType QT = VD->getType();

        // Work through any typedefs to get to the ultimate
        // underlying type.
        while (QT->isAnyPointerType() || QT->isReferenceType()) {
            QT = QT->getPointeeType();
        }
        QT = QT.getCanonicalType();

        // Now, QT should be the actual type of the variable, without any typedefs
        // Check if it's a record type (i.e., a struct or class type).
        if (const RecordType *RT = dyn_cast<RecordType>(QT)) {
            // Get the RecordDecl for the record type.
            if(FinalTypes.find(QT.getAsString()) == FinalTypes.end())
                processRecord(RT->getDecl());
        } else if (const TypedefType *TDT = dyn_cast<TypedefType>(QT)) {
            // Get the TypedefNameDecl for the typedef type.
            TypedefNameDecl *TND = TDT->getDecl();
            // llvm::outs() << "Variable " << VD->getNameAsString() << " is of typedef type "
            //             << TND->getNameAsString() << "\n";
            // This is never reached, but I keep incase it is needed in future analysis            
        }
    }

    /*
        Generate the call info by converting the Clang AST
        graph into a string one
    */
    bool GenCallInfo(Expr* EX)
    {
        if (!EX) return false;
        bool found = false;

        std::string CallExprString;
        /*if (FunctionDecl* FD = dyn_cast<FunctionDecl>(EX)) {
            CallExprString = FD->getNameAsString();
            CallInfo.Function = CallExprString;
            CallInfo.Arguments = GetVarDeclMap(VarDeclMap);
            return true;
        }
        else*/ if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(EX)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                CallExprString = FD->getNameAsString();
                CallInfo.Function = CallExprString;
                CallInfo.Arguments = GetVarDeclMap(VarDeclMap);
                return true;
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(EX)) {
            CallExprString = MemExpr->getMemberNameInfo().getName().getAsString();
            CallInfo.Function = CallExprString;
            if (auto *Base = dyn_cast<Expr>(MemExpr->getBase()))
            {
                // Base is of type Expr*
                // Now, you can get the type information
                QualType BaseType = Base->getType();
                std::string type = BaseType.getAsString();
                std::transform(type.begin(), type.end(), type.begin(), ::tolower);

                // check if the BaseType contains the phrase protocol and make sure its lowercase
                if (type.find("protocol") != std::string::npos) {
                    CallInfo.Service = "protocol";
                    ///CallInfo.Arguments.begin()->second.variable = "__PROTOCOL__";
                }
                else
                {
                    CallInfo.Service = getSourceCode(Base, *this->Context);
                }

            }
            CallInfo.Arguments = GetVarDeclMap(VarDeclMap);
            return true;
        }
        for (Stmt *child : EX->children()) {
            if (Expr *childExpr = dyn_cast<Expr>(child)) {
                if(GenCallInfo(childExpr))
                {
                    found = true;
                    break;
                }
            }
        }
        return found;
    }

    void CheckConditional(ConditionalOperator *CO) {
        Expr *condition = CO->getCond();
        Expr *trueExpr = CO->getTrueExpr();
        Expr *falseExpr = CO->getFalseExpr();

        std::string conditionString = getSourceCode(condition, *this->Context);
        std::string trueExprString = getSourceCode(trueExpr, *this->Context);
        std::string falseExprString = getSourceCode(falseExpr, *this->Context);

        llvm::outs() << "Conditional Operator: " << conditionString << "\n";
        llvm::outs() << "True Expr: " << trueExprString << "\n";
        llvm::outs() << "False Expr: " << falseExprString << "\n";
    }

    bool isProtocol(std::string function_name) {
        if(CallInfo.Arguments.empty())
        {
            return false;
        }
        std::string type = CallInfo.Arguments.begin()->second.data_type;
        if(type.empty())
        {
            return false;
        }
        // if(CallInfo.Service == "protocol")
        // {
        //     CallInfo.Arguments.begin()->second.variable = "__PROTOCOL__";
        //     llvm::outs() << "Protocol: " << function_name << "\n";
        //     return true;
        // }
        std::string guid;
        for(auto it = HarnessFunctions.begin(); it != HarnessFunctions.end(); ++it)
        {
            if(it->first == function_name)
            {
                if(!it->second.empty())
                {
                    guid = it->second;
                }
            }
        }
        if(guid.empty())
        {
            return false;
        }
        // drop the g and Guid from the string guid
        guid = guid.substr(1, guid.length() - 5);

        // make sure its all lowercase
        std::transform(guid.begin(), guid.end(), guid.begin(), ::tolower);

        // remove the all underscores from the data type string
        type.erase(std::remove(type.begin(), type.end(), '_'), type.end());

        // make sure its all lowercase
        std::transform(type.begin(), type.end(), type.begin(), ::tolower);

        // check if the type contains the guid
        if (type.find(guid) != std::string::npos) {
            CallInfo.Service = "protocol";
            CallInfo.Arguments.begin()->second.variable = "__PROTOCOL__";
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

    void verifyCallInfo()
    {
        if(isNonProtocol(CallInfo.Function) || isProtocol(CallInfo.Function))
        {
            CallMap.push_back(CallInfo);
        }
    }

    /*
        Visit Every Call Expr and add its info to the 
        Call Map if the function name matches
    */
    bool VisitCallExpr(CallExpr *Call) {

        // Check if any of the arguments are references to the functions of interest
        // This happens when converting the function pointers during UEFI -> OS transition
        for (unsigned i = 0; i < Call->getNumArgs(); ++i) {
            Expr* Arg = Call->getArg(i);
            if (doesCallMatch(Arg, *this->Context)) {
                return true;  // Skip this CallExpr if an argument refers to a function of interest
            }
        }

        if(doesCallMatch(Call, *this->Context))
        {
            VarDeclMap.clear();
            CallInfo.clear();
            HandleMatchingExpr(Call, *this->Context);
            CallExprMap[Call] = VarDeclMap;
            GenCallInfo(Call);
            CallInfo.includes = IncludeDirectives;
            CallInfo.return_type = Call->getType().getAsString();
            verifyCallInfo();
        }
        return true;
    }

private:
    ASTContext *Context;
    VarMap VarDeclMap;
    Call CallInfo;
};

#endif