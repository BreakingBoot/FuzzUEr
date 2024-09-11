#ifndef __FCP_CALLBACKS_H__
#define __FCP_CALLBACKS_H__

#include "Globals.h"

class FCPCallbacks : public PPCallbacks {
public:

    explicit FCPCallbacks(SourceManager &SM, ASTContext *Context) : SM(SM), Context(Context) {}

    /*
        Filter the macro definition to remove the macro name and any leading spaces.
    */
    std::string filterMacroDefinition(const std::string &name, const std::string &value) {
        size_t pos = value.find(name);
        if (pos != std::string::npos) {
            // Find the space character after the name
            size_t spacePos = value.find(' ', pos + name.length());
            std::string filteredValue = value.substr(spacePos + 1);

            // Remove backslashes and spaces from the filteredValue
            std::string filteredResult;
            bool foundBackslash = false;
            for (char c : filteredValue) {
                if (c == '\\') {
                    foundBackslash = true;
                } else if (!isspace(c) || (isspace(c) && !foundBackslash)) {
                    foundBackslash = false;
                    filteredResult += c;
                }
            }

            return filteredResult;
        }
        return value;
    }

    /*
        Capture all of the macro definitions per compilation command.
    */
    void MacroDefined(const Token &MacroNameTok, const MacroDirective *MD) override {
        StringRef MacroName = MacroNameTok.getIdentifierInfo()->getName();

        SourceLocation MacroLoc = MD->getMacroInfo()->getDefinitionLoc();

        FileID FID = SM.getFileID(MacroLoc);
        const FileEntry *FE = SM.getFileEntryForID(FID);
        if (FE) {
            StringRef FilePath = FE->tryGetRealPathName();
            if (!FilePath.empty()) {
                MacroDef mac;
                mac.Name = MacroName.str();
                mac.File = FilePath.str();

                const LangOptions &LangOpts = Context->getLangOpts();
                CharSourceRange Range = CharSourceRange::getTokenRange(MD->getMacroInfo()->getDefinitionLoc(), MD->getMacroInfo()->getDefinitionEndLoc());
                mac.Value = Lexer::getSourceText(Range, SM, LangOpts).str();
                mac.Value = PassHelpers::reduceWhitespace(filterMacroDefinition(mac.Name, mac.Value));

                PreDefinedConstants[MacroName.str()] = mac;
            }
        }
    }

    /*
        Capture all of the includes per compilation command.
    */
    void InclusionDirective (SourceLocation HashLoc, 
                            const Token & IncludeTok, 
                            StringRef FileName, 
                            bool IsAngled, 
                            CharSourceRange FilenameRange, 
                            Optional<clang::FileEntryRef> File, 
                            StringRef SearchPath, 
                            StringRef RelativePath, 
                            const Module * Imported, 
                            SrcMgr::CharacteristicKind FileType) override {
        // Need to also track the function calls -> include directives
        // Store the full path and other information as needed.
        std::string FullPath = SearchPath.str() + "/" + FileName.str();
        std::string currentFile = SM.getFilename(HashLoc).str();

        if(FileName.str().find("AutoGen") == std::string::npos)
        {
            IncludeDirectives.insert(FullPath);
            if(currentFile.find("AutoGen") == std::string::npos)
            {
                if (IncludesDependencyGraph.find(currentFile) == IncludesDependencyGraph.end()) {
                    IncludesDependencyGraph[currentFile] = {};
                }
                IncludesDependencyGraph[currentFile].insert(FullPath);
            }
        }
    }

private:
    ASTContext *Context;
    SourceManager &SM;
};

#endif