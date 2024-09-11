#ifndef __FILE_OP_HELPERS_H__
#define __FILE_OP_HELPERS_H__

#include "Globals.h"
#include <nlohmann/json.hpp>


namespace FileOps {
    void outputMacros(const std::string &filename, const std::map<std::string, MacroDef>& macros) {
        std::string file_path = filename + "/macros.json";
        nlohmann::json j;
        for (const auto& pair : macros) {
            const MacroDef& macro = pair.second;
            nlohmann::json macroJson;
            macroJson["Name"] = macro.Name;
            macroJson["File"] = macro.File;
            macroJson["Value"] = macro.Value;
            j.push_back(macroJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }
    
    /*
        Responsible for writing the typedef aliases
        gathered from the analysis to a json output file called aliases

    */
    void outputTypedefs(const std::string &filename, const std::set<std::pair<std::string, std::string>>& types) {
        std::string file_path = filename + "/aliases.json";
        nlohmann::json j;
        for (const auto& pair : types) {
            j[pair.first] = pair.second;
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Responsible for writing the structure type information
        gathered from the analysis to a json output file called types

    */
    void outputTypeStructs(const std::string &filename, const std::map<std::string, TypeData>& final) {
        std::string file_path = filename + "/types.json";
        nlohmann::json j;

        for (const auto& pair : final) {
            const TypeData& typeData = pair.second;
            nlohmann::json typeJson;
            typeJson["TypeName"] = typeData.TypeName;

            nlohmann::json fieldsJson;
            for (const FieldInfo& fieldInfo : typeData.Fields) {
                nlohmann::json fieldJson;
                fieldJson["Name"] = fieldInfo.Name;
                fieldJson["Type"] = fieldInfo.Type;
                fieldsJson.push_back(fieldJson);
            }
            typeJson["File"] = typeData.File;
            typeJson["Fields"] = fieldsJson;

            j.push_back(typeJson);
        }

        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Responsible for writing the function information
        gathered from the analysis to a json output file called functions
    */
    void outputFunctionDecl(const std::string &filename, const std::vector<Function>& functions) {
        std::string file_path = filename + "/functions.json";
        nlohmann::json j;
        for (const auto& function : functions) {
            nlohmann::json functionJson;
            functionJson["Function"] = function.FunctionName;
            functionJson["ReturnType"] = function.return_type;
            nlohmann::json parametersJson;
            for (const auto& pair : function.Parameters) {
                nlohmann::json paramJson;
                const Argument& arg = pair.second;
                paramJson["arg_dir"] = arg.arg_dir;
                paramJson["arg_type"] = arg.arg_type;
                paramJson["variable"] = arg.variable;
                paramJson["data_type"] = arg.data_type;
                paramJson["assignment"] = arg.assignment;
                paramJson["usage"] = arg.usage;
                paramJson["potential_outputs"] = arg.potential_outputs;
                parametersJson[pair.first] = paramJson;
            }
            functionJson["Parameters"] = parametersJson;
            functionJson["File"] = function.File;
            functionJson["Includes"] = function.includes;
            j.push_back(functionJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    void outputIncludesDependencyGraph(const std::string& filename, const std::map<std::string, std::set<std::string>>& includes) {
        std::string file_path = filename + "/includes.json";
        nlohmann::json j;
        for (const auto& pair : includes) {
            nlohmann::json includeJson;
            includeJson["File"] = pair.first;
            includeJson["Includes"] = pair.second;
            j.push_back(includeJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4);
        file.close();
    }

    /*
        Responsible for writing the function information
        gathered from the analysis to a json output file called functions
    */
    void outputGeneratorDecl(const std::string &filename, const std::vector<Function>& functions) {
        std::string file_path = filename + "/generators.json";
        nlohmann::json j;
        for (const auto& function : functions) {
            nlohmann::json functionJson;
            functionJson["Function"] = function.FunctionName;
            functionJson["ReturnType"] = function.return_type;
            nlohmann::json parametersJson;
            for (const auto& pair : function.Parameters) {
                nlohmann::json paramJson;
                const Argument& arg = pair.second;
                paramJson["arg_dir"] = arg.arg_dir;
                paramJson["arg_type"] = arg.arg_type;
                paramJson["variable"] = arg.variable;
                paramJson["data_type"] = arg.data_type;
                paramJson["assignment"] = arg.assignment;
                paramJson["usage"] = arg.usage;
                paramJson["potential_outputs"] = arg.potential_outputs;
                parametersJson[pair.first] = paramJson;
            }
            functionJson["Parameters"] = parametersJson;
            functionJson["File"] = function.File;
            functionJson["Includes"] = function.includes;
            j.push_back(functionJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Prints all of the call site information obtained from the
        pass to a json file call call-database
        "Arguments": {
            "Arg_0": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_1": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_2": {
                "arg_dir": "IN/OUT/IN_OUT",
                "arg_type": "",
                "assignment": "", -> Last assignment that happened
                "data_type": "",
                "usage": "", -> source code of call arg
                "variable": ""
            }
        },
        "Function": "FuncName"

        data_type and arg_type are both included incase a cast to VOID happens
        other than the built in variables I also included 3 more types for
        the cases of constants being directly used:
            - __CONSTANT_SIZEOF__
            - __CONSTANT_INT__
            - __CONSTANT_STRING__
    */
    void outputCallMap(const std::string& filename, std::vector<Call> callMap) {
        std::string file_path = filename + "/call-database.json";
        nlohmann::json jsonOutput;

        // Iterate over the CallMap
        for (const auto& call : callMap) {
            // Create a JSON object for each call
            nlohmann::json callObject;
            callObject["Function"] = call.Function;
            callObject["Service"] = call.Service;
            callObject["Include"] = call.includes;
            callObject["ReturnType"] = call.return_type;

            for (const auto& argumentPair : call.Arguments) {
                // Create a JSON object for each argument
                nlohmann::json argObject;
                const Argument& arg = argumentPair.second;
                argObject["data_type"] = arg.data_type;
                argObject["variable"] = arg.variable;
                argObject["assignment"] = arg.assignment;
                argObject["arg_dir"] = arg.arg_dir;
                argObject["arg_type"] = arg.arg_type;
                argObject["usage"] = arg.usage;
                argObject["potential_outputs"] = arg.potential_outputs;

                callObject["Arguments"][argumentPair.first] = argObject;
            }

            // Add the call object to the JSON output
            jsonOutput.push_back(callObject);
        }

        // Write the JSON object to a file
        std::ofstream outFile(file_path);
        outFile << jsonOutput.dump(4);
        outFile.close();
    }

    /*
        Prints all of the call site information obtained from the
        pass to a json file call call-database
        "Arguments": {
            "Arg_0": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_1": {
                "arg_dir": "",
                "arg_type": "",
                "assignment": "",
                "data_type": "",
                "usage": "",
                "variable": ""
            },
            "Arg_2": {
                "arg_dir": "IN/OUT/IN_OUT",
                "arg_type": "",
                "assignment": "", -> Last assignment that happened
                "data_type": "",
                "usage": "", -> source code of call arg
                "variable": ""
            }
        },
        "Function": "FuncName"

        data_type and arg_type are both included incase a cast to VOID happens
        other than the built in variables I also included 3 more types for
        the cases of constants being directly used:
            - __CONSTANT_SIZEOF__
            - __CONSTANT_INT__
            - __CONSTANT_STRING__
    */
    void outputGeneratorMap(const std::string& filename, std::vector<Call> GenMap) {
        std::string file_path = filename + "/generator-database.json";
        nlohmann::json jsonOutput;

        // Iterate over the CallMap
        for (const auto& call : GenMap) {
            // Create a JSON object for each call
            nlohmann::json callObject;
            callObject["Function"] = call.Function;
            callObject["Service"] = call.Service;
            callObject["Include"] = call.includes;
            callObject["ReturnType"] = call.return_type;

            for (const auto& argumentPair : call.Arguments) {
                // Create a JSON object for each argument
                nlohmann::json argObject;
                const Argument& arg = argumentPair.second;
                argObject["data_type"] = arg.data_type;
                argObject["variable"] = arg.variable;
                argObject["assignment"] = arg.assignment;
                argObject["arg_dir"] = arg.arg_dir;
                argObject["arg_type"] = arg.arg_type;
                argObject["usage"] = arg.usage;

                callObject["Arguments"][argumentPair.first] = argObject;
            }

            // Add the call object to the JSON output
            jsonOutput.push_back(callObject);
        }

        // Write the JSON object to a file
        std::ofstream outFile(file_path);
        outFile << jsonOutput.dump(4);
        outFile.close();
    }

    /*
        Responsible for writing the function aliases
        gathered from the analysis to a json output file called function-aliases
    */
   void outputAliases(const std::string &filename, const std::map<std::string, std::set<std::string>>& aliases) {
        std::string file_path = filename + "/function-aliases.json";
        nlohmann::json j;
        for (const auto& pair : aliases) {
            nlohmann::json aliasJson;
            aliasJson["Function"] = pair.first;
            aliasJson["Aliases"] = pair.second;
            j.push_back(aliasJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Debugging function to print the Arg Map to stdout
    */
    void printCallMap(const std::vector<Call> &calls) {
        for (const auto &callEntry : calls) {
            llvm::outs() << "Function: " << callEntry.Function << "\n";
            llvm::outs() << "Service: " << callEntry.Service << "\n";
            
            for (const auto &varEntry : callEntry.Arguments) {
                llvm::outs() << "\tArgument: " << varEntry.first << "\n";
                Argument Arg = varEntry.second;
                llvm::outs() << "\t\tData_Type: " << Arg.data_type << "\n";
                llvm::outs() << "\t\tArg_Type: " << Arg.arg_type << "\n";
                llvm::outs() << "\t\tArg_Name: " << Arg.variable << "\n";
                llvm::outs() << "\t\tArg_Assign: " << Arg.assignment << "\n";
                llvm::outs() << "\t\tArg_Direction: " << Arg.arg_dir << "\n";
                llvm::outs() << "\t\tArg_Usage: " << Arg.usage << "\n";
            }
        }
    }

    /*
        Read input file that contains the functions to analyze
        and store them in the FunctionNames set
    */
    std::set<std::string> processFunctionNames(const std::string& filename) {
        std::ifstream file(filename);

        if (!file.is_open()) {
            std::cerr << "Error opening file: " << filename << std::endl;
            exit(1);
        }
        FunctionNames.clear();
        std::string line;
        while (std::getline(file, line)) {
            // Remove leading and trailing whitespace
            line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](int ch) { return !std::isspace(ch); }));
            line.erase(std::find_if(line.rbegin(), line.rend(), [](int ch) { return !std::isspace(ch); }).base(), line.end());

            // Remove extra whitespace between words
            line = std::regex_replace(line, std::regex("\\s+"), " ");

            // stip any line that containes a [ or a ]
            if (line.find('[') != std::string::npos || line.find(']') != std::string::npos) {
                continue;
            }

            // Remove the protocol name from the function name
            // e.g. gEdkiiIoMmuProtocolGuid:Map -> Map
            size_t colonIndex = line.find(':');
            if (colonIndex != std::string::npos) {
                line = line.substr(colonIndex + 1);
            }

            if (!line.empty()) {
                FunctionNames.insert(line);
            }
        }

        file.close();
        return FunctionNames;
    }

    /*
        Output enums to a json file
    */
    void outputEnums(const std::string& filename, const std::map<std::string, EnumDef>& enums) {
        std::string file_path = filename + "/enums.json";
        nlohmann::json j;
        for (const auto& pair : enums) {
            const EnumDef& enumValues = pair.second;
            nlohmann::json enumJson;
            enumJson["Name"] = pair.first;
            enumJson["Values"] = enumValues.Constants;
            enumJson["File"] = enumValues.File;

            j.push_back(enumJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

    /*
        Read input file that contains the functions to analyze
        and store them in the HarnessFunctionNames set
    */
    std::set<std::pair<std::string, std::string>> processHarnessFunctions(const std::string& filename) {
        std::ifstream file(filename);

        if (!file.is_open()) {
            std::cerr << "Error opening file: " << filename << std::endl;
            exit(1);
        }
        HarnessFunctions.clear();
        std::string line;
        std::string function;
        std::string guid = "";
        while (std::getline(file, line)) {
            // Remove leading and trailing whitespace
            line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](int ch) { return !std::isspace(ch); }));
            line.erase(std::find_if(line.rbegin(), line.rend(), [](int ch) { return !std::isspace(ch); }).base(), line.end());

            // Remove extra whitespace between words
            line = std::regex_replace(line, std::regex("\\s+"), " ");

            // stip any line that containes a [ or a ]
            if (line.find('[') != std::string::npos || line.find(']') != std::string::npos) {
                continue;
            }

            // Remove the protocol name from the function name
            // e.g. gEdkiiIoMmuProtocolGuid:Map -> Map
            size_t colonIndex = line.find(':');
            if (colonIndex != std::string::npos) {
                function = line.substr(colonIndex + 1);
                guid = line.substr(0, colonIndex);
            }
            else
            {
                function = line;
            }

            if (!line.empty()) {
                HarnessFunctions.insert(std::make_pair(function, guid));
                function.clear();
                guid = "";
            }
        }

        file.close();
        return HarnessFunctions;
    }

    void GenerateCallGraph(const std::string& filename, const std::map<std::string, std::set<std::string>>& call_graph) {
        std::string file_path = filename + "/call-graph.dot";
        std::ofstream file(file_path);
        file << "digraph G {\n";
        // Add all of the nodes to the graph
        for (const auto& call : call_graph) {
            file << "\t\"" << call.first << "\";\n";
        }

        // Add all the edges to the graph
        for (const auto& call : call_graph) {
            for (const auto& callSite : call.second) {
                file << "\t\"" << call.first << "\" -> \"" << callSite << "\";\n";
            }
        }
        file << "}\n";
        file.close();
    }

    void outputCastMap(const std::string &filename, const std::map<std::string, std::set<std::string>> &castMap) {
        std::string file_path = filename + "/cast-map.json";
        nlohmann::json j;
        for (const auto& pair : castMap) {
            nlohmann::json castJson;
            castJson["Type"] = pair.first;
            castJson["Casts"] = pair.second;
            j.push_back(castJson);
        }
        std::ofstream file(file_path);
        file << j.dump(4); 
        file.close();
    }

}; // FileOps namespace

#endif