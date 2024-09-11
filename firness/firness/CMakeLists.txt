add_executable(firness
  FCP.cpp
  )

llvm_map_components_to_libnames(llvm_libs support core irreader)

target_link_libraries(firness
  PRIVATE
  nlohmann_json::nlohmann_json
  clangAST
  clangASTMatchers
  clangBasic
  clangFrontend
  clangSerialization
  clangTooling
  )

  install(TARGETS firness RUNTIME DESTINATION bin) 