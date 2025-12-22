# ============================================================================
# Examples CMakeLists.txt
# ============================================================================

# Helper function - 用于确定可执行文件应该放在哪里
function(setup_example_target target_name)
    # Add src directory to include path
    target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

    # 链接核心库
    target_link_libraries(${target_name} PRIVATE elf_got_core)

    # 设置输出目录
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples
    )
endfunction()

# ============================================================================
# Example executables
# ============================================================================

# 基本的 ELF 解析示例
add_executable(basic_parse basic_parse.cpp)
setup_example_target(basic_parse)

# 运行时 GOT 检测示例
add_executable(runtime_check runtime_check.cpp)
setup_example_target(runtime_check)

# GOT hook 演示和检测示例
add_executable(got_hook_demo got_hook_demo.cpp)
setup_example_target(got_hook_demo)
