
file(GLOB_RECURSE HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

add_executable(riscv-dfa
        main.cpp
        ${HEADERS})

target_link_libraries(riscv-dfa rv32 platform-common ${Boost_LIBRARIES} ${SystemC_LIBRARIES} pthread)

INSTALL(TARGETS riscv-dfa RUNTIME DESTINATION bin)
