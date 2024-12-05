# tutorial/CMakeLists.txt
# tutorial1 executable

# myApp executable
add_executable(myApp myApp.cpp DataProcessor.cpp)
if (BUILD_STATIC)
    target_link_libraries(myApp
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
else()
    target_link_libraries(myApp
        PUBLIC OPENFHEcore
        PUBLIC OPENFHEpke
        PUBLIC OPENFHEbinfhe
    )
endif()