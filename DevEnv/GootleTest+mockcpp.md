目标：基于GoogleTest + mockcpp单元测试环境



1. 基于WSL2安装Ubuntu 20.04开发环境

   详见Develop Environment.md

   python --version为Python 2.7.18

   

2. 下载googletest和mockcpp

   googletest：https://github.com/google/googletest/archive/refs/tags/release-1.11.0.tar.gz

   mockcpp：https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/mockcpp/mockcpp-2.6.tar.gz

   

3. 编译googletest

   tar -xzvf googletest-release-1.11.0.tar.gz && cd googletest-release-1.11.0 && cmake . && make

   *将lib/libgtest.a、lib/libgmock.a、lib/libgmock_main.a、lib/libgtest_main.a和googletest/include/gtest/gtest.h拷贝到目标工程

   

4. 编译mockcpp

   tar -xzvf mockcpp-2.6.tar.gz && cd mockcpp

   处理C++11中的static_assert，与mockcpp中的相冲突

   vim include/mockcpp/mockcpp.h

    58 #if __cplusplus < 199711L
    59 template <bool condition>
    60 struct static_assert
    61 {
    62     typedef int static_assert_failure[condition ? 1 : -1];
    63 };
    64 #endif // __cplusplus

   cmake . && make

   *将src/libmockcpp.a、include/mockcpp/mockcpp.h和include/mockcpp/mockcpp.hpp拷贝到目标目录

   

5. 拷贝至目标工程

   cp -rf googletest-release-1.11.0 <dest_dir>

   cp -rf mockcpp <dest_dir>

   

   头文件包含目录新增：mockcpp/include，mockcpp/3rdparty，googletest-release-1.11.0/googletest/include

   链接库文件引用新增：googletest-release-1.11.0/lib/libgtest.a，mockcpp/src/libmockcpp.a，pthread

   

6. 编写测试文件

   测试源文件包含头文件新增：

   \#include "gtest/gtest.h"

   \#include "mockcpp/mockcpp.hpp"

   

   运行测试用例：

   testing::InitGoogleTest(&argc, argv);

   RUN_ALL_TESTS();
