cmake_minimum_required(VERSION 3.22)

project(CNetherNet)

if(TARGET nethernet)
	return()
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(NO_EXAMPLES TRUE CACHE BOOL "" FORCE)
set(NO_TESTS TRUE CACHE BOOL "" FORCE)
set(NO_MEDIA TRUE CACHE BOOL "" FORCE)

add_subdirectory(${PROJECT_SOURCE_DIR}/third_party/libdatachannel)
find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE NETHERNET_FILES ${PROJECT_SOURCE_DIR}/nethernet/*.c)

add_library(nethernet STATIC
	${NETHERNET_FILES}
	${PROJECT_SOURCE_DIR}/third_party/mongoose/mongoose.c
)

target_include_directories(nethernet
	PUBLIC
		${PROJECT_SOURCE_DIR}
	PRIVATE
		${PROJECT_SOURCE_DIR}/third_party/mongoose
)

if(MSVC)
	target_compile_options(nethernet PUBLIC /experimental:c11atomics)
endif()

target_compile_definitions(nethernet PRIVATE
	MG_TLS=MG_TLS_OPENSSL
	MG_MAX_RECV_SIZE=262144
	$<$<CONFIG:Debug>:_DEBUG>
)
if(WIN32)
	target_compile_definitions(nethernet PRIVATE
		WIN32_LEAN_AND_MEAN
		NOMINMAX
	)
	target_link_libraries(nethernet PRIVATE ws2_32 bcrypt)
endif()

target_link_libraries(nethernet PRIVATE datachannel-static OpenSSL::SSL OpenSSL::Crypto)

if(BUILD_NETHERNET_TESTS)
	add_executable(ServerTest ${PROJECT_SOURCE_DIR}/tests/server_test.c)
	target_link_libraries(ServerTest PRIVATE nethernet)

	add_executable(ClientTest ${PROJECT_SOURCE_DIR}/tests/client_test.c)
	target_link_libraries(ClientTest PRIVATE nethernet)
endif()
