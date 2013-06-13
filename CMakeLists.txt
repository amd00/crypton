
cmake_minimum_required(VERSION 2.8)	 # Проверка версии CMake.
                                        # Если версия установленой программы
                                        # старее указаной, произайдёт аварийный выход.

project(crypton)			# Название проекта

set(SOURCE_LIB cryptographer.cpp  passwordgen.cpp  randomgen.cpp)
set(HEADER_LIB cryptographer.h  passwordgen.h  randomgen.h)

add_library(cryptonS STATIC ${SOURCE_LIB})	# Создание статической библиотеки с именем foo
add_library(crypton SHARED ${SOURCE_LIB})	# Создание динамической библиотеки с именем foo

set_target_properties(crypton  PROPERTIES
	  VERSION 1.0.0
	  SOVERSION 1.0
	)
	
INSTALL(TARGETS cryptonS crypton
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
)

INSTALL(FILES ${HEADER_LIB} 
	DESTINATION include)

# add_executable(main ${SOURCE_EXE})	# Создает исполняемый файл с именем main

# target_link_libraries(main foo)		# Линковка программы с библиотекой