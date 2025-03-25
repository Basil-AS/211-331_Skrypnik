cmake_minimum_required(VERSION 3.16)

project(PasswordManagerProtector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Для Windows добавляем библиотеку advapi32 для функций Windows API
if(WIN32)
    link_libraries(advapi32)
endif()

add_executable(PasswordManagerProtector
    PasswordManagerProtector.cpp
)

set_target_properties(PasswordManagerProtector PROPERTIES
    WIN32_EXECUTABLE FALSE
)

# Определяем расположение основного приложения
set(TARGET_DIR "${CMAKE_BINARY_DIR}")

# Команда, копирующая исполняемый файл в директорию основного проекта
add_custom_command(TARGET PasswordManagerProtector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${TARGET_DIR}/PasswordManagerProtector"
    COMMAND ${CMAKE_COMMAND} -E copy 
            "$<TARGET_FILE:PasswordManagerProtector>" 
            "${TARGET_DIR}/PasswordManagerProtector/$<TARGET_FILE_NAME:PasswordManagerProtector>"
    COMMENT "Копирование PasswordManagerProtector.exe в директорию сборки основного проекта"
)
set(POSSIBLE_BUILD_DIRS 
    "${CMAKE_SOURCE_DIR}/../build/Desktop_Qt_6_8_3_MSVC2022_64bit-Release"
    "${CMAKE_SOURCE_DIR}/../build/Desktop_Qt_6_8_3_MSVC2022_64bit-Debug"
    "${CMAKE_SOURCE_DIR}/../build/Desktop_Qt_6_8_2_MSVC2022_64bit-Release"
    "${CMAKE_SOURCE_DIR}/../build/Desktop_Qt_6_8_2_MSVC2022_64bit-Debug"
    "${CMAKE_BINARY_DIR}"
)

# Поиск директории с основным приложением
set(TARGET_DIR "")
foreach(BUILD_DIR ${POSSIBLE_BUILD_DIRS})
    if(EXISTS "${BUILD_DIR}")
        message(STATUS "Найдена директория сборки: ${BUILD_DIR}")
        set(TARGET_DIR "${BUILD_DIR}")
        break()
    endif()
endforeach()

if(TARGET_DIR STREQUAL "")
    message(WARNING "Не найдена директория сборки основного приложения. Исполняемый файл будет скопирован только в локальную директорию.")
    set(TARGET_DIR "${CMAKE_BINARY_DIR}")
endif()

# Копируем исполняемый файл в директорию сборки основного приложения после сборки
add_custom_command(TARGET PasswordManagerProtector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Копирование PasswordManagerProtector.exe в директорию сборки: ${TARGET_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy 
        $<TARGET_FILE:PasswordManagerProtector>
        "${TARGET_DIR}/PasswordManagerProtector.exe"
    COMMENT "Копирование PasswordManagerProtector.exe в директорию сборки основного приложения"
)

# Копирование также в корневую директорию сборки, если она отличается
if(NOT "${TARGET_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    add_custom_command(TARGET PasswordManagerProtector POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy 
            $<TARGET_FILE:PasswordManagerProtector>
            "${CMAKE_BINARY_DIR}/PasswordManagerProtector.exe"
        COMMENT "Копирование PasswordManagerProtector.exe в локальную директорию сборки"
    )
endif()
