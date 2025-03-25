#!/usr/bin/env pwsh
# Script: clean_project.ps1
# Очистка проекта от временных файлов и артефактов сборки

Write-Host "Начинаем очистку проекта..." -ForegroundColor Cyan

# Исходная директория проекта
$PROJECT_DIR = (Get-Location).Path
Set-Location $PROJECT_DIR

# Список важных файлов и директорий, которые нужно сохранить
$KEEP_FILES = @(
    "authwindow.cpp",
    "authwindow.h",
    "authwindow.ui",
    "CMakeLists.txt",
    "credentialsmodel.cpp",
    "credentialsmodel.h",
    "generate_vault.py",
    "main.cpp",
    "mainwindow.cpp",
    "mainwindow.h",
    "mainwindow.ui",
    "README.md",
    "run_project.ps1",
    "clean_project.ps1",
    "deploy_dependencies.ps1",
    "PasswordManagerProtector\CMakeLists.txt",
    "PasswordManagerProtector\PasswordManagerProtector.cpp"
)

# 1. Закрываем возможные процессы, которые могут блокировать файлы
Write-Host "Проверка и закрытие процессов, которые могут блокировать файлы..." -ForegroundColor Green
$processes = Get-Process -Name "LR1", "PasswordManagerProtector" -ErrorAction SilentlyContinue
if ($processes) {
    Write-Host "Обнаружены запущенные процессы приложения. Закрываем их..." -ForegroundColor Yellow
    $processes | ForEach-Object { 
        Write-Host "Завершение процесса: $($_.Name) (PID: $($_.Id))" -ForegroundColor Yellow
        $_ | Stop-Process -Force 
    }
    # Дадим время на освобождение файлов
    Start-Sleep -Seconds 1
}

# 2. Очистка корневой директории проекта от временных файлов
Write-Host "Очистка корневой директории проекта от временных файлов..." -ForegroundColor Green
Get-ChildItem -Path $PROJECT_DIR -File | Where-Object {
    $KEEP_FILES -notcontains $_.Name -and 
    -not $_.Name.StartsWith(".") -and 
    -not ($_.Name -eq "clean_project.ps1") -and
    -not ($_.Extension -eq ".md")
} | ForEach-Object {
    Write-Host "Удаление файла: $($_.Name)" -ForegroundColor Yellow
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
}

# 3. Очистка директорий сборки и временных файлов
Write-Host "Очистка директорий сборки и временных файлов..." -ForegroundColor Green

# Перечисляем шаблоны для удаления
$TEMP_PATTERNS = @(
    "*.user",
    "*.obj",
    "*.ilk",
    "*.pdb",
    "*.exe",
    "*.dll",
    "vault.enc",
    "moc_*",
    "ui_*",
    "qrc_*",
    "*.o",
    "*.a",
    "*.so",
    "*.dylib"
)

# Удаляем файлы по шаблонам
foreach ($pattern in $TEMP_PATTERNS) {
    Get-ChildItem -Path $PROJECT_DIR -Filter $pattern -Recurse -File | ForEach-Object {
        Write-Host "Удаление: $($_.FullName)" -ForegroundColor Yellow
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

# 4. Сохраняем директорию PasswordManagerProtector, но удаляем из неё только временные файлы
$protectorDir = Join-Path -Path $PROJECT_DIR -ChildPath "PasswordManagerProtector"
if (Test-Path $protectorDir) {
    Write-Host "Очистка директории PasswordManagerProtector..." -ForegroundColor Green
    
    # Создаем список файлов, которые нужно сохранить
    $protectorKeepFiles = @("CMakeLists.txt", "PasswordManagerProtector.cpp")
    
    # Получаем все файлы в директории протектора
    Get-ChildItem -Path $protectorDir -Recurse -File | Where-Object {
        # Проверяем, не входит ли файл в список исключений
        -not ($protectorKeepFiles -contains $_.Name)
    } | ForEach-Object {
        Write-Host "Удаление: $($_.Name)" -ForegroundColor Yellow
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
    
    # Дополнительно проверяем наличие критических файлов
    foreach ($file in $protectorKeepFiles) {
        $filePath = Join-Path -Path $protectorDir -ChildPath $file
        if (-not (Test-Path $filePath)) {
            Write-Host "Внимание: Критически важный файл не найден: $file" -ForegroundColor Red
            Write-Host "Пожалуйста, восстановите этот файл из резервной копии." -ForegroundColor Red
        } else {
            Write-Host "Сохранен файл: $file" -ForegroundColor Green
        }
    }
}

# 5. Удаляем директории сборки (с обработкой ошибок, если файлы заблокированы)
$buildDirs = @(
    (Join-Path -Path $PROJECT_DIR -ChildPath "build")
)

foreach ($dir in $buildDirs) {
    if (Test-Path $dir) {
        Write-Host "Попытка удаления директории сборки: $dir" -ForegroundColor Yellow
        
        # Проверяем, содержит ли директория исполняемые файлы
        $exeFiles = Get-ChildItem -Path $dir -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
        if ($exeFiles.Count -gt 0) {
            Write-Host "В директории $dir найдены исполняемые файлы:" -ForegroundColor Yellow
            $exeFiles | ForEach-Object {
                Write-Host " - $($_.Name)" -ForegroundColor Yellow
            }
            Write-Host "Продолжить удаление? (Y/N)" -ForegroundColor Yellow
            $confirm = Read-Host
            if ($confirm -ne "Y" -and $confirm -ne "y") {
                Write-Host "Удаление директории $dir отменено пользователем" -ForegroundColor Cyan
                continue
            }
        }
        
        # Пробуем удалить с обработкой ошибок
        try {
            Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
            Write-Host "Директория $dir успешно удалена" -ForegroundColor Green
        }
        catch {
            Write-Host "Не удалось полностью удалить директорию $dir" -ForegroundColor Red
            Write-Host "Причина: $_" -ForegroundColor Red
            Write-Host "Попытка удаления доступных файлов..." -ForegroundColor Yellow
            
            # Удаляем максимум возможных файлов
            Get-ChildItem -Path $dir -Recurse -File | ForEach-Object {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                }
                catch {}
            }
            
            Write-Host "Примечание: возможно, некоторые файлы заблокированы другими процессами" -ForegroundColor Yellow
            Write-Host "Закройте все связанные приложения и попробуйте снова" -ForegroundColor Yellow
        }
    }
}

# 6. Создаем минимальную структуру директорий, если они были удалены
$protectorDir = Join-Path -Path $PROJECT_DIR -ChildPath "PasswordManagerProtector"
if (-not (Test-Path $protectorDir)) {
    Write-Host "Создание директории PasswordManagerProtector..." -ForegroundColor Green
    New-Item -Path $protectorDir -ItemType Directory | Out-Null
    
    # Если файл CMakeLists.txt для протектора был удален, пересоздаем его
    $protectorCmake = Join-Path -Path $protectorDir -ChildPath "CMakeLists.txt"
    if (-not (Test-Path $protectorCmake)) {        $cmakeContent = @"
cmake_minimum_required(VERSION 3.16)

project(PasswordManagerProtector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Установка пути к исходному файлу (если он находится в родительской директории)
set(PROTECTOR_SOURCE_PATH "\${CMAKE_CURRENT_SOURCE_DIR}/../PasswordManagerProtector.cpp")

# Проверяем наличие файла
if(NOT EXISTS \${PROTECTOR_SOURCE_PATH})
    message(FATAL_ERROR "Файл PasswordManagerProtector.cpp не найден по пути: \${PROTECTOR_SOURCE_PATH}")
endif()

# Для Windows добавляем библиотеку advapi32 для функций Windows API
if(WIN32)
    link_libraries(advapi32)
endif()

add_executable(PasswordManagerProtector
    \${PROTECTOR_SOURCE_PATH}
)

set_target_properties(PasswordManagerProtector PROPERTIES
    WIN32_EXECUTABLE FALSE
)

# Копируем исполняемый файл в директорию сборки основного приложения после сборки
add_custom_command(TARGET PasswordManagerProtector POST_BUILD
    COMMAND \${CMAKE_COMMAND} -E copy 
        \$<TARGET_FILE:PasswordManagerProtector>
        \${CMAKE_CURRENT_SOURCE_DIR}/../build/Desktop_Qt_6_8_3_MSVC2022_64bit-\$<CONFIG>/PasswordManagerProtector.exe
    COMMENT "Копирование PasswordManagerProtector.exe в директорию сборки основного приложения"
)
"@

        Set-Content -Path $protectorCmake -Value $cmakeContent
        Write-Host "Создан файл конфигурации для протектора: $protectorCmake" -ForegroundColor Green
    }
}

# 7. Создание нового скрипта запуска
$RUN_SCRIPT = @"
# Script: run_project.ps1
# Сборка и запуск проекта менеджера паролей

# Получаем полный путь к текущей директории
`$CURRENT_DIR = (Get-Location).Path

# 1. Проверка наличия собранных файлов
`$DEBUG_BUILD_DIR = Join-Path -Path `$CURRENT_DIR -ChildPath "build\Desktop_Qt_6_8_3_MSVC2022_64bit-Debug"
`$RELEASE_BUILD_DIR = Join-Path -Path `$CURRENT_DIR -ChildPath "build\Desktop_Qt_6_8_3_MSVC2022_64bit-Release"

`$BUILD_DIR = `$null
if (Test-Path (Join-Path -Path `$RELEASE_BUILD_DIR -ChildPath "LR1.exe")) {
    Write-Host "Найдена Release сборка" -ForegroundColor Green
    `$BUILD_DIR = `$RELEASE_BUILD_DIR
} elseif (Test-Path (Join-Path -Path `$DEBUG_BUILD_DIR -ChildPath "LR1.exe")) {
    Write-Host "Найдена Debug сборка" -ForegroundColor Yellow
    `$BUILD_DIR = `$DEBUG_BUILD_DIR
} else {
    Write-Host "Ошибка: Сборка проекта не найдена!" -ForegroundColor Red
    Write-Host "Пожалуйста, сначала соберите проект в Qt Creator:" -ForegroundColor Red
    Write-Host "1. Откройте CMakeLists.txt в Qt Creator" -ForegroundColor Yellow
    Write-Host "2. Выберите конфигурацию (Debug или Release)" -ForegroundColor Yellow  
    Write-Host "3. Нажмите кнопку Build (Ctrl+B)" -ForegroundColor Yellow
    exit 1
}

# 2. Генерация зашифрованного хранилища паролей
Write-Host "Генерация файла данных..." -ForegroundColor Green
python `$CURRENT_DIR\generate_vault.py 1234
Copy-Item "`$CURRENT_DIR\vault.enc" -Destination `$BUILD_DIR -Force
Write-Host "Файл данных сгенерирован и скопирован в директорию сборки" -ForegroundColor Green

# 3. Проверка наличия программы-протектора
`$PROTECTOR_PATH = Join-Path -Path `$BUILD_DIR -ChildPath "PasswordManagerProtector.exe"
if (-not (Test-Path `$PROTECTOR_PATH)) {
    Write-Host "Предупреждение: Программа-протектор не найдена!" -ForegroundColor Yellow
    Write-Host "Запуск будет выполнен без защиты от отладки" -ForegroundColor Yellow
}

# 4. Проверка наличия библиотек Qt
`$QT_DLL = Join-Path -Path `$BUILD_DIR -ChildPath "Qt6Cored.dll"
if (-not (Test-Path `$QT_DLL) -and (-not (Test-Path `$QT_DLL.Replace("d.dll", ".dll")))) {
    Write-Host "Предупреждение: Библиотеки Qt не найдены!" -ForegroundColor Yellow
    Write-Host "Выполняем копирование библиотек Qt..." -ForegroundColor Green
    
    `$QT_DIR = "C:\Qt\6.8.3\msvc2022_64"
    if (-not (Test-Path `$QT_DIR)) {
        `$QT_DIR = "C:\Qt\6.8.2\msvc2022_64"  # Проверяем альтернативную версию Qt
    }
    
    if (Test-Path `$QT_DIR) {
        & "`$QT_DIR\bin\windeployqt.exe" "`$BUILD_DIR\LR1.exe"
    } else {
        Write-Host "Ошибка: Не удалось найти директорию Qt!" -ForegroundColor Red
        Write-Host "Пожалуйста, скопируйте необходимые библиотеки Qt вручную" -ForegroundColor Red
    }
}

# 5. Запуск приложения
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Запуск менеджера паролей" -ForegroundColor Cyan
Write-Host "PIN-код для входа: 1234" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Cyan

Push-Location `$BUILD_DIR
if (Test-Path `$PROTECTOR_PATH) {
    Write-Host "Запуск с защитой от отладки..." -ForegroundColor Green
    & `$PROTECTOR_PATH
} else {
    Write-Host "Запуск без защиты от отладки..." -ForegroundColor Yellow
    & "`$BUILD_DIR\LR1.exe"
}
Pop-Location
"@

$RUN_SCRIPT_PATH = Join-Path -Path $PROJECT_DIR -ChildPath "run_project.ps1"
Set-Content -Path $RUN_SCRIPT_PATH -Value $RUN_SCRIPT
Write-Host "Создан скрипт запуска: run_project.ps1" -ForegroundColor Green

# 8. Финальное сообщение
Write-Host "`nПроект успешно очищен!" -ForegroundColor Green
Write-Host "Для сборки проекта:" -ForegroundColor Cyan
Write-Host "1. Откройте основной проект в Qt Creator: $PROJECT_DIR\CMakeLists.txt" -ForegroundColor Yellow
Write-Host "2. Соберите его (Ctrl+B)" -ForegroundColor Yellow
Write-Host "3. Откройте проект программы-протектора: $PROJECT_DIR\PasswordManagerProtector\CMakeLists.txt" -ForegroundColor Yellow
Write-Host "4. Соберите его (Ctrl+B)" -ForegroundColor Yellow
Write-Host "5. Запустите проект с защитой используя скрипт run_project.ps1" -ForegroundColor Yellow
