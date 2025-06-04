# Script: run_project.ps1
# Сборка и запуск проекта менеджера паролей

# Получаем полный путь к текущей директории
$CURRENT_DIR = (Get-Location).Path

# 1. Проверка наличия собранных файлов
$DEBUG_BUILD_DIR = Join-Path -Path $CURRENT_DIR -ChildPath "build\Desktop_Qt_6_8_3_MSVC2022_64bit-Debug"
$RELEASE_BUILD_DIR = Join-Path -Path $CURRENT_DIR -ChildPath "build\Desktop_Qt_6_8_3_MSVC2022_64bit-Release"

$BUILD_DIR = $null
if (Test-Path (Join-Path -Path $RELEASE_BUILD_DIR -ChildPath "LR1.exe")) {
    Write-Host "Найдена Release сборка" -ForegroundColor Green
    $BUILD_DIR = $RELEASE_BUILD_DIR
} elseif (Test-Path (Join-Path -Path $DEBUG_BUILD_DIR -ChildPath "LR1.exe")) {
    Write-Host "Найдена Debug сборка" -ForegroundColor Yellow
    $BUILD_DIR = $DEBUG_BUILD_DIR
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
python $CURRENT_DIR\generate_vault.py 1234
Copy-Item "$CURRENT_DIR\vault.enc" -Destination $BUILD_DIR -Force
Write-Host "Файл данных сгенерирован и скопирован в директорию сборки" -ForegroundColor Green

# 3. Проверка наличия программы-протектора
$PROTECTOR_PATH = Join-Path -Path $BUILD_DIR -ChildPath "PasswordManagerProtector.exe"
if (-not (Test-Path $PROTECTOR_PATH)) {
    Write-Host "Предупреждение: Программа-протектор не найдена!" -ForegroundColor Yellow
    Write-Host "Запуск будет выполнен без защиты от отладки" -ForegroundColor Yellow
}

# 4. Проверка наличия библиотек Qt
$QT_DLL = Join-Path -Path $BUILD_DIR -ChildPath "Qt6Cored.dll"
if (-not (Test-Path $QT_DLL) -and (-not (Test-Path $QT_DLL.Replace("d.dll", ".dll")))) {
    Write-Host "Предупреждение: Библиотеки Qt не найдены!" -ForegroundColor Yellow
    Write-Host "Выполняем копирование библиотек Qt..." -ForegroundColor Green
    
    $QT_DIR = "C:\Qt\6.8.3\msvc2022_64"
    if (-not (Test-Path $QT_DIR)) {
        $QT_DIR = "C:\Qt\6.8.2\msvc2022_64"  # Проверяем альтернативную версию Qt
    }
    
    if (Test-Path $QT_DIR) {
        & "$QT_DIR\bin\windeployqt.exe" "$BUILD_DIR\LR1.exe"
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

Push-Location $BUILD_DIR
if (Test-Path $PROTECTOR_PATH) {
    Write-Host "Запуск с защитой от отладки..." -ForegroundColor Green
    & $PROTECTOR_PATH
} else {
    Write-Host "Запуск без защиты от отладки..." -ForegroundColor Yellow
    & "$BUILD_DIR\LR1.exe"
}
Pop-Location
