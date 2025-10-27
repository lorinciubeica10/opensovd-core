:: OpenSOVD Core build script
::
::

:: Don't show executed commands
@echo off

:: Variables are gone after termination of this script
setlocal EnableDelayedExpansion

:: Set required variables
set ROOT_DIR=%~dp0
set OUT_DIR=%ROOT_DIR%target\generated\sovd-api
:: Openapi generator has issues with backslashes in path
set OUT_DIR=%OUT_DIR:\=/%
set SPEC_FILE=%ROOT_DIR%sovd-interfaces\sovd-api.yaml
:: Openapi generator has issues with backslashes in path
set SPEC_FILE=%SPEC_FILE:\=/%
set GENERATOR_DIR=%ROOT_DIR%target
set GENERATOR_VERSION=7.16.0
set GENERATOR_JAR=%GENERATOR_DIR%\openapi-generator-cli-%GENERATOR_VERSION%.jar
set GENERATOR_URL=https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/%GENERATOR_VERSION%/openapi-generator-cli-%GENERATOR_VERSION%.jar
:: Search git executable
for /f %%a in ('where git 2^> NUL') do (
  set GIT_EXE=%%a
)
if not defined GIT_EXE (
  echo ERROR: Git is not installed
  exit /b 1
)
:: Build path to sed executable
set SED_EXE=%GIT_EXE:mingw64\bin\git.exe=usr\bin\sed.exe%

:: Allowed commands
for %%a in (all clean codegen help validate) do set %%a=1
:: No command is given
if "%~1"=="" (
  goto :all
)
:: Progress command line parameter
if defined %1 (
  goto :%1 
) else (
  goto :help
)
exit /b 1

:all
  echo ==^> Starting SOVD build process...
  call :codegen
  if errorlevel 1 (
    exit /b 1
  )
  echo ==^> Building SOVD server...
  cargo build
  if errorlevel 1 (
    echo Error: Cargo build failed!
    exit /b 1
  )
  echo Build completed successfully.
  exit /b 0

:clean
  echo ==^> Cleaning generated rust code...
  rmdir /Q /S "%OUT_DIR%" 2> NUL
  echo Clean complete.
  exit /b 0

:codegen
  echo ==^> Starting SOVD code generation
  echo Project root: %ROOT_DIR%
  :: Show openapi generator version / check, if openapi generator needs to be 
  :: downloaded
  echo|set /p="OpenAPI Generator Version "
  java -jar "%GENERATOR_JAR%" version
  if errorlevel 1 (
    call :get_generator
    if errorlevel 1 (
      exit /b 1
    )
  )
  java -jar "%GENERATOR_JAR%" generate -i "%SPEC_FILE%" -g rust-axum -o "%OUT_DIR%" --additional-properties=packageName=sovd-api
  if errorlevel 1 (
    exit /b 1
  )
  echo Generated Rust code at %OUT_DIR%
  :: Patch generated code
  :: It seems, that openapi generator isn't generating  validator implementation 
  :: for self defined byte array type
  echo. >> "%OUT_DIR%\src\types.rs"
  echo impl validator::Validate for ByteArray { >> "%OUT_DIR%\src\types.rs"
  echo     fn validate(^&self) -^> std::result::Result^<(), validator::ValidationErrors^> { >> "%OUT_DIR%\src\types.rs"
  echo         Ok(()) >> "%OUT_DIR%\src\types.rs"
  echo     } >> "%OUT_DIR%\src\types.rs"
  echo } >> "%OUT_DIR%\src\types.rs"
  :: Fix http return code in generated server code in some error cases
  "%SED_EXE%" -i 's/response.status(0)/response.status(200)/g' "%OUT_DIR%\src\server\mod.rs"
  exit /b 0

:get_generator
  if not exist "%GENERATOR_DIR%" (
    mkdir "%GENERATOR_DIR%"
  )
  echo Downloading OpenAPI generator version %GENERATOR_VERSION%...
  curl "%GENERATOR_URL%" -o "%GENERATOR_JAR%"
  if errorlevel 1 (
    echo Error: Failed to download OpenAPI Generator CLI.
    exit /b 1
  )
  echo Downloaded openapi-generator-cli_%GENERATOR_VERSION%.jar to %GENERATOR_JAR%
  exit /b 0

:help
  echo Usage: %~n0 ^<command^>
  echo.
  echo Available commands:
  echo  all       Generate code and build sovd server
  echo  clean     Remove build artifacts and generated code
  echo  codegen   Run OpenAPI code generator
  echo  help      Show this help message
  echo  validate  Validate OpenAPI schema
  exit /b 0

:validate
  echo ==^> Validating OpenAPI schema
  :: Show openapi generator version / check, if openapi generator needs to be 
  :: downloaded
  echo|set /p="OpenAPI Generator Version "
  java -jar "%GENERATOR_JAR%" version
  if errorlevel 1 (
    call :get_generator
    if errorlevel 1 (
      exit /b 1
    )
  )
  java -jar "%GENERATOR_JAR%" validate -i "%SPEC_FILE%"
  if errorlevel 1 (
    exit /b 1
  )
  exit /b 0