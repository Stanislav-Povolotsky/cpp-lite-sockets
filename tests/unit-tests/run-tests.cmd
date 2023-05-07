@echo off
set test_archs=Win32 x64
set test_cfg_types=Debug Release
for %%c in (%test_cfg_types%) do (
  for %%a in (%test_archs%) do (
    call :build_and_run_tests %%a %%c || exit /b 1
  )
)
echo Done.
exit /b 0

:build_and_run_tests
set arch=%1
set cfg_type=%2
set build_folder=build\windows\%arch%\%cfg_type%
echo Running tests ^(platform: windows; arch: %arch%; configuration: %cfg_type%^)
cmake -A %arch% -S . -B "%build_folder%" && cmake --build "%build_folder%" --config "%cfg_type%" && ".\%build_folder%\%cfg_type%\unit_tests.exe"
if ERRORLEVEL 1 (
  echo Error running tests ^(platform: windows; arch: %arch%; configuration: %cfg_type%^)
  exit /b 1
)
exit /b 0