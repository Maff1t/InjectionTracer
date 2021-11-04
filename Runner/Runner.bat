@echo off
rem This script is to be used from the context menu

rem PIN_DIR is your root directory of Intel Pin
set PIN_DIR=C:\pin\

rem ARGS_* are the arguments passed to InjectionTracer
set ARGS_VERBOSE="1"

set EXE_ARGS=""

set TARGET_APP=%~1
set PE_TYPE=%~2
set IS_ADMIN=%~3

if "%TARGET_APP%"=="" goto display_args
if "%PE_TYPE%"=="" goto display_args
goto run_it
:display_args
echo Run a process with InjectionTracer
echo Required args: [target app] [pe type: dll or exe]
pause
goto end

:run_it

rem PIN_TOOL_DIR is your directory with this script and the Pin Tools
set PIN_TOOL_DIR=%PIN_DIR%\source\tools\InjectionTracer

set PINTOOL32=%PIN_TOOL_DIR%\Release\InjectionTracer.dll
rem This script is to be used from the context menu
set PINTOOL64=%PIN_TOOL_DIR%\x64\Release\InjectionTracer.dll
set PINTOOL=%PINTOOL32%

set DLL_LOAD32=%PIN_TOOL_DIR%\Runner\dll_load32.exe
set DLL_LOAD64=%PIN_TOOL_DIR%\Runner\dll_load64.exe

%PIN_TOOL_DIR%\Runner\pe_check.exe "%TARGET_APP%"
if %errorlevel% == 32 (
	echo 32bit selected
	set PINTOOL=%PINTOOL32%
	set DLL_LOAD=%DLL_LOAD32%
)
if %errorlevel% == 64 (
	echo 64bit selected
	set PINTOOL=%PINTOOL64%
	set DLL_LOAD=%DLL_LOAD64%
)

if [%IS_ADMIN%] == [A] (
	echo Elevation requested
)

set ADMIN_CMD=%PIN_TOOL_DIR%\Runner\sudo.vbs
;rem "Trace EXE"
if [%PE_TYPE%] == [exe] (
	goto run_exe
)
;rem "Trace DLL"
if [%PE_TYPE%] == [dll] (
	goto run_dll
)

:run_exe
set /P EXE_ARGS="[+] Insert executable arguments (leave blank if there are no arguments): "
set EXE_CMD=%PIN_DIR%\pin.exe -t %PINTOOL% -verbose %ARGS_VERBOSE% -- "%TARGET_APP%" "%EXE_ARGS%"
echo  I will run %TARGET_APP% %EXE_ARGS%
if [%IS_ADMIN%] == [A] (
	%ADMIN_CMD% %EXE_CMD%
) else (
	%EXE_CMD%
)
goto finish

:run_dll
set /P DLL_EXPORTS="[+] Insert DLL export to call, in format [name1];[name2] or [#ordinal1];[#ordinal2] (Leave empty to call DLL_Main): "
set DLL_CMD=%PIN_DIR%\pin.exe -t %PINTOOL% -verbose %ARGS_VERBOSE% -- "%DLL_LOAD%" "%TARGET_APP%" %DLL_EXPORTS%
if [%IS_ADMIN%] == [A] (
	%ADMIN_CMD% %DLL_CMD%
) else (
	%DLL_CMD%
)

:finish
if [%IS_ADMIN%] == [A] (
	rem In Admin mode, a new console should be created. Pause only if it failed, in order to display the error:
	if NOT %ERRORLEVEL% EQU 0 pause
) else (
	if %ERRORLEVEL% EQU 0 echo [OK] PIN tracing finished: the traced application terminated.
	rem Pausing script after the application is executed is useful to see all eventual printed messages and for troubleshooting
	pause
)

:end