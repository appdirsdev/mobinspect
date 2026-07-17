@echo off 
echo =======================MobInspect Clean Script for Windows=======================
echo Running this script will delete the Scan database, all files uploaded and generated.
SET mobinspect_home="%userprofile%\.MobInspect"
SET mypath=%~dp0
echo %mypath:~0,-1%
IF "%~1"=="y" (
echo Deleting all uploads
rmdir "mobinspect\uploads" /q /s >nul 2>&1
echo Deleting all downloads
rmdir "mobinspect\downloads" /q /s >nul 2>&1
echo Deleting Static Analyzer migrations
rmdir "mobinspect\StaticAnalyzer\migrations" /q /s >nul 2>&1
echo Deleting Dynamic Analyzer migrations
rmdir "mobinspect\DynamicAnalyzer\migrations" /q /s >nul 2>&1
echo Deleting MobInspect migrations
rmdir "mobinspect\MobInspect\migrations" /q /s >nul 2>&1
echo Deleting temp and log files
del /f "mobinspect\debug.log" >nul 2>&1
del /f "classes*" >nul 2>&1
echo Deleting Scan database
del /f "mobinspect\db.sqlite3" >nul 2>&1
echo Deleting Secret file
del /f "mobinspect\secret" >nul 2>&1
echo Deleting Previous setup files
rmdir "%UserProfile%\MobInspect" /q /s >nul 2>&1
del /f "mobinspect\setup_done.txt" >nul 2>&1
echo Deleting MobInspect data directory: %mobinspect_home%
del /f "%mobinspect_home%" /q /s >nul 2>&1
rmdir "%mobinspect_home%" /S /Q >nul 2>&1
echo Done
) ELSE ( 
echo Please run script from mobinspect.MobInspect directory
echo 'scripts/clean.bat y
)
