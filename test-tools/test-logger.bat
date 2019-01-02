setlocal enableextensions enabledelayedexpansion
set /a count = 1

:loop

echo hellotail !count! >> tail.txt
timeout 5
REM echo|set /p="Hello World" >> tail2.txt
REM sleep 10
echo|set /p="secret2">>tail2.txt
REM echo secret2>> tail2.txt
timeout 5
echo hellotail !count! >> C:\Users\admin\Downloads\tail.txt
timeout 5
REM echo ###secret3### >> C:\Users\admin\Downloads\tail.txt
REM sleep 10
set /a count += 1

goto loop