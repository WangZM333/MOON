@echo off
chcp 936 >nul
setlocal enabledelayedexpansion

set trusted_party_ip=127.0.0.1
set client_count=100
:: 0不分组，1分组
set alg=0
set vectorsize=100000
::  先在终端跑trusted_party，再运行bat
::  python trusted_party.py 100

set CONDA_PATH=C:\ProgramData\anaconda3
call %CONDA_PATH%\Scripts\activate.bat tenseal

:: 启动客户端进程
for /L %%i in (1,1,%client_count%) do (
    echo 启动客户端 %%i...
    start /B python client.py %alg% %vectorsize% %client_count% %trusted_party_ip% %%i
)

echo 所有客户端已启动
endlocal
