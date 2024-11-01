@echo off
chcp 936 >nul
setlocal enabledelayedexpansion

set trusted_party_ip=127.0.0.1
set client_count=100
set alg=1
set vectorsize=200000

:: 设置 Conda 的安装路径（根据你的安装路径进行调整）
set CONDA_PATH=C:\ProgramData\anaconda3

:: 激活 Conda 环境
call %CONDA_PATH%\Scripts\activate.bat tenseal

:: 启动客户端进程
for /L %%i in (1,1,%client_count%) do (
    echo 启动客户端 %%i...
    start /B python client.py %alg% %vectorsize% %client_count% %trusted_party_ip% %%i
)

echo 所有客户端已启动
endlocal
