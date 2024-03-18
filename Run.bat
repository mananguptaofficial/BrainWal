@Echo off
title BrainWal
Pushd "%~dp0"
:loop
python main.py
goto loop
