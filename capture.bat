@echo off
setlocal
set NODE=%~1
if "%NODE%"=="" set NODE=alice
set WIRESHARK=C:\Program Files\Wireshark\Wireshark.exe
if not exist "%WIRESHARK%" (
  echo Wireshark not found at "%WIRESHARK%". Edit the path in capture.bat.
  exit /b 1
)
echo Live capture on container "%NODE%" (eth0, tcp ports 5000 and 6000). Close Wireshark to stop.
docker exec %NODE% tcpdump -U -n -i eth0 -w - "tcp port 5000 or tcp port 6000" | "%WIRESHARK%" -k -i -
