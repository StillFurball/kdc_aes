@echo off
setlocal
cd /d "%~dp0"

docker info >/dev/null 2>&1
if errorlevel 1 (
  echo Docker Desktop is not running. Open it, wait until the engine is running, then try again.
  pause
  exit /b 1
)

echo Starting containers kdc, alice, bob ...
docker compose up -d
if errorlevel 1 (
  echo docker compose failed. Run "docker compose up -d --build" once and check the error.
  pause
  exit /b 1
)

where wt >/dev/null 2>&1
if errorlevel 1 goto separate_windows

wt --title KDC cmd /k docker exec -it kdc python kdc.py ; split-pane -H --size 0.55 --title Alice cmd /k docker exec -it alice python alice.py ; split-pane -V --size 0.5 --title Bob cmd /k docker exec -it bob python bob.py
exit /b 0

:separate_windows
start "KDC" cmd /k docker exec -it kdc python kdc.py
start "Bob" cmd /k docker exec -it bob python bob.py
start "Alice" cmd /k docker exec -it alice python alice.py
