@echo off
set path=%path%;C:\Python27\
set PYTHONPATH=C:\Python27;C:\Python27\Lib

echo ^<head^> > .\release\DE-log14402.html
echo ^<link rel="stylesheet" href="style.css"^> >> .\release\DE-log14402.html
echo ^<title^>Logik - Feiertage / Ferien (14401)^</title^> >> .\release\DE-log14402.html
echo ^<style^> >> .\release\DE-log14402.html
echo body { background: none; } >> .\release\DE-log14402.html
echo ^</style^> >> .\release\DE-log14402.html
echo ^<meta http-equiv="Content-Type" content="text/html;charset=UTF-8"^> >> .\release\DE-log14402.html
echo ^</head^> >> .\release\DE-log14402.html

@echo on

type .\README.md | C:\Python27\python -m markdown -x tables >> .\release\DE-log14402.html

cd ..\..
C:\Python27\python generator.pyc "14402_Tapo_Cam" UTF-8

xcopy .\projects\14402_Tapo_Cam\src .\projects\14402_Tapo_Cam\release /exclude:.\projects\14402_Tapo_Cam\src\exclude.txt

@echo Fertig.

@pause
