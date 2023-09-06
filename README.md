# FeiertageFerien (14401)
Das Logikmodul nutzt https://www.openholidaysapi.org, um festzustellen, ob es sich beim aktuellen Tag um einen Feiertag 
oder um einen Tag der Schulferien handelt.

Wir das Überprüfen eines Tages kommandiert und es sind *keine* Feiertage bekannt, werden zuerst die Feiertage für die 
kommenden 356 Tage abgerufen.  

**Achtung**: Fehler bei den Eingängen können *nicht* detektiert werden und führen zur Ausgabe "kein Feiertag / 
Ferientag". 

## Voraussetzungen
HSL 2.0.4

## Installation
Die .hslz Datei mit dem Gira Experte importieren. Das Logikmodul ist dann in der Rubrik "Datenaustausch" verfügbar.

## Eingänge

| Nr. | Eingang                  | Initwert | Beschreibung                                                                                                                                                                                                                                                                                              |
|-----|--------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1   | ISO-Code Land            | DE       | Länderkürzel gem. [https://openholidaysapi.org/Countries](https://openholidaysapi.org/Countries)                                                                                                                                                                                                          |
| 2   | Code Verwaltungseinheit  | DE-BY    | Kürzel der Verwaltungseinheit gem. Länderkürzel gem. `https://openholidaysapi.org/Subdivisions?countryIsoCode={Ländercode}` <br>Z.B. für Deutschland mit `{Ländercode}` = DE:<br>[https://openholidaysapi.org/Subdivisions?countryIsoCode=DE](https://openholidaysapi.org/Subdivisions?countryIsoCode=DE) |
| 3   | Mitternacht              | 0        | <ul><li>Der Baustein prüft den Feiertags- / Schulferienstatus des aktuellen Tages, wenn auf diesem Eingang eine 1 empfangen wird.</li><li>Veraltete Einträge werden gelöscht.</li><li>Wenn keine / 0 Einträge bekannt sind, werden die nächsten 356 Tage abgerufen und gespeichert.</li></ul>             |
| 4   | Feiertage/Ferien abrufen | 0        | Der Baustein ruft die Feiertage und Ferien für die nächsten 365 Tage ab                                                                                                                                                                                                                                   |


## Ausgänge
Alle Ausgänge sind Send-by-Change ausgeführt.

| Nr. | Ausgang         | Initwert | Beschreibung                                                   |
|-----|-----------------|----------|----------------------------------------------------------------|
| 1   | Feiertag/Ferien | 0        | 1 wenn der aktuelle Tag ein Ferien- oder Feiertag ist, sonst 0 |


## Sonstiges

- Neuberechnung beim Start: Nein
- Baustein ist remanent: Nein
- Interne Bezeichnung: 14401

### Change Log

- v00.02: 
  - Improved exception logging
  - Fix: Renew stok 
- v00.01: Initial

### Open Issues / Known Bugs



### Support

Für Fehlermeldungen oder Feature-Wünsche, bitte [github issues](https://github.com/En3rGy/14401_FeiertageFerien/issues) nutzen.
Fragen am besten als Thread im [knx-user-forum.de](https://knx-user-forum.de) stellen. Dort finden sich ggf. bereits Diskussionen und Lösungen.

## Code

Der Code des Bausteins befindet sich in der hslz Datei oder auf [github](https://github.com/En3rGy/14401_FeiertageFerien).

### Entwicklungsumgebung

- [Python 2.7.18](https://www.python.org/download/releases/2.7/)
    - Install python *markdown* module (for generating the documentation) `python -m pip install markdown`
- Python editor [PyCharm](https://www.jetbrains.com/pycharm/)
- [Gira Homeserver Interface Information](http://www.hs-help.net/hshelp/gira/other_documentation/Schnittstelleninformationen.zip)

## Anforderungen

- Der Baustein soll eine 1 ausgeben, wenn es ich bei dem aktuellen Tag, um einen Ferien- oder Feiertag handelt, andernfalls eine 0. 

## Software Design Description

* Der Baustein fragt https://www.openholidaysapi.org nach dem Status des Tages ab.
* Der Baustein führt selbst *keine* zyklische Abfrage durch. Hintergrund ist, dass die Abfrage möglichst um Mitternacht 
erfolgen sollte. Überprüft der Baustein dies selbst wäre ein Timer mit einer z.B. Minütlichen Ausführung nötig. Das 
erhöht die Komplexität und Rechenlast des HS, wenn auch nur minimal. Ein Trigger für den Tageswechsel ist oftmals 
ohnehin vorhanden.  

## Validierung und Verifikation

- Unit Tests

## Lizenz

Copyright 2023 T. Paul

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
