<div align="center">

# 🛰️ SIGINT-Console
> **Central Wireless Intelligence, Correlation & Audit Hub for ESP32-S3 Sensor Nodes**

<p align="center">
  <img alt="Python 3.13" src="https://img.shields.io/badge/Python-3.13-blue?style=flat-square&logo=python">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker">
  <img alt="IEEE OUI" src="https://img.shields.io/badge/IEEE_OUI_DB-40%2C355_Prefixes-10b981?style=flat-square">
  <img alt="Sensors" src="https://img.shields.io/badge/Sensors-ESP32_Projects-orange?style=flat-square&logo=espressif">
</p>

</div>

---

**SIGINT-Console** es la plataforma central de análisis, correlación multi-sesión y auditoría de espectro diseñada como el **cerebro de inteligencia** para los sensores hardware del repositorio [**kta41/ESP32_projects**](https://github.com/kta41/ESP32_projects):

| Sensor Hardware (`ESP32_projects`) | Estado | Telemetría Ingerida |
| :--- | :--- | :--- |
| [**`Wifi-Wardriving`**](https://github.com/kta41/ESP32_projects/tree/main/Wifi-Wardriving) | ✅ **Activo** | Barrido pasivo 802.11 + modo promiscuo (`MGMT`/`DATA`), estaciones clientes (`ToDS`/`FromDS`), huella PNL (*Probe Requests*) y tramas `Deauth`/`Disassoc`. |
| [**`BLE-Recon`**](https://github.com/kta41/ESP32_projects/tree/main/BLE-Recon) | 🔜 *Roadmap* | Balizas Bluetooth Low Energy (iBeacon, Eddystone, Apple FindMy / AirTag) y correlación temporal con clientes Wi-Fi. |
| [**`ESP32-RF-Lab`**](https://github.com/kta41/ESP32_projects/tree/main/ESP32-RF-Lab) | 🔜 *Roadmap* | Ocupación espectral 2,4 GHz / Sub-GHz y telemetría de nivel físico. |

---

## 🧠 Capacidades de Inteligencia

1. **Resumen Ejecutivo & Postura de Exposición RF (`0–100`)**:
   - Evaluación automática de protocolos obsoletos (`OPEN`, `WEP`, `WPA1`, `TKIP` — *Beck-Tews / ChopChop*), exposición de **WPS** (*Pixie-Dust / PIN*), redes ocultas (*SSID Cloaking*) y colisiones Multi-BSSID / posibles *Evil Twins*.
2. **Dossier de Redes e Infraestructura (`BSSID` / Clusters `SSID`)**:
   - Filtro instantáneo de **`⚠️ Redes No Seguras`** con explicación técnica detallada por vulnerabilidad y severidad (`CRÍTICO`, `ALTO`, `MEDIO`, `INFO`).
   - Correlación de qué estaciones clientes están traficando datos en cada AP y qué dispositivos externos están buscando ese SSID.
3. **Inteligencia de Dispositivos Clientes (`STA MAC` & Huella PNL)**:
   - Asocia cada dispositivo con los puntos de acceso a los que se conecta y con la lista de redes que busca mediante *Probe Requests* (distinguiendo redes presentes en el entorno frente a redes remotas guardadas en el dispositivo).
4. **Base de Datos IEEE OUI Completa (`40.355` prefijos, España + Global)**:
   - Identificación offline de los fabricantes de móviles más usados en España (`Apple`, `Samsung`, `Xiaomi/Redmi/POCO`, `Huawei`, `Honor`, `OPPO`, `realme`, `OnePlus`, `Google Pixel`, `Motorola`), routers de operadoras (`Arcadyan`, `MitraStar`, `Askey`, `Sagemcom`, `Sercomm`, `ZTE`, `TP-Link`, `Mercusys`) e IoT (`Espressif`, `Tuya`, `Amazon`, `Shelly`).
   - Desenmascarado automático de **BSSIDs virtuales** (bit `Locally-Administered` invertido sobre un OUI real) frente a **MACs aleatorias de privacidad (iOS/Android)**.
5. **Persistencia Multi-Sesión (Cross-Session Tracking)**:
   - Detecta qué dispositivos (`STA MAC`) o puntos de acceso reaparecen en múltiples sesiones de captura distintas.
6. **Gestión de Sesiones, GPS por Sesión y Etiquetado Persistente (`tags.json`)**:
   - Permite nombrar sesiones, asignarles coordenadas GPS y etiquetar dispositivos o redes con nombres personalizados (`PROPIO`, `CONOCIDO`, `OBJETIVO`, `SOSPECHOSO`, `IGNORAR`).
   - Cuando corre como servicio Docker/HTTP, cualquier cambio de etiqueta se guarda automáticamente en `/data/tags.json` a través de `POST /api/tags`.

---

## 🐳 Despliegue Rápido con Docker

```bash
git clone https://github.com/kta41/SIGINT-Console.git
cd SIGINT-Console
docker compose up -d --build
```

Abre en tu navegador: **`http://localhost:8080`**

### Cómo importar capturas `.jsonl` al servicio

1. **Desde el propio navegador web (`http://localhost:8080`)**:
   - Haz clic en el botón superior **`📥 Importar .JSONL al Servidor`** y selecciona uno o varios ficheros `wardrive_*.jsonl` (o arrastra tu `tags.json`).
2. **Copiando los archivos a la carpeta `./data/`**:
   - Cualquier fichero `.jsonl` en `./data/` es leído y correlacionado en caliente al recargar la página (puedes sincronizar directo desde el móvil con `warpull ./data` desde `ESP32_projects/Wifi-Wardriving`).
3. **Por API HTTP (`curl` o push directo del sensor)**:
   ```bash
   curl -X POST "http://localhost:8080/api/import?filename=sesion_auditoria.jsonl" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary @wardrive_20261020_1313.jsonl
   ```

---

## 🔌 Endpoints de la API

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| `GET` | `/` | Consola Web SIGINT interactiva renderizada con los datos actuales de `/data`. |
| `GET` | `/api/dataset` | Dataset JSON completo ya correlacionado (APs, STAs, PNL, sesiones, vulnerabilidades). |
| `GET` | `/api/tags` | Devuelve el diccionario activo de etiquetas (`sessions`, `networks`, `devices`). |
| `POST` | `/api/tags` | Persiste cambios de etiquetas/nombres/GPS directamente en `/data/tags.json`. |
| `POST` | `/api/import` | Importa y valida líneas JSONL v1 en `/data/`. |
| `POST` | `/scans` | Endpoint compatible con el push directo del firmware ESP32-S3 (`Wifi-Wardriving`). |
| `GET` | `/export/csv` | Descarga el catálogo único de BSSIDs en CSV. |
| `GET` | `/export/wigle` | Descarga las redes en formato oficial **WiGLE CSV v1.4**. |
| `GET` | `/health` | Estado del contenedor y lista de ficheros cargados. |

---

## 💻 Ejecución sin Docker (Python 3stdlib pura)

No requiere instalar paquetes con `pip` (usa exclusivamente la librería estándar de Python 3):

```bash
python3 app/server.py --host 0.0.0.0 --port 8080 --data ./data
```

O en modo CLI / generador estático:

```bash
python3 app/engine.py ./data/wardrive_*.jsonl \
    --csv ./data/redes.csv \
    --wigle ./data/wigle.csv \
    --html ./data/dashboard.html
```
