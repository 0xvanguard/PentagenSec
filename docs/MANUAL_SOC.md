# MANUAL DE INSTALACIÓN Y OPERACIÓN
**PentagenSec v4.6.0 GA**
*IPS/IDS + Deception + SOAR Kernel-Native*
*Para uso en Centro de Operaciones de Seguridad (SOC)*

**Versión del documento:** 1.0  
**Fecha:** 30 Mayo 2026  
**Audiencia:** Analistas SOC, Ingenieros de Red, IT

---

## 1. Descripción del Producto

**PentagenSec** es una plataforma de defensa que se ejecuta dentro del kernel Linux. Detecta y bloquea ataques en 10 microsegundos sin usar agentes ni firmas. 

**Componentes:**
1. **Sensor XDP**: Programa eBPF que filtra tráfico en la tarjeta de red.
2. **Control Plane**: Servicio web con dashboard en puerto 8080.
3. **Integración Telegram**: Recibes alertas críticas en el móvil para aprobar/bloquear.

**Qué verás:** Un dashboard web con medidores en tiempo real de amenazas, atacantes bloqueados, y una tabla de acciones.

---

## 2. Requisitos Previos

| Requisito | Detalle | Cómo verificarlo |
| :--- | :--- | :--- |
| **Servidor** | Servidor Linux dedicado | Ubuntu 22.04 o superior |
| **Permisos** | Acceso `sudo` o usuario root | Ejecuta `sudo -v` |
| **Red** | 1 interfaz conectada a la DMZ/Tráfico | `ip a` para ver nombre (ej. eth0) |
| **Puertos** | 8080 TCP libre para dashboard | `sudo ss -tlnp \| grep 8080` debe estar vacío |
| **Telegram** | Bot Token y Chat ID | Te lo entrega el administrador |

> **Importante:** Esta instalación debe hacerla el equipo de IT/Infraestructura. No se instala en laptops de usuario final.

---

## 3. Instalación Paso a Paso - 15 Minutos

**Paso 1: Descargar el instalador**  
IT te entregará un archivo `pentagensec-4.6.0.tar.gz` en un USB o repositorio interno. Cópialo al servidor.

```bash
tar -xzf pentagensec-4.6.0.tar.gz
cd pentagensec-4.6.0
```

**Paso 2: Ejecutar instalador automático**  
Reemplaza `eth0` por el nombre de tu interfaz de red.

```bash
sudo ./install.sh eth0
```
El script te pedirá 2 datos:
1. `TELEGRAM_BOT_TOKEN`: Pégalo y Enter
2. `TELEGRAM_CHAT_ID`: Pégalo y Enter

**Paso 3: Verificar que funciona**  
Al terminar verás este mensaje confirmando la instalación y proporcionando la URL del dashboard.
1. Abre Chrome/Firefox en tu PC de oficina.
2. Entra a la URL que mostró: `http://IP_DEL_SERVIDOR:8080`
3. Debes ver el logo **PentagenSec** y el estado `XDP Active` en verde.

---

## 4. Uso Diario para Analistas SOC

### 4.1 Pantalla Principal del Dashboard

| Elemento | Qué significa |
| :--- | :--- |
| **Gauge ML Anomaly Score** | 0-100. Si pasa de 42 y se pone rojo, hay anomalía. |
| **ML Blocks/s** | Cuántos ataques bloquea por segundo. 0 = modo monitor. |
| **Attackers Tarred** | Atacantes "colgados" con TARPIT. Cada +1 es un escáner neutralizado. |
| **Active Actions** | Tabla con IPs bloqueadas y razón. |

### 4.2 Flujo de una Alerta Real

1. **Suena tu Telegram**: `🚨 P1 - C2 Beaconing detectado en srv-db-01`
2. **Miras el Dashboard**: El gauge está en rojo 47.3. La tabla muestra `srv-db-01 → TARPIT PENDING`
3. **Decides en 300s**: Tienes 3 opciones:
   - `APPROVE`: Bloquea la IP y activa TARPIT. La tabla se pone roja `TARPIT ACTIVE`.
   - `REJECT`: Falso positivo. La tabla se limpia. Suma +1 en `False Positives Averted`.
   - `ESCALATE`: Pasa a L2/L3. No hace nada aún.
4. **Confirmación**: El dashboard cambia de color confirmando tu acción.

### 4.3 Cómo Investigar Antes de Aprobar

1. En el Dashboard, haz click en la IP de la tabla `Active Actions`.
2. Se abre la ventana **Explain** con 3 datos clave:
   - `iat_ns`: Si dice `180s` es beaconing. Si es random, puede ser humano.
   - `payload_entropy`: `7.9` = cifrado. Normal en TLS.
   - `reverse_dns`: Si dice `microsoft.com` o `amazonaws.com`, cuidado.

> **Regla de oro:** Si `reverse_dns` es de proveedores en la nube y el servidor afectado es de backups/monitorización, consulta antes de `APPROVE`.

---

## 5. Solución de Problemas Básicos

| Problema | Causa | Solución para Analista |
| :--- | :--- | :--- |
| **Dashboard no carga** | Servicio caído | Llama a IT. Diles: "reiniciar servicio pentagensec" |
| **No llegan alertas** | Token mal configurado | Verifica con IT que el Chat ID es correcto |
| **Todo rojo (sin ataque)** | Falso positivo masivo | Haz `REJECT` y avisa a L3 para ajustar umbral ML |
| **Bloqueé servidor legal** | Error humano | Contacta a L3 inmediato. Rollback en <30s |

---

## 6. Contactos y Escalamiento

1. **L1 - Dudas de uso diario**: Manual + este documento.
2. **L2 - Falsos positivos / Ajustes**: Equipo de Detección SOC.
3. **L3 - Emergencias / Rollback**: Administrador PentagenSec + IT Infraestructura.

---

### ANEXOS

**A. Glosario**  
* **XDP**: Express Data Path. Procesa paquetes en la tarjeta de red.
* **TARPIT**: "Cuelga" al atacante respondiendo con ventana TCP 0.
* **Beaconing**: Latido periódico de malware a su servidor de control.
* **ML Inline**: Modelo de IA que corre dentro del kernel.

**B. Políticas**  
1. No aprobar bloqueos en servidores críticos sin doble validación.
2. Todo `APPROVE` queda registrado para auditoría.
3. Modo `ml_enforcement: false` es por defecto. Solo L3 activa bloqueo automático.
