# vulnwatch

**Alertas de vulnerabilidades para tus servidores, por Telegram y mail, gratis y sin servidor propio.**

`vulnwatch` vigila de forma automática las vulnerabilidades (CVE) publicadas para los servicios que
suelen correr en una oficina o empresa, y te avisa:

- 📲 **Por Telegram**, cada 3 horas, cuando aparece algo nuevo de nivel **alto** o **crítico**.
- 📧 **Por mail**, una vez por semana, con un **PDF** (lectura rápida) y un **Excel** (detalle con filtros
  y una columna "Estado" para ir marcando qué ya se parcheó).

Corre completamente en **GitHub Actions**: no necesitás servidor, no instalás nada y no cuesta dinero.

**Cubre por defecto:** PHP · MySQL · MariaDB · PostgreSQL · nginx · Node.js · Apache HTTP Server ·
Docker · Linux (kernel) · Laravel · WordPress. Podés quitar o agregar productos editando un archivo.

---

## Índice

1. [Cómo funciona](#cómo-funciona)
2. [Qué vas a recibir](#qué-vas-a-recibir)
3. [Puesta en marcha paso a paso](#puesta-en-marcha-paso-a-paso)
4. [Personalización](#personalización)
5. [Cómo se calcula el riesgo](#cómo-se-calcula-el-riesgo)
6. [Probarlo en tu computadora](#probarlo-en-tu-computadora)
7. [Solución de problemas](#solución-de-problemas)
8. [Costos, límites y seguridad](#costos-límites-y-seguridad)

---

## Cómo funciona

```
 GitHub Actions (cron)
        │
        ├── cada 3 horas ──►  alert  ──┐
        └── lunes 08:00 AR ─►  digest ─┤
                                       ▼
   ┌────────────────────────────────────────────────────┐
   │ 1. Descarga CVE nuevos/modificados de NVD (NIST)   │
   │ 2. Filtra los que tocan tus productos (inventory)  │
   │ 3. Cruza con CISA KEV  (¿ya se explota de verdad?) │
   │ 4. Cruza con EPSS      (probabilidad de explotación)│
   │ 5. Suma GitHub Security Advisories (ej. Laravel)   │
   │ 6. Calcula nivel: bajo / medio / alto / crítico    │
   └───────────────┬────────────────────────────────────┘
                   ├── alert  ► mensaje de Telegram (solo alto y crítico, solo lo nuevo)
                   └── digest ► mail con PDF + Excel (todos los niveles)
```

Fuentes de datos, todas públicas y gratuitas:

| Fuente | Aporta |
|---|---|
| [NVD](https://nvd.nist.gov/) | CVE, descripción, puntaje CVSS, versiones afectadas |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Lista de vulnerabilidades **explotadas activamente** |
| [EPSS](https://www.first.org/epss/) | Probabilidad (0–100 %) de que se explote en los próximos 30 días |
| [GitHub Advisories](https://github.com/advisories) | Avisos de paquetes (composer/npm), ej. `laravel/framework` |

El estado ("qué ya te avisé") se guarda en `state/state.json` dentro del propio repositorio, con un commit
automático, para no repetirte avisos.

## Qué vas a recibir

**Telegram** (solo novedades alto/crítico):

```
🚨 2 vulnerabilidad(es) nueva(s)

🔴 CVE-2026-XXXXX — CRÍTICO (CVSS 9.8)
Producto: PHP
🔥 Explotación activa confirmada (CISA KEV)
Prob. de explotación (EPSS): 87%
Corregida en: 8.2.33, 8.3.33
<descripción del CVE>
https://...
```

**Mail semanal:** asunto con el resumen (`crítico: 3 | alto: 12 | medio: 40 | bajo: 9`), un **PDF**
ordenado por gravedad y un **Excel** con filtros, colores por nivel y columnas `Estado` y `Notas`.

> Las descripciones están en inglés, tal como las publica NVD.

---

## Puesta en marcha paso a paso

Tiempo estimado: **15–20 minutos**. Necesitás una cuenta de GitHub, Telegram y una casilla de mail.

### Paso 1 — Crear tu copia **privada** del proyecto

1. En la página de este repositorio hacé clic en el botón verde **Use this template** →
   **Create a new repository**.
2. Ponele un nombre (ej. `vulnwatch`) y elegí **Private**.
3. Clic en **Create repository**.

> **¿Por qué privado y por qué template y no fork?** Tu copia guarda tu configuración y el historial de
> avisos, que no tienen por qué ser públicos. Además, en los *forks* GitHub desactiva las tareas
> programadas; en un repositorio creado desde una plantilla funcionan normalmente.

### Paso 2 — Crear el bot de Telegram

1. En Telegram buscá **@BotFather** (el oficial, con tilde azul) y escribile `/newbot`.
2. Elegí un nombre (ej. `Alertas Vulnerabilidades`) y un usuario que termine en `bot`
   (ej. `mi_empresa_vulns_bot`).
3. BotFather te responde con el **token**, algo como `123456789:AAH...`. **Copialo y no lo compartas**:
   quien lo tenga controla el bot.
4. Buscá tu bot nuevo en Telegram, tocá **Start** y escribile cualquier mensaje (ej. `hola`).
   *Este paso es obligatorio: un bot no puede escribirte si vos no le escribiste primero.*

### Paso 3 — Obtener tu Chat ID

Abrí en el navegador, reemplazando `<TOKEN>` por el token del paso anterior:

```
https://api.telegram.org/bot<TOKEN>/getUpdates
```

Buscá en el resultado `"chat":{"id": 123456789` — ese número es tu **Chat ID**.

- Si el resultado aparece vacío (`"result":[]`), no le escribiste al bot: volvé al paso 2.4.
- **Para que lleguen a un grupo** (ej. el equipo de sistemas): agregá el bot al grupo, escribí un mensaje
  en el grupo y repetí esta consulta. El Chat ID de un grupo es un número **negativo** (ej. `-1001234567890`).

### Paso 4 — Preparar el envío de mail

**Con Gmail (lo más simple):**

1. Activá la *verificación en 2 pasos* en tu cuenta de Google.
2. Entrá a <https://myaccount.google.com/apppasswords>, creá una contraseña de aplicación
   (ej. nombre `vulnwatch`) y copiá los 16 caracteres que te muestra (podés pegarla con o sin espacios).
3. Usarás: `SMTP_USER` = tu Gmail, `SMTP_PASSWORD` = esa contraseña de aplicación.

**Con otro proveedor** (Outlook, un SMTP de la empresa, Brevo, etc.): además de `SMTP_USER` y
`SMTP_PASSWORD`, cargá `SMTP_HOST` (ej. `smtp.empresa.com`) y `SMTP_PORT` (`465` para SSL, `587` para
STARTTLS). Nota: algunas cuentas de Google Workspace y de Microsoft 365 tienen deshabilitado el SMTP con
contraseña por política del administrador; en ese caso usá una casilla personal de Gmail solo para enviar.

### Paso 5 — (Opcional pero recomendado) Clave de NVD

Pedí una clave gratuita en <https://nvd.nist.gov/developers/request-an-api-key> (llega por mail).
Sin ella el proyecto funciona igual, pero NVD limita a 5 consultas cada 30 segundos y cada ejecución
tarda varios minutos.

### Paso 6 — Cargar los secrets en GitHub

En tu repositorio: **Settings → Secrets and variables → Actions → New repository secret**.
Creá uno por cada fila (el nombre debe ser exacto):

| Secret | Obligatorio | Valor |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | ✅ | El token de BotFather |
| `TELEGRAM_CHAT_ID` | ✅ | Tu Chat ID (o el del grupo) |
| `SMTP_USER` | ✅ | Tu casilla de mail (usuario SMTP) |
| `SMTP_PASSWORD` | ✅ | Contraseña de aplicación / del SMTP |
| `MAIL_TO` | ➖ | Destinatario del reporte. Si no lo cargás, se usa `SMTP_USER`. Admite varios separados por coma |
| `SMTP_HOST` | ➖ | Solo si no usás Gmail |
| `SMTP_PORT` | ➖ | Solo si no usás Gmail (`465` o `587`) |
| `NVD_API_KEY` | ➖ | La clave del paso 5 |

> Si instalás [GitHub CLI](https://cli.github.com/) podés hacerlo desde la terminal:
> `gh secret set TELEGRAM_BOT_TOKEN -R tu-usuario/vulnwatch`

### Paso 7 — Revisar los permisos de Actions

**Settings → Actions → General → Workflow permissions** → elegir **Read and write permissions** → Save.
(Es necesario para que el proceso pueda guardar su estado en el repositorio.)

### Paso 8 — Primera ejecución de prueba

1. Pestaña **Actions** (si GitHub pregunta, aceptá habilitar los workflows).
2. Elegí **Alertas por Telegram** → **Run workflow** → **Run workflow**.
   - Esta primera vez **no manda avisos viejos**: registra la línea base y te envía a Telegram
     `✅ vulnwatch activo`. Desde ahí solo recibís novedades.
3. Elegí **Reporte semanal por mail** → **Run workflow**. En unos minutos te llega el mail con el PDF y el Excel
   (revisá *spam* la primera vez).

Si algo falla, abrí la ejecución con la ❌ y mirá el log; el apartado
[Solución de problemas](#solución-de-problemas) cubre los casos habituales.

### Listo

Desde ahora funciona solo:

- Telegram: cada 3 horas, si hay novedades alto/crítico.
- Mail: cada lunes (ver [horarios](#cambiar-los-horarios)).

---

## Personalización

Todo se configura en [`inventory.yml`](inventory.yml).

### Quitar o agregar productos

Cada producto es un bloque:

```yaml
- name: Redis
  installed: []                       # versiones que usás (opcional, ver abajo)
  cpes: ["cpe:2.3:a:redis:redis:"]    # identificador del producto en NVD
  keywords: ['(?<![\w-])Redis (?:before|prior|through|versions?|\d)']   # opcional
```

- Para encontrar el `cpe` de un producto, buscalo en <https://nvd.nist.gov/products/cpe/search>
  y copiá el prefijo `cpe:2.3:a:<fabricante>:<producto>:`.
- Para dejar de vigilar algo, borrá su bloque.
- `only_kev: true` hace que solo avise lo que CISA confirma como explotado (útil para productos muy
  ruidosos, como el kernel de Linux).

### Filtrar por tus versiones (opcional)

Si completás `installed: ["8.2.12", "8.3.4"]`, el sistema compara contra los rangos afectados y:

- Si **no** te afecta, no te avisa.
- Si te afecta, lo marca (`Te afecta: SÍ`) y sube un nivel de riesgo.

Si en tu organización conviven muchas versiones, dejalo vacío: avisa de todo el producto.

### Nivel mínimo para Telegram

```yaml
min_alert_level: alto     # bajo | medio | alto | crítico
```

El mail semanal siempre incluye todos los niveles.

### Cambiar los horarios

Están en `.github/workflows/` (formato cron, **en UTC**):

| Archivo | Valor por defecto | Significado |
|---|---|---|
| `alert.yml` | `17 */3 * * *` | Cada 3 horas, minuto 17 |
| `digest.yml` | `0 11 * * 1` | Lunes 11:00 UTC (= 08:00 en Argentina, UTC-3) |

Ayuda para armar expresiones: <https://crontab.guru>. Para ver más días hacia atrás en el reporte,
cambiá `digest_days` en `inventory.yml`.

---

## Cómo se calcula el riesgo

Se parte de la severidad **CVSS** y se ajusta con datos de explotación real:

| Condición | Efecto |
|---|---|
| CVSS 0.1–3.9 / 4.0–6.9 / 7.0–8.9 / 9.0–10 | Bajo / Medio / Alto / Crítico |
| Está en **CISA KEV** (explotación activa) | **Crítico** siempre |
| **EPSS ≥ 50 %** | +1 nivel |
| Afecta una versión que declaraste instalada | +1 nivel |
| Declaraste versiones y **no** te afecta | Se descarta |

Los CVE recién publicados pueden no tener puntaje todavía (NVD tarda en analizarlos); en ese caso se
asume nivel medio hasta que haya datos, y vuelven a evaluarse cuando NVD los actualiza (si suben de nivel,
se te avisa de nuevo).

---

## Probarlo en tu computadora

Requiere Python 3.10 o superior.

```bash
git clone https://github.com/<tu-usuario>/vulnwatch.git && cd vulnwatch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m vulnwatch digest --dry-run --days 3   # genera out/vulnerabilidades.pdf y .xlsx, sin enviar
python -m vulnwatch alert  --dry-run            # muestra qué avisaría, sin enviar ni guardar estado
pytest                                          # tests
```

Para envíos reales desde tu máquina, copiá `.env.example` a `.env`, completalo y cargalo con
`set -a; source .env; set +a` antes de ejecutar sin `--dry-run`.

---

## Solución de problemas

| Síntoma | Causa probable y solución |
|---|---|
| `Faltan TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID` | No cargaste los secrets, o el nombre tiene un error de tipeo. |
| Telegram: `401 Unauthorized` | Token incorrecto o revocado. Pedí uno nuevo con `/token` en @BotFather. |
| Telegram: `400 Bad Request: chat not found` | Nunca le escribiste al bot (paso 2.4) o el Chat ID está mal. Si es un grupo, el bot debe estar dentro. |
| `getUpdates` devuelve `"result":[]` | Escribile primero un mensaje al bot y volvé a abrir el link. |
| Mail: `535 Authentication failed` | Usaste tu contraseña normal en vez de la *contraseña de aplicación*, o la verificación en 2 pasos no está activa. |
| Mail: no llega | Revisá *spam*. Verificá `MAIL_TO`. Con SMTP propio revisá `SMTP_HOST` / `SMTP_PORT`. |
| `Resource not accessible by integration` / falla al guardar estado | Falta el paso 7 (permisos de lectura y escritura de Actions). |
| No corren las ejecuciones programadas | Verificá que Actions esté habilitado. Si usaste *fork* en vez de *template*, GitHub las deshabilita: habilitalas en la pestaña Actions o recreá desde la plantilla. |
| Las ejecuciones tardan varios minutos | Normal sin `NVD_API_KEY` (paso 5). |
| Llegan avisos de cosas que no usás | Quitá el producto de `inventory.yml`, o declará tus `installed`. |

---

## Costos, límites y seguridad

**Costo:** $0. En un repositorio privado GitHub incluye 2.000 minutos mensuales de Actions en el plan
gratuito; este proyecto usa aproximadamente 400. Telegram, NVD, CISA y EPSS son gratuitos.

**Límites conocidos**

- Es un **complemento**, no reemplaza a los avisos oficiales de tus proveedores ni a un escáner de
  vulnerabilidades sobre tus equipos. No inspecciona tus servidores: solo vigila lo que se publica.
- Los CVE aún sin analizar por NVD se detectan por palabras clave en la descripción y pueden generar
  algún falso positivo o pasar desapercibidos; se corrigen solos cuando NVD completa el análisis.
- El kernel de Linux solo avisa lo explotado activamente (CISA KEV), para evitar cientos de avisos.
- Las descripciones están en inglés.
- Las tareas programadas de GitHub pueden demorar unos minutos respecto de la hora indicada.

**Seguridad**

- Los tokens y contraseñas viven solo en *Secrets* de GitHub; nunca los escribas en el código ni en
  `inventory.yml`.
- Usá una **contraseña de aplicación** (revocable), no la contraseña real de tu cuenta.
- Si un token se filtra: revocalo (`/revoke` en @BotFather, o la página de contraseñas de aplicación de Google)
  y actualizá el secret.
- Mantené el repositorio **privado**.

## Licencia

[MIT](LICENSE). Usalo, modificalo y compartilo libremente. Se ofrece "tal cual", sin garantías.
