import re
import datetime
import os
import sys
import time
import threading
import queue
import signal
import configparser
import crypt
import socket
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import string
import itertools

now = datetime.datetime.now()  # vrijeme
# variabla za ispis na ekran koja je trebala ic do 30 ali problemi sa ispisom
q = queue.Queue()
# -----------------------------------------------------
"""
Kvadrat je funkkfcija koja od broja 27270270260260260260 oduzima kvadrate brojeva do 95999 te je implementirana pomoću 4
dretve koje se služe funkijom Kvadrat koja kvadrira broj i oduzima.Dretve su tako složene da svaka ima jedan raspon
brojeva za odradit
"""


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def kvadrat(parametar, argument):
    if (parametar != "" or argument != ""):
        print("Ova funkcija ne prima argumente ili parametre")
    else:
        b = threading.Barrier(4)
        lock = threading.Lock()
        var = 27270270260260260260

        def Kvadrat(var, n, m):
            lock.acquire()
            for i in range(n, m):
                var -= pow(i, 2)
            time.sleep(1)
            # id_dretve=b.wait()
            # if (id_dretve == 1):
            #   print("zavrsila je")
            print("Dretva je završila")
            lock.release()

        Dretva1 = threading.Thread(target=Kvadrat, args=(var, 1, 24000))
        Dretva2 = threading.Thread(target=Kvadrat, args=(var, 24000, 48000))
        Dretva3 = threading.Thread(target=Kvadrat, args=(var, 48000, 72000))
        Dretva4 = threading.Thread(target=Kvadrat, args=(var, 72000, 96000))
        Dretva1.start()
        Dretva2.start()
        Dretva3.start()
        Dretva4.start()
        Dretva1.join()
        Dretva2.join()
        Dretva3.join()
        Dretva4.join()
        print("rezultat: ", var)


# Pozdravna poruka za ispis na ekran sa vremenom stavljena u funkciju radi fleksibilnosti
def PozdravnaPoruka():
    print("Dobrodošli u Osnovnu komandnu liniju, za informacije o komandama upisite help(",
          (now.strftime("%Y-%m-%d %H:%M:%S")),
          ")")


"""
Vraća trenutni aktivni direktoriji
koristi funkciju iz modela os kako bi pronašo

"""


def pwd(naredba, parametar, argument):
    if (parametar == '' and argument == ''):
        print(os.getcwd())
    else:
        print("Naredba pwd ne prima parametre ni argument (Primjer korištenja: ...pwd)")
    return


"""
Vraća trenutni pid

Argumenti
pid

Vraća:
Ima 2 slučaja, jedan kada baca grešku zbog krivog unosa i drugi da printa pid
"""


def ps(naredba, parametar, argument):
    if (parametar == '' and argument == ''):
        print(os.getpid())
    else:
        print("Naredba ps ne prima parametre ni parametare (Primjer korištenja: ...ps)")
    return


"""
Ova naredba kopira unos korisnika

Argument-unos korisnika

Ima 2 slučaja, jedan kada baca grešku zbog krivog unosa i drugi printa unos korisnika
"""


def echo(naredba, parametar, argument):
    if (parametar != ""):
        print("ova komanda nema ugrađene parametre pokušajte ponovo")
    elif (argument == ''):
        print("Fale vam argumenti")

    else:
        argument = re.sub(r'([\"\']$|^[\"\']| [\"\'] )', "", argument)

        print(argument)


"""
Naredba datum printa trenutno vrijeme i datum

Argumenti-nema argumenata koje unosi korisnik,ali ima parametar koji unosi korisnik
koji određuje dali ce sat bit 24h oblika il 12

Mogući izlaz je greška zbog krivih argumenata ili vrijeme i datum
"""


def datum(naredba, parametar, argument):
    if (argument != ""):
        print("funkcija date ne prima argumente, vaša komanda se neće izvršiti")
    else:
        if (parametar == ""):
            print(now.strftime("%I:%M:%S%p %A %d .%m.%Y "))
        elif (parametar == "-s"):
            print(now.strftime("%H:%M:%S %A %d.%m.%Y "))
        else:
            print("Funkcija date ne prepoznaje parametar: ", parametar)


"""
Komanda Obrada otvara datoteku i ovisno o unosu korisnika je čita ili je stavlja za append

Argumenti-put do datoteke koji se provjerava,te ako je put nepoznat datoteka će se napravit u datoteci gdje se program
izvodi
Parametar-komanda prepoznaje 2 parametrea -a i -r koje funkcija prepoznaje pod čitanje i pisanuje

Funkcija vraća input za pisanje u datoteku ako je parametar -a, a ako je parametar -r
iz printa datoteku na zaslon
"""


def Obrada(komanda, parametar, argument):
    if (parametar == "" or argument == "" or parametar != "-a" and parametar != "-r"):
        print("Ova komanda mora sadržavati parametar(-a za pisanje ili -r za čitanje) i argument(put)")
    else:
        if (parametar == "-a"):

            f = open(argument, 'a')
            brojac = "e"
            print(
                "Sada možete upisivati u vašu datoteku,za izlaz upisite 'esp' i pritisnite enter")
            while brojac != 'esp':
                brojac = input()

                if (brojac != 'esp'):
                    f.writelines(a)
                f.close()
        if (parametar == '-r'):
            if (os.path.isfile(argument) == True):
                f = open(argument, 'r')
                print(f.read())
                f.close()
            else:
                print("Datoteka ne postoji")


"""
Ovo je funkcija koju korisnik nemože pozvat a,služi kako bi provjerila kakva je vrsta adrese i dali adresa postoji

Argumenti su joj adresa koja učitava prvo slovo te prepoznaje po tome vrstu adrese i vraća broj izlaza za druge funkcije
kao return

Funkcija vraća broj izlaza ovisno o argumentu

(savjet: maknut ovu funkciju iz programa i stavitu u funnkcije try)
"""


def ProvjeraAdrese(argument, izlaz):
    if (argument[0] == "."):
        if (len(argument) >= 2):
            if (argument[1] == "/"):
                if (re.search(argument[2:], os.getcwd())):
                    izlaz = 1
                else:
                    izlaz = 0
            if (argument[1] == "."):
                if ((
                        os.path.exists(
                            argument)) == True):  # if (os.path.exists(os.getcwd()) == True): Manje koda sa regexom
                    izlaz = 5
                else:
                    izlaz = 0
        else:
            izlaz = 2

    if (argument[0] == "/"):
        if (os.path.exists(argument)):
            izlaz = 3
        else:
            izlaz = 0
    # os.chdir(os.getcwd()+"/"+argument)

    return izlaz


"""
Ova funkcija mijenja direktoriji koji je aktivan

Argumenti:
Argument koji korisnik unese kao adresu, koji se pregleda prijašnom zadanom funkcijom
Pregledadrese

Vraća:
mjenja aktivnu datoteku ovisno o izlazu funkcije Provjeraadrese ,ali ako korisnik nije uneso argument
vraća adresu home direktorija


"""


def cd(naredba, parametar, argument, provjera):
    if (parametar == ""):
        if (argument == ""):
            home = (os.path.expanduser("~"))  # homeee
            os.chdir(home)
        else:
            provjera = ProvjeraAdrese(argument, 0)

            if (provjera == 1):

                b = (re.search(".*" + argument[2:], os.getcwd()))
                b = b.group()
                os.chdir(b)
            elif (provjera == 2):
                os.chdir((os.getcwd()))
            elif (provjera == 3):
                os.chdir((argument))

            elif (provjera == 5):

                os.chdir(argument)
            elif (provjera == 0):
                print("Nepostojeći direktoriji, komanda nije ostvarena")
    else:
        print("Ova komanda nema ugrađenih parametara")
    return provjera


"""
Funkcija koja izlistava stavke direktoija

Argumenti su joj adresa koja mora bit apsolutna koju korisnik unese te parametar -l

Funkcija vraća grešku ako su krivi argumenti
ako nije korišten parametar funkcija vraća listu ali ako je korišten parametar
onda vraća detaljnu listu

"""


def ls(naredba, parametar, argument):
    b = 0
    osiguranje = (
        os.getcwd())  # ako želimo da nam sa lsom mjenja trenutni pokazivac na datoteku maknuli bismo ovu varibalu
    provjera = 0
    if (argument == ''):
        argument = os.getcwd()
        provjera = 3
    else:
        provjera = cd(cd, "", argument, provjera)

    if (provjera != 3 and provjera != 0):

        print('Komanda ls prima samo apsolutnu adresu')

    elif (provjera != 0):

        if (os.listdir(argument) == 0):
            print("direktoriji je prazan")
        elif (parametar == ''):
            for i in os.listdir(argument):
                if not (i.startswith('.')):
                    print(i)
        elif (parametar == "-l"):
            for i in os.listdir(argument):
                if not (i.startswith('.')):
                    b = (os.stat(argument))
                    print(i, "\tDozvole:", b[0], "\tBroj čvrstih poveznica:", b[3], "\t Uid vlasnika: ", b[4],
                          "\tGid vlasnika: ", b[5], "\tVeličina: ", b[6])
                #  print(i+"\t"+b)
            else:
                print("komanda ls ne prepoznaje argument, mogući argumenti -l")

    os.chdir(osiguranje)


"""
Funkcije mkdir i rmdir su slične funkcije mkdir stvara novi direktoriji , a rmdir briše

Argumenti-Put koji korisnik unese

Kod mkdir stvara novu datoteku ako je putanja dobro napisana
Kod rmdir pregledava dali je direktoriji prazan ako je putanja točna te ga briše ako je

(ovdje smo skužili da možemo koristit try)

"""


def mkdir(komanda, parametar, argument):  # najkracemoguce
    if (argument == "" or parametar != ""):
        print("ova naredba zahtjeva najmanje jedan argument i nesmije sadržavati parametre")
    else:
        try:
            os.mkdir(argument)
        except OSError as error:
            if (os.path.exists(argument) == False):
                print("Put do toga direktorija ne postoji")
            else:
                print("Direktoriji već postoji")


def rmdir(komanda, parametar, argument):
    if (argument == "" or parametar != ""):
        print("ova naredba zahtjeva najmanje jedan argument i nesmije sadržavati parametre")
    else:
        try:
            os.rmdir(argument)
        except OSError as error:
            if (os.path.exists(argument) == False):
                print("Nije moguće pronaći željeni direktoriji")
            elif (os.listdir(argument) != True):
                print("Direktoriji nije prazan, pa se neće izbrisati")
            else:
                print("Nemate prava brisati taj direktoriji")


"""
Printa sve funkcije korisniku

"""


def help():
    print("pwd-Funkcija ispisuje u kojem se direktoriju nalazite-bez parametara-bez argumenata\n"
          "ps-Ispisuje trenutni pd ljuske-bez parametara-bez argumenata\necho-kopira vas unos-bez parametara-argument obavezan"
          "cd-naredba koja mjenja pokazivač na trenutnom direktoriju,prima relativne i apsolutne adrese-bez parametara-obavezan argument kao adresa"
          "\ndate-Ispisuje datum i vrijeme-parametar -s=promjena u 24-satni oblik-bez argumenata\n"
          "ls-naredba koja lista datoteke u direktoriju-argument-put do direktorija-parametar -l =duga i detaljna lista\n"
          "mkdir-radi folder u željenom direktoriju,prima apsolutne i relativne adrese-argument-put i ime nove mape-bez parametara\n"
          "rmdir-briše prazan direktoriji-argument put do direktorija-bez parametra"
          "\nkvadrat-prikaz rada dredvi-bez argumenti-bez parametara\"n"
          "close-izlaz")

# Nasumično generirana sol
salt = crypt.mksalt()


# Funkcija za izradu novih korisnika, provjera da li korisnik posotoji, soljenje passworda i upisavanje u config datoteku
def NewUser():
    userConfig = configparser.ConfigParser()
    userConfig.read('users-passwords.conf')
    sameUsername = True
    while sameUsername == True:
        user = input("Username : ")
        for key in userConfig.sections():
            if(user == userConfig.get(key, 'Username')):
                print("Username already exists...")
                sameUsername = True
                break
            else:
                sameUsername = False

    password = input("Password : ")
    # Haširanje passworda
    hashedPassword = crypt.crypt(password, salt)
    config = configparser.ConfigParser()
    config[user] = {'Username': user,
                    'Password': hashedPassword, 'Salt': salt}
    with open('users-passwords.conf', 'a') as configfile:
        config.write(configfile)


# Poslužitelj
def Remoteshd():
    serverConfig = configparser.ConfigParser()
    userConfig = configparser.ConfigParser()
    serverConfig.read('remoteshd.conf')
    userConfig.read('users-passwords.conf')

    # Serijalizacija privatnog ključa iz PEM kodiranih podataka u jednu od podržanih asimetričnih vrsta
    with open("private_key.pem", "rb") as keyFile:
        private_key = serialization.load_pem_private_key(
            keyFile.read(),
            password=b'42230',
            backend=default_backend()
        )

    HEADER = 20
    PORT = int(serverConfig.get('INFO', 'Port'))
    SERVER = socket.gethostbyname(socket.gethostname())
    ADDRESS = (SERVER, PORT)

    # Socket se spaja na adresu
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDRESS)

    # Provjera za novu konekciju od klijenta na poslužitelj
    def Client(connection, address):
        print(bcolors.OKGREEN +
              f"\nNew connection from adress: {address}" + bcolors.ENDC)
        connected = True
        if (Login(connection) == True):
            cipherText1 = connection.recv(1024)
            # Dekripcija simetričnog ključa ako je login uspješan
            decryptedSymmetricKey = private_key.decrypt(
                cipherText1,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))

            backend = default_backend()
            cihper2 = Cipher(algorithms.ARC4(
                decryptedSymmetricKey), mode=None, backend=backend)
            decryptor = cihper2.decryptor()

            while connected:
                fullMSG = ''
                newMSG = True
                counter = 0
                while counter < 2:
                    counter = counter + 1
                    if(newMSG == True):
                        fullMSG = ''
                    MSG = connection.recv(1024)
                    if not MSG:
                        break
                    if newMSG:
                        MSGlength = int(len(MSG))
                        newMSG = False
                    fullMSG = MSG

                    # Dekripcija poruka
                    if len(fullMSG) == MSGlength:
                        if(counter == 1):
                            print(decryptor.update(fullMSG).decode())
                        if(counter == 2):
                            (decryptor.update(fullMSG).decode())
                        if(counter == 3):
                            print(decryptor.update(fullMSG).decode())

                    newMSG = True

            else:
                connection.close()

    # Pokretanje poslužitelja
    def Start():
        print(bcolors.OKGREEN + "Server is starting..." + bcolors.ENDC)
        print(bcolors.OKCYAN +
              f"Server is active on address  : {ADDRESS}" + bcolors.ENDC)
        server.listen()
        while True:
            # Prihvačanje klijenata na poslužitelja
            connection, address = server.accept()
            Client(connection, address)


    # Login
    def Login(connection):
        while True:
            connection.send(bytes("\nLOGIN", "utf-8"))
            messageLength1 = connection.recv(HEADER).decode("utf-8")
            if messageLength1:
                messageLength1 = int(messageLength1)
                username = connection.recv(messageLength1).decode("utf-8")
                for key in userConfig.sections():
                    if(username == userConfig.get(key, 'Username')):
                        connection.send(
                            bytes(userConfig.get(key, 'Salt'), "utf-8"))
                        messageLength2 = connection.recv(
                            HEADER).decode("utf-8")
                        messageLength2 = int(messageLength2)
                        Password = connection.recv(
                            messageLength2).decode("utf-8")
                        if(Password == userConfig.get(key, 'Password')):
                            connection.send(
                                bytes("\nSuccess!", "utf-8"))
                            return True
                connection.send(
                    bytes("\nError. Wrong username or password!", "utf-8"))

    Start()

# Klijent
def Remotesh():
    clientConfig = configparser.ConfigParser()
    clientConfig.read('remoteshd.conf')
    HEADER = 20
    PORT = int(clientConfig.get('INFO', 'Port'))
    SERVER = socket.gethostbyname(socket.gethostname())
    ADDRESS = (SERVER, PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDRESS)

    key = os.urandom(5)
    backend = default_backend()
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=backend)

    encryptor = cipher.encryptor()
    symetricKeyClient = key

    with open("public_key.pem", "rb") as keyFile:
        public_key = serialization.load_pem_public_key(
            keyFile.read(),
            backend=default_backend()
        )
    # Enkripcija pomoću simetričnog ključa
    cipherText2 = public_key.encrypt(
        symetricKeyClient,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )
    # Slanje poruka
    def Send(mess):
        message = mess.encode("utf-8")
        messageLength = len(message)
        sendLength = str(messageLength).encode("utf-8")
        sendLength += b' ' * (HEADER - len(sendLength))
        client.send(sendLength)
        client.send(message)

    def SendMessage(MESSAGE1):
        message = MESSAGE1
        client.send(message)

    while True:
        mess = client.recv(2048)
        message = mess.decode("utf-8")
        message1 = message.split("\n")
        for i in message1:
            # Input za username i password
            if (i == "LOGIN"):
                username = input(
                    bcolors.BOLD+"\nEnter Username :"+bcolors.ENDC)
                password = input(
                    bcolors.BOLD+"\nEnter Password :"+bcolors.ENDC)
                Send(username)

            if (i.startswith('$')):
                sendHashedPassword = crypt.crypt(password, i)
                Send(sendHashedPassword)
            else:
                if(i != "LOGIN"):
                    print(i)
                if(i == "Success!"):
                    client.send(cipherText2)
                    exit = False
                    while exit == False:
                        # Unos bash komandi
                        input1 = input(
                            "[" + os.getlogin() + "@" + os.uname()[1] + "]" + os.getcwd() + " $ ")
                        if (input1 == 'exit'):
                            exit = True
                        os.system(input1)
                        status = str(os.popen('echo $?').read())
                        output = os.popen(input1).read()
                        encryptedMessage1 = encryptor.update(input1.encode())
                        encryptedMessage2 = encryptor.update(status.encode())
                        encryptedMessage3 = encryptor.update(output.encode())

                        thread = threading.Thread(
                            target=SendMessage, args=(encryptedMessage1,))
                        thread.start()
                        thread2 = threading.Thread(
                            target=SendMessage, args=(encryptedMessage2,))
                        thread2.start()
                        thread3 = threading.Thread(
                            target=SendMessage, args=(encryptedMessage3,))
                        thread3.start()

#Bruteforce
def BruteForce():
    userConfig = configparser.ConfigParser()
    userConfig.read('users-passwords.conf')
    username = input(bcolors.BOLD+"Enter Username : "+bcolors.ENDC)
    for key in userConfig.sections():
        if(username == userConfig.get(key, 'Username')):
            Salt = userConfig.get(key, 'Salt')
    hashedPassword = 0
    time1 = time.perf_counter()
    COUNT = 0
    chars = string.ascii_letters + string.digits
    passwordLength = 0
    while hashedPassword != userConfig.get(username, 'Password'):
        passwordLength = passwordLength + 1
        for crackedPassword in itertools.product(chars, repeat=passwordLength):
            crackedPassword = ''.join(crackedPassword)
            COUNT = COUNT + 1
            hashedPassword = crypt.crypt(crackedPassword, Salt)
            if (COUNT % 500 == 0):
                print(
                    "\033[93mTried\033[0m {} \033[93mkeys.\033[0m".format(COUNT))
            if(hashedPassword == userConfig.get(username, 'Password')):
                time2 = time.perf_counter()
                time3 = time2-time1
                print(
                    "\033[92mPassword for user:\033[0m {} \033[92mhas been cracked. Password is:\033[0m {} \n\n\033[92mElapsed time:\033[0m {} \033[92mseconds\033[0m\n\n\n".format(username, crackedPassword, time3))
                break


# ----------------------------------------------------------------------------------------------------------------
i = 1
#


PozdravnaPoruka()
komanda = 0
pisanje = open("povv", 'a')

while (True):
    # prompt ispis te "deklariranje" parametra i argumenata da mogu biti prazni
    prompt = (("{}::{}::{}$ ".format(
        os.getlogin(), os.uname()[0], os.getcwd())))
    a = input(prompt)
    naredba = ''
    parametar = ''
    argument = ''

    # ovaj tu dio je trebo čitat datoteku te ako se unese naredba izbrisat 30 redak ali nismo uspjeli implementirat
    # if(q.qsize()==30):
    #   q.get(30)

    q.put(a)

    # Ove tu naredbe uz pomoć regex razlikuju komandu parametar i argument te ih sprema u format koje naš program prepoznaje
    if (re.search('^[\w]+', a)):
        naredba = (re.search('^[\w]+', a))
        naredba = naredba.group()
    if (re.search('-[\w]', a)):
        parametar = (re.search('-[\w]', a))
        parametar = parametar.group()

    pomocna = a
    pomocna = re.sub(r'(-[\w])', "", pomocna)
    pomocna = re.sub(r'^[\w]+', "", pomocna)
    pomocna = (re.findall(r'[\S]+', pomocna))

    if (pomocna != ['']):
        pomocna = " ".join(pomocna)
        argument = pomocna
    else:
        argument = ""

    """
    Ovaj tu dio pregleda dali komanda postoji te ako postoji pomoću if pozove gornju funkciju

    """

    if (naredba == "pwd"):
        c = pwd(naredba, parametar, argument)

    elif (naredba == "ps"):
        v = ps(naredba, parametar, argument)

    elif (naredba == "echo"):
        echo(naredba, parametar, argument)
    elif (naredba == "cd"):
        cd(naredba, parametar, argument, 0)
    elif (naredba == "date"):
        datum(naredba, parametar, argument)
    elif (naredba == "ls"):
        ls(naredba, parametar, argument)
    elif (naredba == "mkdir"):
        mkdir(naredba, parametar, argument)
    elif (naredba == "rmdir"):
        rmdir(naredba, parametar, argument)
    elif (naredba == "exit" or naredba == "close"):
        pisanje.seek(0)
        pisanje.write("")
        while not q.empty():
            pisanje.writelines(q.get())
            pisanje.write('\n')
        pisanje.close()
        sys.exit()
    elif (naredba == "kvadrat"):
        kvadrat(parametar, argument)
    elif (naredba == "Obrada"):
        Obrada(naredba, parametar, argument)
    elif (naredba == 'POZ'):
        PozdravnaPoruka()
    elif (naredba == 'help'):
        help()
    elif (naredba == 'newuser'):
        NewUser()
    elif (naredba == 'remoteshd'):
        Remoteshd()
    elif (naredba == 'remotesh'):
        Remotesh()
    elif (naredba == 'brute'):
        BruteForce()
    else:
        print("Netočna komanda,upišite \"help\" za više informacija!")