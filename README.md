
<h1 align="center">
  Linux Bash clone 
  <br>
</h1>

<h4 align="center">Python script that simulates Linux bash with implemented secure shell between two instances of the runing script.</h4>

<p align="center">
  <img src="https://media2.giphy.com/media/FbiCh1wzpruoDAzykK/giphy.gif?cid=790b7611e4a71f047b6b3343763c8158f9dd8e955b03dab1&rid=giphy.gif&ct=g" alt="linux" />
</p>




## How To Use Bash

To clone and run this application, you'll need Python3+ installed on your machine.


Clone this repository
```bash
$ git clone https://github.com/DBDoco/Linux-Bash-Clone.git
```

Go into the repository
```bash
$ cd Linux-Bash-Clone
```

Run the script
```bash
$ sudo python bash.py
```

For information on the available commands type "help" 


## How To Use SSL

In remoteshd.conf type server and client port (same port is used for both.) 

Run the key script (generates RSA key pair)
```bash
$ sudo python generate_key.py
```

Run the script
```bash
$ sudo python bash.py
```

Create users that can login on the server (hashed and saved in users-passwords.conf)
```bash
$ newuser
```

In one terminal run server
```bash
$ remoteshd
```

In second terminal run client that connects on the server
```bash
$ remotesh
```
