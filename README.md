# PoC : Tests unitaires qui interagissent avec une machine virtuelle pour un outil de scan de ports

### Création d'un venv : un environnement virtuel Python pour le projet
1. Créer l'environnement virtuel : `python -m venv .venv`
2. Activer l'environnement virtuel (sous Unix ou MacOS) :
   `source .venv/bin/activate`
3. Installer toutes les dépendances du projet : `pip install -r requirements.txt`
4. Exécuter des scripts Python du projet...
5. Sortir de l'environnement virtuel : `deactivate`

### Exécution de la console Scapy (utile pour les tests) à partir du venv
```sudo -E $(which scapy)```

### Exécution du fichier `src/port_scanner/network_scanner.py` à partir du venv
```sudo .venv/bin/python src/port_scanner/network_scanner.py ip start_port end_port ```


### Tests unitaires
L'exécution des tests unitaires pour les scans de ports nécessite l'accès à un serveur avec un système d'exploitation 
de la famille Unix auquel il est possible de se connecter via SSH sans mot de passe, idéalement 
[Ubuntu Server](https://ubuntu.com/download/server). Une deuxième exigence est l'existence d'une configuration 
permettant d'exécuter la commande `iptables` en sudo sur ce serveur sans avoir besoin de saisir un mot de passe. **De toute évidence, une telle configuration permettant d'exécuter une commande en sudo sans mot de passe ne doit pas être utilisée dans un environnement de production.**

Ces deux prérequis sont nécessaires afin de pouvoir ajouter des règles `iptables` et les supprimer, selon les besoins des différents tests.

L'exécution de tests unitaires écrits à l'aide du framework [Pytest](https://pytest.org/) se fait simplement à l'aide 
de la commande `pytest`. Cependant, dans le cas de l'outil d'analyse de ports, l'utilisation de `scapy` nécessite généralement également l'utilisation 
de `sudo`.

De plus, le caractère unique des tests unitaires nécessaires pour vérifier les performances de notre outil nécessite 
l'utilisation de 3 options qui ont été définies à l'aide de Pytest spécialement pour cet outil. Ces options permettent 
de définir l'adresse IP du serveur de test, le nom d'utilisateur par lequel la connexion SSH se fera, 
ainsi que le chemin menant à la clé privée qui permettra la connexion SSH sans mot de passe :
```
sudo pytest --host=10.0.2.16 --username=namolaru --pkey=/home/namolaru/.ssh/id_rsa
```

**Exécution des tests unitaires à partir d'un venv :**
`
sudo .venv/bin/pytest --host=10.0.2.16 --username=namolaru --pkey=/home/namolaru/.ssh/id_rsa
`
L'utilisation de cette commande entraîne l'exécution des tests dans les fichiers du sous-répertoire `tests`. 
