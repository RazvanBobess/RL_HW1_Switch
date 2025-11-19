1 2

Deciziile de design au fost:

    Pentru Forwarding Logic, am folosit o structura de tip pair, numita mac_table.
Aceasta lista contine toate intrarile de tip mac. Fiecarui mac ii este asociat o interfata

    Initial verific daca destination mac este de tip unicast. Daca este, verific daca am o interfata i asociata
acelei destinatii in lista mac. Daca am gasit, trimit pe interfata i cadrul de lungime len(data) si cadrul in sine data.
Daca nu il gasesc / nu am o interfata, dau flood in retea.
    Altfel, daca destination mac este de tip multicast, dau flood, trimit pachete pe toate interfetele, mai putin pe
interfata de unde a venit.

    Pentru a verifica daca o adresa este de tip unicast, am creat o functie auxiliara numita is_unicast() daca primul bit
al adresei mac are valoarea 0.

    Pentru citirea datelor din fisierul switchX.cfg al switch-ului asociat, am creat o functie auxiliara parser_vlan
care imi citeste linie cu linie fisierul de intrare. Prioritatea switch-ului o pun intr-o variabila auxiliara switch_priority.
Folosesc o structura de tip pair numita vlan_config care pentru tipul fiecare nume de interfata ii asociez o valoare, fie un int care
reprezinta vlan-ul, fie 'T' care reprezinta un port de tip trunk. La finalul apelului functiei, returnez structura vlan_config si
switch_priority.

    In ex1.jpg -> trimit un cadru de la host0 (switch0) la host2 (switch1), unde ambele switch-uri sunt pornite
               -> pe swtich0 am deschis o fereastra wireshark care verifica cadrele primite de la host-uri
               -> in aceasta poza apar cadrele de ICMP request si reply trimise intre host0 si host2

    Pentru implementarea VLAN-ului, am implementat mai multe functii cu diferite functionalitati:

-- calculate_mac_nibble() -> calculeaza nibble-ul pentru o adresa mac primita ca parametru (adunarea bitilor) 

-- extract_vlan_id() -> imi extrage dintr-un pachet extins cu 802.1Q header VID-ul

-- send_on_trunk_or_not_ports() -> este apelata in cazul in care destination mac nu este gasita in mac table sau daca
                                   adresa mac este de tip mulitcast

                                -> In aceasta functie verific tipul interfetelor de unde a venit cadrul si tipul interfetei unde
                                    trebuie sa trimit cadrul. Daca trimit un cadrul dintr-un port de access la un alt port de access, verific
                                    daca se afla in acelasi vlan. Daca cadrul este transmis de la o interfata de tip trunk si interfata de iesire
                                    este de tip access, atunci scot din cadru extensia .1Q si verific daca VID se potriveste cu VLAN-ul interfetei unde
                                    vreau sa trimit cadrul. Daca cadrul vine de la o interfata de tip access si este transmis pe o interfata de tip trunk,
                                    atunci cadrului ii adaug .1Q header si il trimit pe acea interfata. Daca nu se respecta niciuna dintre cazuri, atunci
                                    inseamna ca interfetele sunt de tip trunk, iar cadrul este trimis asa cum e.

    In main, pastrez logica de la Forwarding si adaug logica explicata mai sus de la send_on_trunk_or_not_ports() pentru fiecare tip de destination mac
(unicast, cu o interfata asociata / fara interfata asociata, sau multicast)

    In ex2.jpg + ex2.1.jpg -> in ex2.1.jpg am aratat cum sunt transmise pachetele de la host0 la host2, care sunt in acelasi vlan (1)
                           -> fereastra de wireshark este deschisa pentru host2 care primeste cadrele de tip ICMP (reply + request) + cadrele HPDU
                              (uneori mai sunt receptate cereri de ARP)