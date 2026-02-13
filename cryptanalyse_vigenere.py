# Sorbonne Université 3I024 2024-2025
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : Ramaholison 21301758
# Etudiant.e 2 : Singh 21239295 

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [0.09213414037491088, 0.010354463742221126, 0.030178915678726964, 0.03753683726285317, 0.17174710607479665, 0.010939030914707838, 0.01061497737343803, 0.010717912027723734, 0.07507240372750529, 0.003832727374391129, 6.989390105819367e-05, 0.061368115927295096, 0.026498684088462805, 0.07030818127173859, 0.049140495636714375, 0.023697844853330825, 0.010160031617459242, 0.06609294363882899, 0.07816806814528274, 0.07374314880919855, 0.06356151362232132, 0.01645048271269667, 1.14371838095226e-05, 0.004071637436190045, 0.0023001447439151006, 0.0012263202640210343]

# Chiffrement César
def chiffre_cesar(txt, key):
    """
    Permet de chiffrer le 'txt' avec la cle 'key'
    txt -> le texte à chiffrer
    key -> la clé de chiffement
    """
    texte = txt
    txt = ""
    base = ord('A')
    for c in texte:
	    char = ((ord(c) - base) + key) % 26 + base
	    txt += chr(char)
   
    return txt

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    Permet de dechiffrer le 'txt' avec la cle 'key'
    txt -> le texte à dechiffrer
    key -> la clé de déchiffement
    """
    texte = txt
    txt = ""
    base = ord('A')
    for c in texte:
        char = ((ord(c) - base) - key) % 26 + base
        txt += chr(char)
    return txt

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    Documentation à écrire
    """
    texte = txt
    txt = ""
    base = ord('A')
    i = 0
    for c in texte:
        char = ((ord(c) - base) + key[i]) % 26 + base
        txt += chr(char)
        i = (i+1) % len(key)
    return txt

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    Documentation à écrire
    """
    texte = txt
    txt = ""
    base = ord('A')
    i = 0
    for c in texte:
        char = ((ord(c) - base) - key[i]) % 26 + base
        txt += chr(char)
        i = (i+1) % len(key)
    return txt

# Analyse de fréquences
def freq(txt):
    """
    Documentation à écrire
    """
    hist=[0.0]*len(alphabet)
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    Documentation à écrire
    """
    return 0

# indice de coïncidence
def indice_coincidence(hist):
    """
    Documentation à écrire
    """
    return 0.0

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    Documentation à écrire
    """
    return 0
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    Documentation à écrire
    """
    decalages=[0]*key_length
    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Documentation à écrire
    """
    decalages=[0]*key_length
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Documentation à écrire
    """
    key=[0]*key_length
    score = 0.0
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
