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
    Permet de chiffrer en Cesar le 'txt' avec la cle 'key'
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
    Permet de dechiffrer en Cesar le 'txt' avec la cle 'key'
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
    Chiffre un texte avec Vigenère.
    On décale chaque lettre par la valeur de la clé correspondante.
    Si la clé est plus courte, on boucle dessus avec un modulo.
    """
    texte = txt
    txt = ""
    base = ord('A')
    i = 0
    for c in texte:
        char = ((ord(c) - base) + key[i]) % 26 + base
        txt += chr(char)
        i = (i+1) % len(key) # On passe à la lettre suivante de la clé
    return txt

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    Déchiffre un texte avec Vigenère.
    Même principe que le chiffrement mais on soustrait la clé.
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
    Compte le nombre d'apparitions de chaque lettre de l'alphabet 
    dans le texte passé en paramètre. Renvoie une liste de 26 éléments.
    """
    hist=[0.0]*len(alphabet)
    for c in txt:
        if c in alphabet:
            indice = alphabet.index(c)
            hist[indice] += 1.0
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    Cherche l'indice de la lettre qui apparaît le plus souvent.
    Utile pour supposer que cette lettre correspond au 'E'.
    """
    list = freq(txt)
    return list.index(max(list))

# indice de coïncidence
def indice_coincidence(hist):
    """
    Calcule l'indice de coïncidence (IC) à partir d'un histogramme de fréquences.
    Plus le texte ressemble à du français, plus l'IC est proche de 0.07.
    """
    res = 0.0
    total = sum(hist)
    # Sécurité pour éviter la division par zero si la colonne est trop petite
    if total <= 1.0:
        return 0.0
    for valeur in hist:
        res += (valeur * (valeur - 1.0))/(total * (total - 1.0))
    return res

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    Teste les longueurs de clé de 1 à 20.
    Découpe le texte en colonnes et calcule l'IC moyen.
    Dès que l'IC moyen dépasse 0.06, on considère qu'on a trouvé la bonne taille.
    """
    for key in range(1,21):
        IC_moyen = 0
        colonnes = [cipher[i::key] for i in range(key)]

        for colonne in colonnes:
            IC_moyen += indice_coincidence(freq(colonne))
        
        IC_moyen /= key

        if IC_moyen > 0.06:
           return key
    return 0
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    Pour chaque colonne, on cherche la lettre la plus fréquente.
    On suppose que c'est un 'E' chiffré, ce qui nous donne le décalage.
    """
    decalages=[0]*key_length
    colonnes = [cipher[i::key_length] for i in range(key_length)]
    i = 0
    for colonne in colonnes:
        indice_max = lettre_freq_max(colonne)
        decalages[i] = (indice_max - alphabet.index('E'))% len(alphabet)
        i+=1

    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    Réalise l'attaque de base (longueur de clé + lettre la plus fréquente).
    
    Analyse (Test 5) : Seulement 18 textes ont été cryptanalysés. 
    Explication : Si le texte est trop court, le découpage en colonnes fait que les colonnes contiennent très peu de lettres. Les statistiques sont faussées 
    et la lettre la plus fréquente de la colonne n'est pas forcément le 'E'.
    """
    key_length = longueur_clef(cipher)
    decalages = clef_par_decalages(cipher,key_length)
    
    return dechiffre_vigenere(cipher,decalages)


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Calcule l'ICM entre deux colonnes (h1 et h2) avec un décalage d.
    Permet de voir si les deux colonnes ont été chiffrées avec la même lettre.
    """
    res = 0.0
    nb_lettres = sum(h1) * sum(h2)

    if nb_lettres == 0:
        return 0.0
    
    for i in range(len(h1)):
        indice_decalage = (i+d)%len(h2)
        res += (h1[i] * h2[indice_decalage]) / nb_lettres
    return res

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Prend la première colonne comme référence.
    Pour chaque autre colonne, teste tous les décalages (0 à 25) 
    pour trouver celui qui maximise l'ICM avec la référence.
    """
    decalages=[0]*key_length
    colonnes = [cipher[i::key_length] for i in range(key_length)]
    reference = freq(colonnes[0])
    for i in range(1,len(colonnes)):
        decalage = 0
        recherche = freq(colonnes[i])
        for j in range(len(alphabet)):
            if(indice_coincidence_mutuelle(reference,recherche,j) > indice_coincidence_mutuelle(reference,recherche,decalage)):
                decalage = j
        decalages[i] = decalage
    
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Trouve les décalages relatifs avec l'ICM pour "aplatir" le Vigenère 
    en un simple code de César, puis casse ce César.
    
    Analyse (Test 7) : Ici on obtient 43 textes cryptanalysés c'est à dire meilleur que la v1
    Explication : Si le texte est court ou atypique, la lettre globale la plus fréquente du texte César (texte_cesar) 
    peut ne pas être le 'E'. Si on se trompe de référence finale, tout le texte est faux.
    """
    key_length = longueur_clef(cipher)
    decalages = tableau_decalages_ICM(cipher,key_length)
    res = []
    
    # On aligne tout sur la colonne 0 (ça devient un César)
    for i in range(len(cipher)):
        res.append(dechiffre_cesar(cipher[i],decalages[i % key_length]))
    texte_cesar = "".join(res)
    
    # On casse le César final en cherchant le 'E'
    return dechiffre_cesar(texte_cesar, (ord(alphabet[lettre_freq_max(texte_cesar)]) - ord('E')))


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    Calcule le coefficient de corrélation de Pearson entre deux histogrammes.
    Plus le résultat est proche de 1, plus les listes se ressemblent.
    """
    espX = 1/len(L1) * sum(L1)
    espY = 1/len(L2) * sum(L2)

    num = 0.0
    denX = 0.0
    denY = 0.0
    for i in range(len(L1)):
        num += (L1[i] - espX) * (L2[i] - espY)
        denX += (L1[i] - espX)**2
        denY += (L2[i] - espY)**2
        
    if denX == 0.0 or denY == 0.0:
        return 0.0
        
    # Arrondi pour éviter les erreurs de précision (les fameux 0.9999999)
    return round(num / (math.sqrt(denX) * math.sqrt(denY)),10)

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Compare chaque colonne directement avec les fréquences du français (freq_FR).
    Renvoie le score moyen de corrélation et le tableau de la clé trouvée.
    """
    key=[0]*key_length
    score = 0.0
    colonnes = [cipher[i::key_length] for i in range(key_length)]
    j=0
    for colonne in colonnes:
        dec_max = 0.0
        corr_max = -1.0
        for i in range(len(alphabet)):
            frecC = freq(dechiffre_cesar(colonne,i))
            currentC = correlation(freq_FR,frecC)
            if currentC > corr_max:
                corr_max = currentC
                dec_max = i
        score += corr_max
        key[j] = dec_max
        j+=1
        
    score = score / key_length

    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Teste toutes les longueurs de clé (de 1 à 20) et garde celle 
    qui donne le meilleur score de corrélation de Pearson.
    
    Analyse (Test 9) : On obtient 94 textes cryptanalysés.C'est la méthode la plus robuste car elle compare
    directement à l'alphabet complet français, pas juste à la lettre 'E'. 
    Les textes qui échouent sont généralement extrêmement courts (statistiques 
    inexploitables) ou alors ce sont des textes où la répartition des lettres
    est artificiellement modifiée (par exemple un texte sans la lettre E).
    """
    key = []
    corr = 0.0
    for i in range(1,21):
        currentC = clef_correlations(cipher,i)
        # On cherche le score maximum parmi toutes les longueurs
        if corr < currentC[0]:
            corr = currentC[0]
            key = currentC[1]
        
    return dechiffre_vigenere(cipher,key)


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