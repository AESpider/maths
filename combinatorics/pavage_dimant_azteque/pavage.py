from enum import Enum

import random
import matplotlib.pyplot as plt

# AESpider

        ##
       ####
      ######
     ########
    ##########
   ############
  ##############
 ################
##################
##################
 ################
  ##############
   ############
    ##########
     ########
      ######
       ####
        ##

class Couleur(Enum):
  VIDE = 0       # Represente un case vide
  B_BLEU = 1     # la case blanche d'un domino bleu
  N_BLEU = 2     # la case noir d'un domino bleu
  N_ROUGE = 3    # la case noir du rouge
  B_ROUGE = 4    # la case blanche du rouge
  B_VERT = 5     # la case blanche du vert
  N_VERT = 6     # la case noir du vert
  N_JAUNE = 7    # la case noir du jaune
  B_JAUNE = 8    # la case blanche du jaune
  
# Renvoie le nombre de cases à la ligne i, d'un diamant de taille n
def nb_colls(ligne, n): 
  return 2 + 2*ligne if ligne < n else 2*n - 2*(ligne % n)

# Revoie vrai si la case est occupé par un domino bleu
def est_bleu(case):
  return case == Couleur.B_BLEU or case == Couleur.N_BLEU

# Revoie vrai si la case est occupé par un domino vert
def est_vert(case):
  return case == Couleur.B_VERT or case == Couleur.N_VERT

# Revoie vrai si la case est occupé par un domino rouge
def est_rouge(case):
  return case == Couleur.N_ROUGE or case == Couleur.B_ROUGE

# Revoie vrai si la case est occupé par un domino jaune
def est_jaune(case):
  return case == Couleur.N_JAUNE or case == Couleur.B_JAUNE

# Initialisation d'une diamant de taille n en mettant toutes ses case vides
def ini_diamant(n):

  nombre_lignes = 2*n

  diamant = []

  for ligne in range(nombre_lignes):

    nombre_cases = nb_colls(ligne, n)

    # Initialisation de la ligne avec des cases vides
    diamant.append([Couleur.VIDE] * nombre_cases)

  return diamant

# Renvoie vrai si le diamant contient une case vide.
def le_diamant_a_case_vide(diamant):
  for i in range(len(diamant)):
    for j in range(len(diamant[i])):
      if diamant[i][j] == Couleur.VIDE:
        return True
  return False

# Copie un diamant 
def copie_diamant(diamant):

  newDiamant = []
  
  for ligne in range(len(diamant)):
    
    # Initialisation de la ligne avec celle du diamant à copier
    newDiamant.append(list(diamant[ligne]))

  return newDiamant

# Renvoie vrai si les diamant sont pavés de la même manière.
def les_diamants_sont_egaux(diamant1, diamant2):
  if len(diamant1) != len(diamant2):
    return False
  for i in range(len(diamant1)):
    if len(diamant1[i]) != len(diamant2[i]):  # ✓ Comparer les longueurs des lignes
      return False
    for j in range(len(diamant1[i])):
      if diamant1[i][j] != diamant2[i][j]:
        return False
  return True


    ##         ##         ##         ##         ##
   ####       ####       ####       ####       ####
  ######     ######     ######     ######     ######
 ########   ########   ########   ########   ########
########## ########## ########## ########## ##########
########## ########## ########## ########## ##########
 ########   ########   ########   ########   ########
  ######     ######     ######     ######     ######
   ####       ####       ####       ####       ####
    ##         ##         ##         ##         ##


# Une cellule est une region (2x2) dont les 4 cases sont à l'intérieur du diamant.
# Renvoie vrai si la case (i,j) est la case en haut à gauche d'une cellule active
def est_case_haut_gauche_de_cellule_active(i, j, nb_colls, n):
  if i < n :
    return j%2 == 1 and j != nb_colls-1 
  else : 
    return j%2 == 0 and j != 0 and j != nb_colls-2

# Renvoie vrai si la cellule active est destructible, faux sinon
# Autrement dit si la cellule active possède une paire de domino vertical ou horizontal 
# Soit [B_VERT, DNOIR]  ou  [B_BLEU, N_BLEU]
#      [N_VERT, FNOIR]      [N_ROUGE, B_ROUGE]
def destructible(diamant, i, j, n):
  case = diamant[i][j]
  if i < n-1:
      return (case == Couleur.B_VERT and diamant[i][j+1] == Couleur.N_JAUNE) or \
                (case == Couleur.B_BLEU and diamant[i+1][j+1] == Couleur.N_ROUGE)
  elif i == n-1: 
    return (case == Couleur.B_VERT and diamant[i][j+1] == Couleur.N_JAUNE) or \
              (case == Couleur.B_BLEU and diamant[i+1][j] == Couleur.N_ROUGE)
  else: # i >= n
    return (case == Couleur.B_VERT and diamant[i][j+1] == Couleur.N_JAUNE) or \
              (case == Couleur.B_BLEU and diamant[i+1][j-1] == Couleur.N_ROUGE)


# Détruit la cellule active
def detruire(diamant, i, j, n):
  if i < n-1:
    diamant[i][j] = Couleur.VIDE
    diamant[i][j+1] = Couleur.VIDE
    diamant[i+1][j+1] = Couleur.VIDE
    diamant[i+1][j+2] = Couleur.VIDE
  elif i == n-1:
    diamant[i][j] = Couleur.VIDE
    diamant[i][j+1] = Couleur.VIDE
    diamant[i+1][j] = Couleur.VIDE
    diamant[i+1][j+1] = Couleur.VIDE
  else: # i >= n
    diamant[i][j] = Couleur.VIDE
    diamant[i][j+1] = Couleur.VIDE
    diamant[i+1][j-1] = Couleur.VIDE
    diamant[i+1][j] = Couleur.VIDE

# Applique la phase de destruction à un diamant.
# Renvoie le diamant après destruction et une séquence 
# contentent les orientations des cellules détruites.
# '0' si elle était horizontal, '1' si vertical
# exemple: "001", représenterait une séquence de destruction : 
#          horizontal, horizontal, vertical
#          donc la première et la deuxième cellules détruitent étaient horizontal, et
#          la troisième cellule détruite était vertical    
def destruction(diamant):

  diamant_detruit = copie_diamant(diamant)

  # Utiliser pour stocker les orientations des cellules detruite
  sequence_orientation_detruite = ""    
  
  nombre_lignes = len(diamant_detruit)

  n = int(nombre_lignes/2)
     
  for i in range(nombre_lignes):
    nombre_colonnes = len(diamant_detruit[i])
    for j in range(nombre_colonnes):
      if est_case_haut_gauche_de_cellule_active(i, j, nombre_colonnes, n) \
          and destructible(diamant_detruit, i, j, n):
        
          if diamant_detruit[i][j] == Couleur.B_BLEU :
            # une cellule horizontale est détruite
            sequence_orientation_detruite += '0'
          else:
            # une cellule verticale est détruite
            sequence_orientation_detruite += '1' 
            
          detruire(diamant_detruit, i, j, n)
          j+=1  # Pour ne pas repasser sur la même case
        
  return (sequence_orientation_detruite, diamant_detruit)

# Calcul les coordonées du domino d'un diamant de taille n
# dans celui de taille n+1 durant la phase de glissage
def new_coordonée_i_j_glissage(case, i, j, n):
  if est_rouge(case): # decalage vers le nord
    if i < n:
      return (i,j)
    elif i == n:
      return (i, j+1)
    else:
      return (i, j+2)
  elif est_bleu(case): # decalage vers le sud
    if i <  n-1:
      return (i+2, j+2)
    if i == n-1:
      return (i+2, j+1)
    else:
      return (i+2,j)
  elif est_vert(case):
    return (i+1,j+2)   # decalage vers l'est
  else: 
    # la case est jaune
    return (i+1,j)    # decalage vers l'ouest


# Applique la phase de glissage à un diamant de taille n.
# Renvoie le diamant de taille n+1 après ma phase de glissage
def glissage(diamant_inf):
  
  nombre_lignes = len(diamant_inf)

  n = int(nombre_lignes/2)
  
  tmp_diamant = copie_diamant(diamant_inf)

  # Initialisation du diamant de taille n+1
  diamant_sup = ini_diamant(n+1)

  for i in range(nombre_lignes):
    for j in range(len(diamant_inf[i])):
      case = tmp_diamant[i][j]

      if(case != Couleur.VIDE): # Faire glisser le domino

        # Calcule de la nouvelle position du domino
        (newI,newJ) = new_coordonée_i_j_glissage(case, i, j, n)
        # Positionner le domino dans le diamant de taille n+1
        diamant_sup[newI][newJ] = case

  return diamant_sup


# Génère toutes les séquences binaires de longueur n.
def gen_seq_bits(n):
  if n == 0:
      yield ''
  else:
      for sequence in gen_seq_bits(n - 1):
          yield sequence + '0'
          yield sequence + '1'

# Pave une cellule horizontalement:
#       [N_ROUGE, B_ROUGE]
#        [B_BLEU, N_BLEU]
def création_pile(diamant, i, j, n):
  if i < n-1:
    diamant[i][j] = Couleur.N_ROUGE
    diamant[i][j+1] = Couleur.B_ROUGE
    diamant[i+1][j+1] = Couleur.B_BLEU
    diamant[i+1][j+2] = Couleur.N_BLEU
  elif i == n-1:
    diamant[i][j] = Couleur.N_ROUGE
    diamant[i][j+1] = Couleur.B_ROUGE
    diamant[i+1][j] = Couleur.B_BLEU
    diamant[i+1][j+1] = Couleur.N_BLEU
  else:
    diamant[i][j] = Couleur.N_ROUGE
    diamant[i][j+1] = Couleur.B_ROUGE
    diamant[i+1][j-1] = Couleur.B_BLEU
    diamant[i+1][j] = Couleur.N_BLEU

# Pave une cellule verticalement:
#         [N_JAUNE, B_VERT]
#         [B_JAUNE, N_VERT]
def création_face(diamant, i, j, n):
  if i < n-1:
    diamant[i][j] = Couleur.N_JAUNE
    diamant[i+1][j+1] = Couleur.B_JAUNE
    diamant[i][j+1] = Couleur.B_VERT
    diamant[i+1][j+2] = Couleur.N_VERT
  elif i == n-1:
    diamant[i][j] = Couleur.N_JAUNE
    diamant[i][j+1] = Couleur.B_VERT
    diamant[i+1][j] = Couleur.B_JAUNE
    diamant[i+1][j+1] = Couleur.N_VERT
  else:
    diamant[i][j] = Couleur.N_JAUNE
    diamant[i][j+1] = Couleur.B_VERT
    diamant[i+1][j-1] = Couleur.B_JAUNE
    diamant[i+1][j] = Couleur.N_VERT
    
# Applique la phase de création à une diamant.
def création(diamant, sequence):
  
  nombre_lignes = len(diamant)

  n = int(nombre_lignes/2)

  newDiamant = copie_diamant(diamant)

  # Utiliser pour parcourir la sequence guidant la construction
  cpt_creation = 0
  
  for i in range(nombre_lignes):
    for j in range(len(newDiamant[i])):
      
      if newDiamant[i][j] == Couleur.VIDE:
        # Alors nous somme sur la case en haut à gauche d'une cellule vide
        if sequence[cpt_creation] == '0':
          # La séquence nous dit de paver horizontalement
          création_pile(newDiamant, i, j, n)
        else:
          # La séquence nous dit de paver verticalement
          création_face(newDiamant, i, j, n)
        j+=1
        cpt_creation += 1

  return newDiamant


# Renvoie le pavage horizontal d'un diamant de taille 1
def diamant1_horizontal():
  return [[Couleur.N_ROUGE,Couleur.B_ROUGE],[Couleur.B_BLEU,Couleur.N_BLEU]]

# Renvoie le pavage vertical d'un diamant de taille 1
def diamant1_vertical():
  return [[Couleur.N_JAUNE,Couleur.B_VERT],[Couleur.B_JAUNE,Couleur.N_VERT]]


# Génère toutes les pavages d'un diamant de taille n.
def generate_pavage_diamant(n):
  if n == 1:
    yield diamant1_horizontal()
    yield diamant1_vertical()
  else:
     # Pour tout les pavages de taille n-1, on applique l'algorithme de shuffling
      for diamant in generate_pavage_diamant(n - 1):
        # Destruction
        (sequence_orientation_detruite, diamant_detruit) = destruction(diamant)

        # Glissage
        diamant_sup_après_glissage = glissage(diamant_detruit)

        # Création
        for seq in gen_seq_bits(n):
          yield création(diamant_sup_après_glissage, sequence_orientation_detruite + seq)


# Tirage aléatoire d'un pavage du diamant de taille n
def tirage_diamant(n):
  # Tirage aléatoire du taille 1
  diamant = random.choice([diamant1_horizontal(), diamant1_vertical()])

  # Chaque étape on augmente la taille de 1, on commence du taille 1
  #   après n-1, on obtient un pavage du taille n
  for _ in range(n-1):
    # Destruction
    (sequence_orientation_detruite, diamant) = destruction(diamant)

    # Glissage
    diamant = glissage(diamant)

    # Génération d'un mot binaire aléatoire
    mot_binaire_aléatoire = ""
    for _ in range(n + len(sequence_orientation_detruite)):
      mot_binaire_aléatoire += random.choice(['0','1'])
    
    # Création
    diamant = création(diamant, mot_binaire_aléatoire)
    
  return diamant
  
# Affiche le pavage d'un diamant, si celui-ci à
#   des cases vide on affiche le quadrillage.
def affiche_pavage(diamant):
  n = int(len(diamant)/2)

  # Création d'une nouvelle figure
  plt.figure()
  # Configuration des limites de l'axe
  plt.xlim(0, 2 * n + 1)
  plt.ylim(0, 2 * n + 1)

  # Configuration du titre
  plt.title('Pavage du diamant aztèque de taille ' + str(n))

# Initialisation de la position en y de la première case d'une ligne
  debut_colonne = n - 1


  # Parcours de chaque case de l'échiquier
  for ligne in range(2 * n):
    # Calcul la coordonné y de la première case sur cette ligne
    if ligne < n: debut_colonne -= 1
    elif ligne > n: debut_colonne += 1

    # Dessin les cases en alternant les couleurs
    for colonne in range(len(diamant[ligne])):

      case = diamant[ligne][colonne]
      if (est_bleu(case)):
        couleur = 'blue'
      elif (est_rouge(case)):
        couleur = 'red'
      elif (est_vert(case)):
        couleur = 'green'
      elif (est_jaune(case)): 
        couleur = 'yellow'
      else: # La case est vide
        if ligne <n: couleur = 'black' if colonne %2 == 0 else 'pink'
        else: couleur = 'pink' if colonne %2 == 0 else 'black'

      # Dessin d'un carré représentant chaque case
      plt.gca().add_patch(plt.Rectangle((debut_colonne + colonne, ligne), 1, 1, color=couleur))


  # Affichage du diamant
  plt.gca().invert_yaxis()
  plt.axis('equal')
  plt.axis('off')  # Supprime les axes
  plt.show()


        ##                 ##                 ##
       ####               ####               ####
      ######             ######             ######
     ########           ########           ########
    ##########         ##########         ##########
   ############       ############       ############
  ##############     ##############     ##############
 ################   ################   ################
################## ################## ##################
################## ################## ##################
 ################   ################   ################
  ##############     ##############     ##############
   ############       ############       ############
    ##########         ##########         ##########
     ########           ########           ########
      ######             ######             ######
       ####               ####               ####
        ##                 ##                 ##



# Demander à l'utilisateur la taille du diamant
n = int(input("Entrez la taille du diamant aztèque : "))

# Test combinatoire

# nombre_pavages = 0
# toutmesPavages = []
# nombre_pavages_égaux = 0
# nombre_case_vide = 0

# for diamant in generate_pavage_diamant(n):
  
#   # Regarde si il y a au moins une case vide
#   if le_diamant_a_case_vide(diamant): nombre_case_vide += 1
  
#   for d in toutmesPavages:
#     # Regarde si deux pavages généré sont égaux
#     if les_diamants_sont_egaux(d, diamant): nombre_pavages_égaux += 1
    
#   toutmesPavages.append(diamant)

#   # Calcul le nombre de pavage généré
#   nombre_pavages += 1


# print("Nombre de pavages = " + str(nombre_pavages))
# print("Nombre de pavages généré qui sont égaux = " + str(nombre_pavages_égaux))
# print("Nombre de pavages généré qui ont une case vide = " + str(nombre_case_vide))

print(f"Tirage aléatoire uniforme d'un pavage du diamant de taille {n}")
print("Attendez que celui-ci s'affiche, cela peut prendre du temps...")

# Affiche un pavage tiré aléatoirement
affiche_pavage(tirage_diamant(n))