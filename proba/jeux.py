#!/usr/bin/python3

import random as rd
import math as mt

# Simulation de la loi de Poisson de paramètre 1
def Poisson1():
    v = rd.random()
    ve = mt.exp(-1)
    k = 0
    while v > ve:
        k = k + 1
        v = v * rd.random()
    return k


def EchantillonP1(n):
    d = {}
    for i in range(n):
        v = Poisson1()
        if v in d:
            d[v] += 1
        else:
            d[v] = 1
    return d


def AfficheDictionnaire(d):
    L = list(d.keys())
    L.sort()
    for v in L:
        print(f'Valeur {v} : {d[v]}')
    return


########################################################################################
## Alice et Bob
########################################################################################

def SimulePileOuFace():
    return 1 if rd.random() > 0.5 else 0


def SimuleJeu():
    joueur_actuel = "Alice"
    while SimulePileOuFace() != 0:
        joueur_actuel = "Bob" if joueur_actuel == "Alice" else "Alice"
    return 1 if joueur_actuel == "Alice" else 0


def EchantillonAP(n):
    resultats = {}
    for _ in range(n):
        resultat_partie = SimuleJeu()
        if resultat_partie in resultats:
            resultats[resultat_partie] += 1
        else:
            resultats[resultat_partie] = 1
    return resultats


print("JEU ENTRE ALICE ET BOB:")

nombre_de_simulations = 10000
resultats = [SimuleJeu() for _ in range(nombre_de_simulations)]
proportion_ana = sum(resultats) / nombre_de_simulations

print(f"\nProbabilité que ce soit Alice qui gagne : {proportion_ana:.4f}")
print(f"Probabilité que ce soit Bob qui gagne : {1 - proportion_ana:.4f}\n")

echantillon_resultats = EchantillonAP(nombre_de_simulations)
print(f"Nombre total d'essais : {nombre_de_simulations}")
print(f"Nombre de victoires d'Alice (1) : {echantillon_resultats.get(1,0)}")
print(f"Nombre de victoires de Bob (0) : {echantillon_resultats.get(0,0)}")
print(f"Proportion de victoires d'Alice : {echantillon_resultats.get(1,0) / nombre_de_simulations:.4f}\n")


########################################################################################
## Le joueur de casino
########################################################################################

def SimuleCasino(p, k, n):
    """Simule un jeu de casino jusqu'à ruine (0€) ou victoire (n€)"""
    while 0 < k < n:
        if rd.random() < p:
            k += 1
        else:
            k -= 1
    return 1 if k == n else 0


def EchantillonCasino(p, k, n, N):
    resultats = {}
    for _ in range(N):
        resultat_simulation = SimuleCasino(p, k, n)
        if resultat_simulation in resultats:
            resultats[resultat_simulation] += 1
        else:
            resultats[resultat_simulation] = 1
    return resultats


print("\nLE JOUEUR DE CASINO:")

p = 0.5
k = 10
n = 20
N = nombre_de_simulations

echantillon_casino = EchantillonCasino(p, k, n, N)

print(f"\nProbabilité de gagner à chaque tour : {p}")
print(f"Fortune initiale : {k}€")
print(f"Objectif : {n}€")
print(f"Nombre de simulations : {N}\n")

print(f"Nombre de réussites (atteint {n}€) : {echantillon_casino.get(1,0)}")
print(f"Nombre d'échecs (ruine à 0€) : {echantillon_casino.get(0,0)}")

proportion_reussites = echantillon_casino.get(1,0) / N
print(f"\nProportion de réussites : {proportion_reussites:.4f}")
print(f"Probabilité théorique (p=0.5) : {k/n:.4f}\n")


########################################################################################
## Jeux de balle
########################################################################################

def SimuleCoup(x):
    """Simule un coup avec probabilité x de gagner"""
    return 1 if rd.random() < x else 0


# Tennis de table corrigé : écart de 2 points
def SimuleSetTable(x):
    """Simule un set de tennis de table (premier à 11 points avec 2 d'écart)"""
    scoreJ = 0
    scoreA = 0

    while True:
        if SimuleCoup(x) == 1:
            scoreJ += 1
        else:
            scoreA += 1
        if (scoreJ >= 11 or scoreA >= 11) and abs(scoreJ - scoreA) >= 2:
            return 1 if scoreJ > scoreA else 0


def SimuleMatchTable(x):
    """Simule un match de tennis de table (premier à 3 sets)"""
    scoreJ = 0
    scoreA = 0

    while max(scoreJ, scoreA) < 3:
        if SimuleSetTable(x) == 1:
            scoreJ += 1
        else:
            scoreA += 1

    return 1 if scoreJ == 3 else 0


# Tennis
def SimuleJeuTennis(x):
    """Simule un jeu de tennis (premier à 4 points avec 2 d'écart)"""
    scoreJ = 0
    scoreA = 0
    while True:
        if SimuleCoup(x) == 1:
            scoreJ += 1
        else:
            scoreA += 1
        if scoreJ >= 4 and scoreJ - scoreA >= 2:
            return 1
        if scoreA >= 4 and scoreA - scoreJ >= 2:
            return 0


def SimuleSetTennis(x):
    """Simule un set de tennis (premier à 6 jeux avec 2 d'avance)"""
    scoreJ = 0
    scoreA = 0
    while True:
        if SimuleJeuTennis(x) == 1:
            scoreJ += 1
        else:
            scoreA += 1
        if scoreJ >= 6 and scoreJ - scoreA >= 2:
            return 1
        if scoreA >= 6 and scoreA - scoreJ >= 2:
            return 0


def SimuleMatchTennis(x):
    """Simule un match de tennis (premier à 3 sets)"""
    scoreJ = 0
    scoreA = 0
    while max(scoreJ, scoreA) < 3:
        if SimuleSetTennis(x) == 1:
            scoreJ += 1
        else:
            scoreA += 1
    return 1 if scoreJ == 3 else 0


# Estimations stables pour les jeux de balle
def EstimationJeu(fonction, x, N=10000):
    """Renvoie la proportion de victoires sur N simulations"""
    return sum(fonction(x) for _ in range(N)) / N


print("\nJEUX DE BALLE:")

probabilite_succes = 0.6
N_jeux = 10000

print("\nTENNIS DE TABLE:")
print(f"Proportion de victoire en set : {EstimationJeu(SimuleSetTable, probabilite_succes, N_jeux):.4f}")
print(f"Proportion de victoire en match : {EstimationJeu(SimuleMatchTable, probabilite_succes, N_jeux):.4f}")

print("\nTENNIS:")
print(f"Proportion de victoire en jeu : {EstimationJeu(SimuleJeuTennis, probabilite_succes, N_jeux):.4f}")
print(f"Proportion de victoire en set : {EstimationJeu(SimuleSetTennis, probabilite_succes, N_jeux):.4f}")
print(f"Proportion de victoire en match : {EstimationJeu(SimuleMatchTennis, probabilite_succes, N_jeux):.4f}\n")


########################################################################################
## Le problème Monty Hall
########################################################################################

def InitJeu():
    return rd.randint(1, 3)

def ChoixJoueur():
    return rd.randint(1, 3)

def Animateur(bon, choix):
    options = [1, 2, 3]
    options.remove(bon)
    if bon != choix:
        options.remove(choix)
    return rd.choice(options)

def StrategieJoueurTetu(initial, reponse):
    return initial

def StrategieJoueurChange(initial, reponse):
    options = [1, 2, 3]
    options.remove(initial)
    options.remove(reponse)
    return options[0]

def SimuleMH(iJ, cI, rA, sJ):
    bon = iJ()
    choix = cI()
    reponse = rA(bon, choix)
    final = sJ(choix, reponse)
    return 1 if final == bon else 0


print("\nLE PROBLÈME MONTY HALL:")

resultats_tetu = [SimuleMH(InitJeu, ChoixJoueur, Animateur, StrategieJoueurTetu) for _ in range(nombre_de_simulations)]
victoires_tetu = sum(resultats_tetu)
proba_tetu = victoires_tetu / nombre_de_simulations

print("\nSTRATÉGIE TÊTU (garde son choix):")
print(f"Nombre de victoires : {victoires_tetu}")
print(f"Probabilité de victoire : {proba_tetu:.4f}")

resultats_change = [SimuleMH(InitJeu, ChoixJoueur, Animateur, StrategieJoueurChange) for _ in range(nombre_de_simulations)]
victoires_change = sum(resultats_change)
proba_change = victoires_change / nombre_de_simulations

print("\nSTRATÉGIE CHANGE (change de porte):")
print(f"Nombre de victoires : {victoires_change}")
print(f"Probabilité de victoire : {proba_change:.4f}")
